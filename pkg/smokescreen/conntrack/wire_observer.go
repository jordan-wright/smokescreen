package conntrack

// Passive, bounded initial-handshake telemetry; never an authentication signal.
import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/sirupsen/logrus"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const wireBudget = 64 << 10

type WireObserver struct{ client, server wireDirection }
type wireDirection struct {
	mu             sync.Mutex
	done           atomic.Bool
	server         bool
	start          time.Time
	buf, handshake []byte
	total, records int
	protocol       string
	banner         bool
	fields         logrus.Fields
}

func NewWireObserver() *WireObserver {
	now := time.Now()
	return &WireObserver{client: wireDirection{start: now, fields: logrus.Fields{}}, server: wireDirection{start: now, server: true, fields: logrus.Fields{}}}
}
func (o *WireObserver) Client(p []byte) { o.client.feed(p) }
func (o *WireObserver) Server(p []byte) { o.server.feed(p) }
func (d *wireDirection) stop(s string) {
	d.fields["status"] = s
	d.buf = nil
	d.handshake = nil
	d.done.Store(true)
}
func (d *wireDirection) feed(p []byte) {
	if len(p) == 0 || d.done.Load() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done.Load() {
		return
	}
	if time.Since(d.start) > 10*time.Second {
		d.stop("time_limit")
		return
	}
	room := wireBudget - d.total
	if len(p) > room {
		p = p[:room]
	}
	d.total += len(p)
	d.buf = append(d.buf, p...)
	if d.protocol == "" {
		if len(d.buf) < 5 {
			return
		}
		switch {
		case d.buf[0] == 22 && d.buf[1] == 3:
			d.protocol = "tls"
		case bytes.HasPrefix(d.buf, []byte("SSH-")):
			d.protocol = "ssh"
		default:
			d.stop("unrecognized")
			return
		}
		d.fields["protocol"] = d.protocol
	}
	switch d.protocol {
	case "tls":
		d.tls()
	case "ssh":
		d.ssh()
	}
	if !d.done.Load() && d.total >= wireBudget {
		d.stop("byte_limit")
	}
}

type wireCursor struct {
	b   []byte
	bad bool
}

func (c *wireCursor) take(n int) []byte {
	if n < 0 || n > len(c.b) {
		c.bad = true
		c.b = nil
		return nil
	}
	p := c.b[:n]
	c.b = c.b[n:]
	return p
}
func (c *wireCursor) u8() int {
	p := c.take(1)
	if p == nil {
		return 0
	}
	return int(p[0])
}
func (c *wireCursor) u16() int {
	p := c.take(2)
	if p == nil {
		return 0
	}
	return int(binary.BigEndian.Uint16(p))
}
func (c *wireCursor) v8() []byte  { return c.take(c.u8()) }
func (c *wireCursor) v16() []byte { return c.take(c.u16()) }
func ids(p []byte) []string {
	a := make([]string, 0, len(p)/2)
	for len(p) >= 2 {
		a = append(a, fmt.Sprintf("0x%04x", binary.BigEndian.Uint16(p)))
		p = p[2:]
	}
	return a
}
func group(n int) string { return tls.CurveID(n).String() }

var retryRandom = []byte{0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c}

func (d *wireDirection) tls() {
	for len(d.buf) >= 5 && !d.done.Load() {
		n := int(binary.BigEndian.Uint16(d.buf[3:5]))
		if n > 18432 {
			d.stop("malformed")
			return
		}
		if len(d.buf) < 5+n {
			return
		}
		typ := d.buf[0]
		payload := d.buf[5 : 5+n]
		d.buf = d.buf[5+n:]
		d.records++
		if d.records > 128 {
			d.stop("record_limit")
			return
		}
		if typ == 20 {
			if d.fields["version"] == "TLS 1.2" {
				d.stop("encrypted")
				return
			}
			continue
		}
		if typ != 22 {
			d.stop("encrypted_or_alert")
			return
		}
		d.handshake = append(d.handshake, payload...)
		for len(d.handshake) >= 4 && !d.done.Load() {
			h := d.handshake
			l := int(h[1])<<16 | int(h[2])<<8 | int(h[3])
			if l > wireBudget {
				d.stop("byte_limit")
				return
			}
			if len(h) < 4+l {
				break
			}
			body := h[4 : 4+l]
			d.handshake = h[4+l:]
			switch h[0] {
			case 1:
				if !d.server {
					d.hello(body, false)
					if !d.done.Load() {
						d.stop("client_hello")
					}
				}
			case 2:
				if d.server {
					d.hello(body, true)
				}
			case 12:
				suite, _ := d.fields["cipher_suite"].(string)
				if strings.HasPrefix(suite, "TLS_ECDHE_") && len(body) >= 4 && body[0] == 3 && int(body[3])+4 <= len(body) {
					g := int(binary.BigEndian.Uint16(body[1:3]))
					d.fields["key_exchange_group"] = group(g)
					d.fields["key_exchange_group_id"] = fmt.Sprintf("0x%04x", g)
					d.stop("server_key_exchange")
				}
			case 14:
				d.stop("server_hello_done")
			}
		}
	}
}
func (d *wireDirection) hello(p []byte, server bool) {
	c := wireCursor{b: p}
	ver := c.u16()
	random := c.take(32)
	c.v8()
	retry := server && bytes.Equal(random, retryRandom)
	f := logrus.Fields{}
	if server {
		suite := c.u16()
		c.u8()
		f["version"] = tls.VersionName(uint16(ver))
		f["cipher_suite"] = tls.CipherSuiteName(uint16(suite))
		f["cipher_suite_id"] = fmt.Sprintf("0x%04x", suite)
	} else {
		suites := c.v16()
		c.v8()
		f["legacy_version"] = tls.VersionName(uint16(ver))
		f["cipher_suites"] = ids(suites)
	}
	var exts []byte
	if len(c.b) > 0 {
		exts = c.v16()
	}
	if c.bad || len(c.b) != 0 {
		d.stop("malformed")
		return
	}
	e := wireCursor{b: exts}
	for len(e.b) > 0 && !e.bad {
		typ := e.u16()
		data := e.v16()
		x := wireCursor{b: data}
		switch typ {
		case 43:
			if server {
				ver = x.u16()
				f["version"] = tls.VersionName(uint16(ver))
			} else {
				f["supported_versions"] = ids(x.v8())
			}
		case 10:
			if !server {
				f["supported_groups"] = ids(x.v16())
			}
		case 13:
			if !server {
				f["signature_algorithms"] = ids(x.v16())
			}
		case 51:
			if server {
				g := x.u16()
				if retry {
					f["retry_requested_group"] = group(g)
				} else {
					x.v16()
					f["key_exchange_group"] = group(g)
					f["key_exchange_group_id"] = fmt.Sprintf("0x%04x", g)
				}
			} else {
				ks := wireCursor{b: x.v16()}
				var groups []string
				for len(ks.b) > 0 && !ks.bad {
					g := ks.u16()
					ks.v16()
					groups = append(groups, group(g))
				}
				if ks.bad {
					x.bad = true
				}
				f["key_share_groups"] = groups
			}
		case 16:
			a := wireCursor{b: x.v16()}
			var names []string
			for len(a.b) > 0 && !a.bad {
				names = append(names, string(a.v8()))
			}
			if a.bad {
				x.bad = true
			}
			f["alpn"] = names
		case 41:
			if server {
				x.u16()
				f["psk_selected"] = true
			}
		case 0xfe0d:
			if !server {
				f["ech_extension_present"] = true
			}
		}
		if x.bad {
			e.bad = true
		}
	}
	if e.bad {
		d.stop("malformed")
		return
	}
	if retry {
		d.fields["hello_retry_request"] = true
		d.fields["retry_requested_group"] = f["retry_requested_group"]
		return
	}
	for k, v := range f {
		d.fields[k] = v
	}
	if server && ver == tls.VersionTLS13 {
		d.stop("server_hello")
	}
}

var sshListNames = []string{"kex", "host_key", "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c", "compression_c2s", "compression_s2c", "language_c2s", "language_s2c"}

func (d *wireDirection) ssh() {
	if !d.banner {
		i := bytes.IndexByte(d.buf, '\n')
		if i < 0 {
			if len(d.buf) > 255 {
				d.stop("malformed")
			}
			return
		}
		if i > 254 {
			d.stop("malformed")
			return
		}
		d.fields["banner"] = strings.TrimSuffix(string(d.buf[:i]), "\r")
		d.buf = d.buf[i+1:]
		d.banner = true
	}
	if len(d.buf) < 5 {
		return
	}
	n := int(binary.BigEndian.Uint32(d.buf[:4]))
	pad := int(d.buf[4])
	if n < 6 || n > 35000 || pad < 4 || pad >= n-1 {
		d.stop("malformed")
		return
	}
	if len(d.buf) < 4+n {
		return
	}
	c := wireCursor{b: d.buf[5 : 4+n-pad]}
	if c.u8() != 20 {
		d.stop("unexpected_ssh_packet")
		return
	}
	c.take(16)
	f := logrus.Fields{}
	for _, name := range sshListNames {
		raw := c.take(4)
		if c.bad {
			break
		}
		size := uint64(binary.BigEndian.Uint32(raw))
		if size > uint64(len(c.b)) {
			c.bad = true
			break
		}
		s := string(c.take(int(size)))
		if s == "" {
			f[name] = []string{}
		} else {
			f[name] = strings.Split(s, ",")
		}
	}
	c.take(5)
	if c.bad || len(c.b) != 0 {
		d.stop("malformed")
		return
	}
	for k, v := range f {
		d.fields[k] = v
	}
	d.stop("kexinit")
}
func (o *WireObserver) Fields() logrus.Fields {
	f := logrus.Fields{"wire_evidence": "unauthenticated_initial_handshake"}
	for _, item := range []struct {
		prefix string
		d      *wireDirection
	}{{"wire_client_", &o.client}, {"wire_server_", &o.server}} {
		item.d.mu.Lock()
		for k, v := range item.d.fields {
			f[item.prefix+k] = v
		}
		if !item.d.done.Load() {
			f[item.prefix+"status"] = "incomplete"
		}
		item.d.mu.Unlock()
	}
	if f["wire_client_status"] == "kexinit" && f["wire_server_status"] == "kexinit" {
		for _, name := range sshListNames[:8] {
			client, _ := f["wire_client_"+name].([]string)
			server, _ := f["wire_server_"+name].([]string)
			selected := ""
			for _, a := range client {
				if strings.HasPrefix(a, "ext-info-") || strings.HasPrefix(a, "kex-strict-") {
					continue
				}
				for _, b := range server {
					if a == b {
						selected = a
						break
					}
				}
				if selected != "" {
					break
				}
			}
			if selected != "" {
				f["wire_ssh_inferred_"+name] = selected
			}
		}
	}
	// AEAD ciphers do not use the separately advertised MAC list.
	for _, direction := range []string{"c2s", "s2c"} {
		cipher, _ := f["wire_ssh_inferred_cipher_"+direction].(string)
		if cipher == "chacha20-poly1305@openssh.com" || cipher == "aes128-gcm@openssh.com" || cipher == "aes256-gcm@openssh.com" {
			f["wire_ssh_inferred_mac_"+direction] = "implicit_aead"
		}
	}
	return f
}
