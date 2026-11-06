package smokescreen

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type wireLog struct {
	sync.Mutex
	bytes.Buffer
}

func (b *wireLog) Write(p []byte) (int, error) { b.Lock(); defer b.Unlock(); return b.Buffer.Write(p) }
func (b *wireLog) logs() string                { b.Lock(); defer b.Unlock(); return b.Buffer.String() }

type fragmentConn struct{ net.Conn }

func (c fragmentConn) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		n := len(p)
		if n > 7 {
			n = 7
		}
		w, e := c.Conn.Write(p[:n])
		total += w
		p = p[w:]
		if e != nil {
			return total, e
		}
		if w == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func TestWireRealTLS(t *testing.T) {
	cases := []struct {
		name             string
		version          uint16
		client, server   []tls.CurveID
		resume, fragment bool
	}{
		{"tls12-x25519", tls.VersionTLS12, []tls.CurveID{tls.X25519}, nil, false, false},
		{"tls12-p256", tls.VersionTLS12, []tls.CurveID{tls.CurveP256}, nil, false, false},
		{"tls13-x25519", tls.VersionTLS13, []tls.CurveID{tls.X25519}, nil, false, false},
		{"tls13-hybrid", tls.VersionTLS13, []tls.CurveID{tls.X25519MLKEM768}, nil, false, false},
		{"tls13-retry", tls.VersionTLS13, []tls.CurveID{tls.X25519, tls.CurveP256}, []tls.CurveID{tls.CurveP256}, false, false},
		{"tls13-resume", tls.VersionTLS13, []tls.CurveID{tls.X25519MLKEM768}, nil, true, false},
		{"tls13-fragment", tls.VersionTLS13, []tls.CurveID{tls.X25519MLKEM768}, nil, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "payload-ok") }))
			origin.TLS = &tls.Config{MinVersion: tc.version, MaxVersion: tc.version, CurvePreferences: tc.server, NextProtos: []string{"http/1.1"}}
			origin.StartTLS()
			defer origin.Close()
			logs := &wireLog{}
			cfg := NewConfig()
			cfg.ObserveTunnelHandshake = true
			cfg.AllowSelfConnections = true
			cfg.Log.SetOutput(logs)
			cfg.Log.SetFormatter(&logrus.JSONFormatter{})
			cfg.ConnTracker = conntrack.NewTracker(cfg.IdleTimeout, metrics.NewNoOpMetricsClient(), cfg.Log, atomic.Value{}, nil)
			if err := cfg.SetAllowAddresses([]string{"127.0.0.1"}); err != nil {
				t.Fatal(err)
			}
			proxy := httptest.NewServer(BuildProxy(cfg))
			defer proxy.Close()
			cc := &tls.Config{InsecureSkipVerify: true, MinVersion: tc.version, MaxVersion: tc.version, CurvePreferences: tc.client, NextProtos: []string{"http/1.1"}, ClientSessionCache: tls.NewLRUClientSessionCache(8)}
			count := 1
			if tc.resume {
				count = 2
			}
			var states []tls.ConnectionState
			for i := 0; i < count; i++ {
				raw, err := net.DialTimeout("tcp", strings.TrimPrefix(proxy.URL, "http://"), 3*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				raw.SetDeadline(time.Now().Add(5 * time.Second))
				fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", origin.Listener.Addr(), origin.Listener.Addr())
				resp, err := http.ReadResponse(bufio.NewReader(raw), &http.Request{Method: "CONNECT"})
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != 200 {
					t.Fatalf("CONNECT %s", resp.Status)
				}
				var transport net.Conn = raw
				if tc.fragment {
					transport = fragmentConn{raw}
				}
				c := tls.Client(transport, cc)
				if err := c.Handshake(); err != nil {
					t.Fatal(err)
				}
				fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
				response, err := http.ReadResponse(bufio.NewReader(c), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || string(body) != "payload-ok" {
					t.Fatalf("payload: %q %v", body, err)
				}
				states = append(states, c.ConnectionState())
				c.Close()
			}
			cfg.ConnTracker.Wg().Wait()
			var entries []map[string]any
			for _, line := range strings.Split(logs.logs(), "\n") {
				var f map[string]any
				if json.Unmarshal([]byte(line), &f) == nil && f["msg"] == conntrack.CanonicalProxyConnClose {
					entries = append(entries, f)
				}
			}
			if len(entries) != count {
				t.Fatalf("close logs: %s", logs.logs())
			}
			for i, f := range entries {
				s := states[i]
				for key, want := range map[string]string{"wire_server_version": tls.VersionName(s.Version), "wire_server_cipher_suite": tls.CipherSuiteName(s.CipherSuite), "wire_server_key_exchange_group": s.CurveID.String()} {
					if f[key] != want {
						t.Errorf("%s got %v want %v", key, f[key], want)
					}
				}
				if s.HelloRetryRequest && f["wire_server_hello_retry_request"] != true {
					t.Error("missing HRR")
				}
				if s.DidResume && f["wire_server_psk_selected"] != true {
					t.Error("missing PSK")
				}
				if tc.version == tls.VersionTLS13 {
					if _, ok := f["wire_server_alpn"]; ok {
						t.Error("TLS13 ALPN should be encrypted")
					}
				}
				t.Logf("endpoint version=%s group=%s resumed=%v retry=%v alpn=%s; LOG %s", tls.VersionName(s.Version), s.CurveID, s.DidResume, s.HelloRetryRequest, s.NegotiatedProtocol, mustJSON(f))
			}
			if tc.resume && !states[1].DidResume {
				t.Fatal("did not exercise resumption")
			}
			if strings.Contains(tc.name, "retry") && !states[0].HelloRetryRequest {
				t.Fatal("did not exercise retry")
			}
		})
	}
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// Benchmark includes CONNECT, TLS 1.3 hybrid handshake, HTTP request, close,
// and JSON log formatting to io.Discard; no persistent connections.
func BenchmarkWireProxy(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		b.Run(fmt.Sprintf("enabled=%v", enabled), func(b *testing.B) {
			origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "ok") }))
			origin.TLS = &tls.Config{MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}
			origin.StartTLS()
			defer origin.Close()
			cfg := NewConfig()
			cfg.ObserveTunnelHandshake = enabled
			cfg.AllowSelfConnections = true
			cfg.Log.SetOutput(io.Discard)
			cfg.Log.SetFormatter(&logrus.JSONFormatter{})
			cfg.ConnTracker = conntrack.NewTracker(cfg.IdleTimeout, metrics.NewNoOpMetricsClient(), cfg.Log, atomic.Value{}, nil)
			if err := cfg.SetAllowAddresses([]string{"127.0.0.1"}); err != nil {
				b.Fatal(err)
			}
			proxy := httptest.NewServer(BuildProxy(cfg))
			defer proxy.Close()
			u, _ := url.Parse(proxy.URL)
			tr := &http.Transport{Proxy: http.ProxyURL(u), DisableKeepAlives: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				resp, err := client.Get(origin.URL)
				if err != nil {
					b.Fatal(err)
				}
				_, err = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if err != nil {
					b.Fatal(err)
				}
				cfg.ConnTracker.Wg().Wait()
			}
		})
	}
}
