package smokescreen

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/stripe/smokescreen/pkg/smokescreen/conntrack"
	"github.com/stripe/smokescreen/pkg/smokescreen/metrics"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestWireFailOpen(t *testing.T) {
	for _, payload := range [][]byte{[]byte("unrecognized-protocol"), {22, 3, 3, 255, 255}, append([]byte("SSH-2.0-test\r\n"), 255, 255, 255, 255, 4)} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() {
			c, e := listener.Accept()
			if e != nil {
				done <- e
				return
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(3 * time.Second))
			_, e = io.Copy(c, c)
			done <- e
		}()
		cfg := NewConfig()
		cfg.ObserveTunnelHandshake = true
		cfg.AllowSelfConnections = true
		cfg.Log.SetOutput(io.Discard)
		cfg.ConnTracker = conntrack.NewTracker(cfg.IdleTimeout, metrics.NewNoOpMetricsClient(), cfg.Log, atomic.Value{}, nil)
		if err := cfg.SetAllowAddresses([]string{"127.0.0.1"}); err != nil {
			t.Fatal(err)
		}
		proxy := httptest.NewServer(BuildProxy(cfg))
		c, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(3 * time.Second))
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", listener.Addr(), listener.Addr())
		reader := bufio.NewReader(c)
		resp, err := http.ReadResponse(reader, &http.Request{Method: "CONNECT"})
		if err != nil || resp.StatusCode != 200 {
			t.Fatal("CONNECT", err)
		}
		p := append(bytes.Clone(payload), bytes.Repeat([]byte("unchanged"), 16384)...)
		writeDone := make(chan error, 1)
		go func() { _, e := c.Write(p); writeDone <- e }()
		got := make([]byte, len(p))
		_, err = io.ReadFull(reader, got)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatal("observer changed or blocked bytes", err)
		}
		if err := <-writeDone; err != nil {
			t.Fatal(err)
		}
		c.Close()
		cfg.ConnTracker.Wg().Wait()
		proxy.Close()
		listener.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
}
