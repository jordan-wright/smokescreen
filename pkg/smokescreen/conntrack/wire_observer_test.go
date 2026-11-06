package conntrack

import (
	"bytes"
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

func testHello() []byte {
	p := []byte{3, 3}
	p = append(p, make([]byte, 32)...)
	p = append(p, 0, 0x13, 1, 0)
	e := []byte{0, 43, 0, 2, 3, 4, 0, 51, 0, 36, 0, 29, 0, 32}
	e = append(e, make([]byte, 32)...)
	p = append(p, byte(len(e)>>8), byte(len(e)))
	p = append(p, e...)
	h := []byte{2, 0, byte(len(p) >> 8), byte(len(p))}
	return append(h, p...)
}
func record(p []byte) []byte { return append([]byte{22, 3, 3, byte(len(p) >> 8), byte(len(p))}, p...) }
func TestWireFragmentation(t *testing.T) {
	h := testHello()
	for split := 1; split < len(h); split++ {
		wire := append(record(h[:split]), record(h[split:])...)
		for chunk := 1; chunk <= len(wire); chunk++ {
			o := NewWireObserver()
			for p := wire; len(p) > 0; {
				n := min(chunk, len(p))
				o.Server(p[:n])
				p = p[n:]
			}
			if got := o.Fields()["wire_server_key_exchange_group"]; got != "X25519" {
				t.Fatalf("split=%d chunk=%d got=%v", split, chunk, got)
			}
		}
	}
}
func TestWireBounds(t *testing.T) {
	for _, p := range [][]byte{[]byte("GET / HTTP/1.1"), {22, 3, 3, 255, 255}, []byte("SSH-2.0-" + string(bytes.Repeat([]byte{'x'}, 300))), []byte("SSH-2.0-test\r\n\xff\xff\xff\xff\x04")} {
		o := NewWireObserver()
		o.Client(p)
		if !o.client.done.Load() {
			t.Fatalf("not stopped %x", p)
		}
		if o.client.buf != nil || o.client.handshake != nil {
			t.Fatal("retained buffers")
		}
	}
	o := NewWireObserver()
	o.client.start = time.Now().Add(-11 * time.Second)
	o.Client([]byte("hello"))
	if o.Fields()["wire_client_status"] != "time_limit" {
		t.Fatal("time limit")
	}
	o = NewWireObserver()
	for i := 0; i < 130; i++ {
		o.Server(record(nil))
	}
	if o.Fields()["wire_server_status"] != "record_limit" {
		t.Fatal("record limit")
	}
}
func TestWireConcurrentSnapshot(t *testing.T) {
	o := NewWireObserver()
	p := record(testHello())
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				switch i {
				case 0:
					o.Server(p)
				case 1:
					o.Client(p)
				case 2:
					o.Fields()
				}
			}
		}(i)
	}
	wg.Wait()
}
func TestWireUnknownGroup(t *testing.T) {
	h := testHello()
	binary.BigEndian.PutUint16(h[len(h)-36:len(h)-34], 0xaaaa)
	o := NewWireObserver()
	o.Server(record(h))
	if o.Fields()["wire_server_key_exchange_group_id"] != "0xaaaa" {
		t.Fatal(o.Fields())
	}
}
func FuzzWire(f *testing.F) {
	f.Add(record(testHello()), uint8(7))
	f.Add([]byte("SSH-2.0-test\r\n"), uint8(1))
	f.Fuzz(func(t *testing.T, p []byte, chunk uint8) {
		if len(p) > wireBudget+1024 {
			p = p[:wireBudget+1024]
		}
		o := NewWireObserver()
		n := int(chunk) + 1
		for len(p) > 0 {
			k := min(n, len(p))
			o.Client(p[:k])
			o.Server(p[:k])
			p = p[k:]
		}
		o.Fields()
		if len(o.client.buf) > wireBudget || len(o.server.handshake) > wireBudget {
			t.Fatal("unbounded")
		}
	})
}
func BenchmarkWire(b *testing.B) {
	p := record(testHello())
	b.Run("ServerHello", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			o := NewWireObserver()
			o.Server(p)
		}
	})
	b.Run("ServerHelloAndFields", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			o := NewWireObserver()
			o.Server(p)
			o.Fields()
		}
	})
	b.Run("Stopped32KiB", func(b *testing.B) {
		o := NewWireObserver()
		o.Server(p)
		payload := make([]byte, 32<<10)
		b.ReportAllocs()
		b.SetBytes(int64(len(payload)))
		b.ResetTimer()
		for b.Loop() {
			o.Server(payload)
		}
	})
}
