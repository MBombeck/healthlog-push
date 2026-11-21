package limits

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

var t0 = time.Date(2026, 12, 1, 12, 0, 0, 0, time.UTC)

func TestPrefixes(t *testing.T) {
	n, w := Prefixes(netip.MustParseAddr("2001:db8:1:2:3:4:5:6"))
	if n.String() != "2001:db8:1:2::/64" || w.String() != "2001:db8:1::/48" {
		t.Fatal(n, w)
	}
	n, w = Prefixes(netip.MustParseAddr("::ffff:203.0.113.7"))
	if n.String() != "203.0.113.7/32" || n != w {
		t.Fatal("mapped IPv4 not treated as IPv4:", n)
	}
}

// TestRegistrationLimits: 3 per IPv4 address or /64 per day, 10 per /48, global caps halved after a start.
func TestRegistrationLimits(t *testing.T) {
	r := NewRegistrations(DefaultRegistrationLimits, t0.Add(-48*time.Hour)) // started long ago: no halving
	r.halfUntil = time.Time{}
	a := netip.MustParseAddr("203.0.113.7")
	for k := range 3 {
		if !r.Allow(a, t0, false) {
			t.Fatalf("registration %d refused", k)
		}
	}
	if r.Allow(a, t0, false) {
		t.Fatal("4th registration from one IPv4 address")
	}
	if !r.Allow(a, t0.Add(24*time.Hour), false) {
		t.Fatal("limit did not reset the next day")
	}
	// Same /64, different addresses.
	r = NewRegistrations(DefaultRegistrationLimits, t0)
	r.halfUntil = time.Time{}
	for k := range 4 {
		ok := r.Allow(netip.MustParseAddr("2001:db8:0:1::"+string(rune('1'+k))), t0, false)
		if ok != (k < 3) {
			t.Fatalf("/64 registration %d: %v", k, ok)
		}
	}
	// Different /64s in one /48: 10.
	r = NewRegistrations(DefaultRegistrationLimits, t0)
	r.halfUntil = time.Time{}
	n := 0
	for k := range 20 {
		a := netip.AddrFrom16([16]byte{0x20, 0x01, 0x0d, 0xb8, 0, 9, 0, byte(k), 15: 1})
		if r.Allow(a, t0, false) {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("/48 allowed %d, want 10", n)
	}
	// After a start, the global hour cap is halved until midnight.
	r = NewRegistrations(RegistrationLimits{PerNarrowDay: 100, PerWideDay: 100, GlobalHour: 30, GlobalDay: 200}, t0)
	n = 0
	for k := range 40 {
		if r.Allow(netip.AddrFrom4([4]byte{198, 51, 100, byte(k)}), t0, false) {
			n++
		}
	}
	if n != 15 {
		t.Fatalf("halved global cap allowed %d, want 15", n)
	}
	if !r.Allow(netip.MustParseAddr("192.0.2.1"), t0, true) {
		t.Fatal("recovery window must ignore the global cap")
	}
}

func TestBucket(t *testing.T) {
	b := NewBucket(20, 6.0/3600, t0)
	for k := range 20 {
		if !b.Allow(t0) {
			t.Fatalf("token %d", k)
		}
	}
	if b.Allow(t0) || b.Allow(t0.Add(9*time.Minute)) {
		t.Fatal("bucket over capacity")
	}
	if !b.Allow(t0.Add(10*time.Minute + time.Second)) {
		t.Fatal("bucket did not refill at 6 per hour")
	}
}

func TestConnLimiter(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cl := NewConnLimiter(ln, 10, 2)
	rejected := make(chan struct{}, 10)
	cl.Rejected = func() { rejected <- struct{}{} }
	go func() {
		for {
			c, err := cl.Accept()
			if err != nil {
				return
			}
			_ = c
		}
	}()
	var conns []net.Conn
	for range 3 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	select {
	case <-rejected:
	case <-time.After(time.Second):
		t.Fatal("third connection from one address not rejected")
	}
	for _, c := range conns {
		_ = c.Close()
	}
	_ = ln.Close()
}
