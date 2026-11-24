package relay

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// APNsHostPort is the only address the tunnel dials. It is a constant on purpose: the wallet process has no
// network, and this tunnel can reach Apple's push service and nothing else.
const APNsHostPort = "api.push.apple.com:443"

// Tunnel bounds.
const (
	tunnelMax         = 2
	tunnelDialTimeout = 5 * time.Second
)

// Tunnel is the relay's byte tunnel for the wallet process (spec/wallet.md, "Processes"): each connection on
// the unix socket is joined to a new TCP connection to APNsHostPort, and bytes are copied both ways without
// being read. TLS runs inside, from the wallet process to Apple, with the pass certificate the relay never
// holds.
type Tunnel struct {
	// Dial opens the connection to Apple; nil means a net.Dialer. Tests replace it; it is always called
	// with APNsHostPort.
	Dial   func(ctx context.Context, network, addr string) (net.Conn, error)
	active atomic.Int32
}

// Serve accepts tunnel connections on ln until ctx ends. A connection beyond tunnelMax is closed at once.
func (t *Tunnel) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr // the listener was closed for shutdown
			}
			return err
		}
		if t.active.Add(1) > tunnelMax {
			t.active.Add(-1)
			_ = c.Close()
			continue
		}
		go func() {
			defer t.active.Add(-1)
			t.join(ctx, c)
		}()
	}
}

// join dials Apple and copies bytes both ways until either side closes or ctx ends.
func (t *Tunnel) join(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	dial := t.Dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: tunnelDialTimeout, KeepAlive: 30 * time.Second}).DialContext
	}
	dctx, cancel := context.WithTimeout(ctx, tunnelDialTimeout)
	up, err := dial(dctx, "tcp", APNsHostPort)
	cancel()
	if err != nil {
		return
	}
	defer func() { _ = up.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = c.Close(); _ = up.Close() })
	defer stop()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(up, c)
		_ = up.Close()
	}()
	_, _ = io.Copy(c, up)
	_ = c.Close()
	wg.Wait()
}
