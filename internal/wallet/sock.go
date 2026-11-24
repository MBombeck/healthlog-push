package wallet

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Socket names inside the shared directory, and the bounds of one exchange.
const (
	SocketName     = "wallet.sock" // served by the wallet process, dialed by the relay
	TunnelName     = "apns.sock"   // served by the relay, dialed by the wallet process
	MaxConcurrent  = 8
	SignDeadline   = 5 * time.Second
	NotifyDeadline = 10 * time.Second
)

// ErrFrame is a frame that is empty, too long or truncated.
var ErrFrame = errors.New("wallet socket: bad frame")

// WriteFrame writes a four-byte big-endian length and the JSON of v.
func WriteFrame(w io.Writer, v any, limit int) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > limit {
		return ErrFrame
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) //nolint:gosec // bounded by limit above
	if _, err := w.Write(append(hdr[:], b...)); err != nil {
		return err
	}
	return nil
}

// ReadFrame reads one frame of at most limit bytes and returns its body.
func ReadFrame(r io.Reader, limit int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, ErrFrame
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > uint32(limit) { //nolint:gosec // limit is a small positive constant
		return nil, ErrFrame
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, ErrFrame
	}
	return b, nil
}

// Listen creates the unix socket at path, readable and writable by the shared group only.
func Listen(ctx context.Context, path string) (net.Listener, error) {
	_ = os.Remove(path)
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil { //nolint:gosec // the other process connects through the shared group
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// Serve answers requests on ln until ctx ends: one request per connection, at most MaxConcurrent at a
// time; a connection beyond that is closed at once and the relay reports the service as unavailable.
func (s *Service) Serve(ctx context.Context, ln net.Listener) error {
	go func() { <-ctx.Done(); _ = ln.Close() }()
	sem := make(chan struct{}, MaxConcurrent)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil //nolint:nilerr // the listener was closed for shutdown
			}
			return err
		}
		select {
		case sem <- struct{}{}:
			go func() { defer func() { <-sem }(); s.serveConn(ctx, c) }()
		default:
			_ = c.Close()
		}
	}
}

func (s *Service) serveConn(ctx context.Context, c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(NotifyDeadline))
	b, err := ReadFrame(c, wire.WalletFrameMax)
	var req wire.WalletRequest
	if err == nil {
		err = wire.DecodeStrict(b, &req)
	}
	start := time.Now()
	var rep *wire.WalletReply
	if err != nil {
		rep = &wire.WalletReply{Error: wire.WalletErrBadRequest, Info: s.Info()}
	} else {
		rctx, cancel := context.WithTimeout(ctx, NotifyDeadline-time.Second)
		rep = s.Handle(rctx, &req)
		cancel()
	}
	logRequest(req.Op, rep, time.Since(start))
	_ = WriteFrame(c, rep, wire.WalletReplyFrameMax)
}

// Client is the relay's side of the wallet socket.
type Client struct {
	Path string
	sem  chan struct{}
}

// NewClient returns a client for the socket at path.
func NewClient(path string) *Client {
	return &Client{Path: path, sem: make(chan struct{}, MaxConcurrent)}
}

// Do sends one request and reads the answer. It waits for a free slot until ctx ends.
func (c *Client) Do(ctx context.Context, req *wire.WalletRequest) (*wire.WalletReply, error) {
	select {
	case c.sem <- struct{}{}:
		defer func() { <-c.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if err := WriteFrame(conn, req, wire.WalletFrameMax); err != nil {
		return nil, err
	}
	b, err := ReadFrame(conn, wire.WalletReplyFrameMax)
	if err != nil {
		return nil, err
	}
	var rep wire.WalletReply
	if err := json.Unmarshal(b, &rep); err != nil {
		return nil, ErrFrame
	}
	return &rep, nil
}
