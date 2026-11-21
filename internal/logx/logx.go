// Package logx is the only logger of the relay. It writes one JSON object per line with a fixed set of
// keys. Values are integers or strings from closed sets; there is no free-text field, so a client address,
// a token or an instance id cannot reach the log by accident. A structural test enforces that no other
// logging path exists outside cmd/.
package logx

import (
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
)

// Key is a permitted log field name. Adding a key is a reviewed change.
type Key string

// The permitted keys.
const (
	KAction  Key = "action"  // fixed event name, e.g. "relay.start"
	KReason  Key = "reason"  // closed enumeration
	KClass   Key = "class"   // alert, silent, liveactivity
	KCount   Key = "n"       // integer
	KValue   Key = "value"   // integer
	KState   Key = "state"   // closed enumeration
	KVersion Key = "version" // build version
	KP95     Key = "p95_ms"  // integer
	KErrors  Key = "errors"  // map of reason to count
	KPushes  Key = "pushes"  // integer
	KPeriod  Key = "period"  // "minute" or "hour"
)

// Field is one key and value.
type Field struct {
	K Key
	V any
}

// Str is a string field. Only closed-set values may be passed; callers never pass request data.
func Str(k Key, v string) Field { return Field{k, v} }

// Int is an integer field.
func Int(k Key, v int64) Field { return Field{k, v} }

// Counts is a map field of reason to count.
func Counts(k Key, v map[string]int64) Field { return Field{k, v} }

var (
	mu  sync.Mutex
	out io.Writer = os.Stdout
	now           = time.Now
)

// SetOutput redirects the log, for tests.
func SetOutput(w io.Writer) { mu.Lock(); out = w; mu.Unlock() }

// Event writes one line. The timestamp is truncated to the second.
func Event(action string, fields ...Field) {
	m := make(map[string]any, len(fields)+2)
	m["ts"] = now().UTC().Truncate(time.Second).Format(time.RFC3339)
	m[string(KAction)] = action
	for _, f := range fields {
		m[string(f.K)] = f.V
	}
	b, err := json.Marshal(m)
	if err != nil {
		return
	}
	mu.Lock()
	defer mu.Unlock()
	_, _ = out.Write(append(b, '\n'))
}

// CountingWriter is used as http.Server.ErrorLog: it counts and discards, because the standard library
// writes client addresses into TLS handshake and protocol error messages.
type CountingWriter struct {
	mu sync.Mutex
	n  int64
}

func (c *CountingWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return len(p), nil
}

// Count returns the number of discarded lines.
func (c *CountingWriter) Count() int64 { c.mu.Lock(); defer c.mu.Unlock(); return c.n }
