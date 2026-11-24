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
	"sync/atomic"
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
	KEvents  Key = "events"  // map of event name to count
	// Keys of the wallet process (one line per request, internal/wallet).
	KOp       Key = "op"       // sign, notify, info
	KResult   Key = "result"   // closed enumeration
	KDuration Key = "duration" // coarse bucket: lt_100ms, lt_1s, ge_1s
	// KLevel is set by Alert only, always to "alert".
	KLevel Key = "level"
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
	mu     sync.Mutex
	out    io.Writer = os.Stdout
	errOut io.Writer = os.Stderr
	now              = time.Now
)

// SetOutput redirects the log, alert lines included, for tests.
func SetOutput(w io.Writer) { mu.Lock(); out, errOut = w, w; mu.Unlock() }

// Event writes one line to standard output. The timestamp is truncated to the second.
func Event(action string, fields ...Field) { write(false, action, fields) }

// Alert writes one line for an event the operator should act on: the same JSON with "level":"alert" added,
// to standard error. A log pipeline can select every such line by that one key without knowing the event
// names, and Docker's journald driver gives standard error the journal priority err, so `journalctl -p err`
// shows them too. docs/operations.md lists every alert in its table of alerts, and a test holds the two
// together.
func Alert(action string, fields ...Field) {
	write(true, action, append(fields, Str(KLevel, "alert")))
}

func write(alert bool, action string, fields []Field) {
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
	w := out
	if alert {
		w = errOut
	}
	_, _ = w.Write(append(b, '\n'))
}

// CountingWriter is used as http.Server.ErrorLog: it counts and discards, because the standard library
// writes client addresses into TLS handshake and protocol error messages.
type CountingWriter struct {
	n atomic.Int64
}

func (c *CountingWriter) Write(p []byte) (int, error) {
	c.n.Add(1)
	return len(p), nil
}

// Count returns the number of discarded lines.
func (c *CountingWriter) Count() int64 { return c.n.Load() }
