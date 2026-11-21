package relay

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// AdminRequest is the body the admin CLI sends over the unix socket.
type AdminRequest struct {
	Cmd    string            `json:"cmd"`
	Args   []string          `json:"args,omitempty"`
	Params map[string]string `json:"params,omitempty"`
}

// AdminHandler serves the operator commands on the admin unix socket. The socket lives inside the relay's
// data volume with mode 0600; only `docker compose exec relay ...` reaches it.
func (r *Relay) AdminHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var ar AdminRequest
		if err := json.NewDecoder(http.MaxBytesReader(w, req.Body, 64<<10)).Decode(&ar); err != nil {
			adminOut(w, nil, err)
			return
		}
		res, err := r.admin(&ar)
		adminOut(w, res, err)
	})
}

func adminOut(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	if v == nil {
		v = map[string]string{"result": "ok"}
	}
	_ = json.NewEncoder(w).Encode(v)
}

type adminError string

func (e adminError) Error() string { return string(e) }

func arg(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}

func (r *Relay) admin(ar *AdminRequest) (any, error) {
	p := ar.Params
	dur := func(k string, def time.Duration) (time.Duration, error) {
		if p[k] == "" {
			return def, nil
		}
		return time.ParseDuration(p[k])
	}
	switch ar.Cmd {
	case "stats":
		return map[string]any{"service": r.Stats(), "usage": r.UsageReport(28)}, nil
	case "instance":
		return r.Instance(arg(ar.Args, 0))
	case "suspects":
		return r.Suspects(50), nil
	case "pause":
		d, err := dur("for", 30*time.Minute)
		if err != nil {
			return nil, err
		}
		cl, tier := p["class"], p["tier"]
		if cl == "" {
			cl = "all"
		}
		if tier == "" {
			tier = "all"
		}
		return nil, r.SetPause(cl, tier, d)
	case "resume":
		return nil, r.Resume()
	case "registration":
		return nil, r.SetRegistration(arg(ar.Args, 0))
	case "invite":
		code, err := r.NewInvite()
		return map[string]string{"invite": code, "validDays": "7"}, err
	case "notice":
		switch arg(ar.Args, 0) {
		case "set":
			d, err := dur("for", 0)
			if err != nil {
				return nil, err
			}
			lvl := p["level"]
			if lvl == "" {
				lvl = "info"
			}
			return nil, r.SetNotice(arg(ar.Args, 1), lvl, d)
		case "clear":
			return nil, r.SetNotice("", "", 0)
		}
		return nil, adminError("notice set <id> [--level L] [--for D] | notice clear")
	case "suspend":
		return nil, r.Suspend(arg(ar.Args, 0), arg(ar.Args, 1))
	case "unsuspend":
		return nil, r.Unsuspend(arg(ar.Args, 0))
	case "revoke":
		return nil, r.Revoke(arg(ar.Args, 0), arg(ar.Args, 1))
	case "block-token", "unblock-token":
		return nil, r.BlockToken(p["token"], p["mac"], ar.Cmd == "unblock-token")
	case "limits":
		n, err := strconv.Atoi(p["devices"])
		if err != nil {
			return nil, adminError("limits <id> devices=<n>")
		}
		return nil, r.SetDeviceLimit(arg(ar.Args, 0), n)
	case "recovery":
		until, err := store.ParseDayString(p["until"])
		if err != nil {
			return nil, adminError("recovery --until YYYY-MM-DD [--from file]")
		}
		var ex *store.Export
		if p["from"] != "" {
			if ex, err = store.ReadExport(p["from"]); err != nil {
				return nil, err
			}
		}
		n, err := r.SetRecovery(until, ex)
		return map[string]int{"imported": n}, err
	case "export":
		return nil, r.ExportNow()
	case "breaker":
		return nil, r.BreakerCommand(arg(ar.Args, 0))
	case "status-file":
		return r.StatusFile(), nil
	}
	return nil, adminError("unknown command")
}

// StatusFile is the signed status document for an out-of-band location (spec/protocol.md, "Status file").
type StatusFile struct {
	Body      json.RawMessage `json:"body"`
	Signature string          `json:"signature"`
}

// StatusFile builds the signed status document.
func (r *Relay) StatusFile() StatusFile {
	r.mu.Lock()
	now := r.cfg.Now()
	body, _ := json.Marshal(map[string]any{"host": r.cfg.Host, "state": r.serviceStateLocked(now), "notice": r.currentNotice(now), "issued": now.Unix()})
	r.mu.Unlock()
	sig := ed25519.Sign(r.cfg.Identity, []byte(wire.StatusFileText(r.cfg.Host, body)))
	return StatusFile{Body: body, Signature: wire.EncodeB64(sig)}
}
