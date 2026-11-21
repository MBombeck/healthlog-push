package relay

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// TestBindingProofOfPossession: a binding needs the device key; an instance that only
// knows the token cannot take it over; an old statement cannot be replayed; the device can move.
func TestBindingProofOfPossession(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(2)
	a.activate(d)

	// B signs with its own key for the same token: a conflict, never a takeover.
	thief := newDevice(2)
	rp := b.bind(thief)
	if rp.Status != 409 || rp.str("error") != "binding_conflict" || rp.str("reason") != "challenge_sent" {
		t.Fatalf("conflict: %d %s", rp.Status, rp.Raw)
	}
	if h.bindingOwner(d) != a.id {
		t.Fatal("binding moved without proof")
	}
	// B replays A's statement: the instance id is signed, so it fails.
	stmt := d.bindBody(a.id, h.clk.Now().Unix())
	if rp := b.do(http.MethodPost, "/v1/bindings", stmt); rp.Status != 403 {
		t.Fatalf("replayed statement: %d %s", rp.Status, rp.Raw)
	}
	// Unsigned or wrongly signed statement.
	bad := d.bindBody(b.id, h.clk.Now().Unix())
	bad.Signature = wire.EncodeB64(make([]byte, 64))
	if rp := b.do(http.MethodPost, "/v1/bindings", bad); rp.Status != 403 {
		t.Fatalf("bad signature: %d", rp.Status)
	}
	// The device moves to B with a higher seq; A now gets binding_unknown.
	if rp := b.bind(d); rp.Status != 201 {
		t.Fatalf("move: %d %s", rp.Status, rp.Raw)
	}
	if res := a.push1(alertItem("after-move", d)); res.Status != 404 || res.Error != "binding_unknown" {
		t.Fatalf("old instance after move: %+v", res)
	}
	// An older statement (lower seq) is refused.
	d.seq -= 5
	if rp := a.bind(d); rp.Status != 403 {
		t.Fatalf("lower seq: %d", rp.Status)
	}
}

// TestUniformAnswers: an unknown token and a token bound elsewhere look the same.
func TestUniformAnswers(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(3)
	a.activate(d)
	r1 := b.push1(alertItem("x", d))
	r2 := b.push1(alertItem("y", newDevice(4)))
	if r1.Status != 404 || r2.Status != 404 || r1.Error != r2.Error || r1.Error != "binding_unknown" {
		t.Fatalf("not uniform: %+v %+v", r1, r2)
	}
	// Deleting a binding the instance does not hold answers the same as deleting one it does.
	if rp := b.do(http.MethodDelete, "/v1/bindings", map[string]string{"token": d.hex()}); rp.Status != 204 {
		t.Fatal(rp.Status)
	}
	if h.bindingOwner(d) != a.id {
		t.Fatal("foreign delete removed the binding")
	}
}

// TestChallengeFlow: the conflicting key wins only by answering the challenge push.
func TestChallengeFlow(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(5)
	a.activate(d)
	restored := newDevice(5) // same token, new key (restored app) registering with B
	if rp := b.bind(restored); rp.Status != 409 {
		t.Fatalf("conflict: %d", rp.Status)
	}
	time.Sleep(200 * time.Millisecond)
	var ch string
	for _, r := range h.apns.requests() {
		if strings.Contains(r.Body, `"c":"`) {
			if r.Header.Get("apns-push-type") != "background" {
				t.Errorf("challenge push type %s", r.Header.Get("apns-push-type"))
			}
			var p struct {
				C string `json:"c"`
			}
			_ = json.Unmarshal([]byte(r.Body), &p)
			ch = p.C
		}
	}
	if ch == "" {
		t.Fatal("no challenge push sent")
	}
	if rp := d.answer(h, ch); rp.Status != 403 {
		t.Fatalf("answer with the old key: %d", rp.Status)
	}
	if rp := restored.answer(h, ch); rp.Status != 200 {
		t.Fatalf("answer: %d %s", rp.Status, rp.Raw)
	}
	if h.bindingOwner(d) != b.id {
		t.Fatal("binding did not move after a valid answer")
	}
	if rp := restored.answer(h, ch); rp.Status != 403 {
		t.Fatal("challenge usable twice")
	}
	// One challenge per token per day.
	other := newDevice(5)
	if rp := a.bind(other); rp.Status != 409 || rp.str("reason") != "challenge_quota" {
		t.Fatalf("second challenge same day: %d %s", rp.Status, rp.Raw)
	}
}

func TestConflictFallbackAfterSevenQuietDays(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(6)
	a.activate(d)
	h.clk.Add(8 * 24 * time.Hour)
	if rp := b.bind(newDevice(6)); rp.Status != 201 {
		t.Fatalf("after 8 quiet days: %d %s", rp.Status, rp.Raw)
	}
	if h.bindingOwner(d) != b.id {
		t.Fatal("fallback did not move the binding")
	}
}

// TestDirectOptOut: only the device key can opt out, it works without
// the instance, and the pair stays blocked.
func TestDirectOptOut(t *testing.T) {
	h := newHarness(t)
	a, b := h.register(), h.register()
	d := newDevice(7)
	a.activate(d)
	if rp := h.unbindSelf(d, a.key, a.id); rp.Status != 404 {
		t.Fatalf("opt-out with the instance key: %d", rp.Status)
	}
	if rp := h.unbindSelf(d, d.key, b.id); rp.Status != 404 {
		t.Fatalf("opt-out naming another instance: %d", rp.Status)
	}
	if rp := h.unbindSelf(d, d.key, a.id); rp.Status != 204 {
		t.Fatalf("opt-out: %d %s", rp.Status, rp.Raw)
	}
	if h.state(d) != "" {
		t.Fatal("binding still present")
	}
	if rp := a.do(http.MethodPost, "/v1/bindings", d.heldBody(a.id, h.clk.Now().Unix())); rp.Status != 403 || rp.str("error") != "binding_refused" {
		t.Fatalf("blocked pair rebind: %d %s", rp.Status, rp.Raw)
	}
	if rp := b.bind(d); rp.Status != 201 {
		t.Fatalf("another instance after opt-out: %d", rp.Status)
	}
	if sr := h.selfRead(newDevice(99)); sr.Status != 404 {
		t.Fatalf("self read of an unknown token: %d", sr.Status)
	}
}

// TestOptOutReturnNeedsTheDevice: after a direct opt-out only a statement by the same binding key with a
// higher seq than the binding that left binds the pair again. The statement the instance still holds,
// another key, and a block restored without its key all stay refused.
func TestOptOutReturnNeedsTheDevice(t *testing.T) {
	h := newHarness(t)
	a := h.register()
	d := newDevice(8)
	a.activate(d)
	h.clk.Add(time.Second)
	if rp := h.unbindSelf(d, d.key, a.id); rp.Status != 204 {
		t.Fatalf("opt-out: %d %s", rp.Status, rp.Raw)
	}
	if rp := a.do(http.MethodPost, "/v1/bindings", d.heldBody(a.id, h.clk.Now().Unix())); rp.Status != 403 || rp.str("error") != "binding_refused" {
		t.Fatalf("statement of the binding that left: %d %s", rp.Status, rp.Raw)
	}
	other := newDevice(8)
	other.seq = d.seq + 5
	h.clk.Add(time.Second)
	if rp := a.bind(other); rp.Status != 403 {
		t.Fatalf("another key returned the pair: %d %s", rp.Status, rp.Raw)
	}
	if rp := a.bind(d); rp.Status != 201 || rp.str("state") != "provisional" {
		t.Fatalf("device return: %d %s", rp.Status, rp.Raw)
	}
	if h.bindingOwner(d) != a.id {
		t.Fatal("binding not restored")
	}
	// Leaving again blocks again, and the return statement does not work twice.
	again := d.heldBody(a.id, h.clk.Now().Unix())
	h.clk.Add(time.Second)
	if rp := h.unbindSelf(d, d.key, a.id); rp.Status != 204 {
		t.Fatalf("second opt-out: %d", rp.Status)
	}
	if rp := a.do(http.MethodPost, "/v1/bindings", again); rp.Status != 403 {
		t.Fatalf("return statement after the second opt-out: %d", rp.Status)
	}
}

func TestSandboxRefusedWhenNotServed(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(23)
	bb := d.bindBody(i.id, h.clk.Now().Unix())
	bb.Env = "sandbox"
	if rp := i.do(http.MethodPost, "/v1/bindings", bb); rp.Status != 422 || rp.str("error") != "env_unsupported" {
		t.Fatalf("sandbox: %d %s", rp.Status, rp.Raw)
	}
}

// TestBindAfterInstanceDeletion: a binding request that authenticated just before its instance was
// deleted leaves no orphan binding.
func TestBindAfterInstanceDeletion(t *testing.T) {
	h := newHarness(t)
	i := h.register()
	d := newDevice(0x33)
	h.r.mu.Lock()
	s := h.r.instances[i.id]
	h.r.dropInstanceLocked(i.id)
	b, err := wire.ParseBind(mustJSON(d.bindBody(i.id, h.clk.Now().Unix())), host, i.id, h.clk.Now().Unix())
	if err != nil {
		h.r.mu.Unlock()
		t.Fatal(err)
	}
	status, _, e := h.r.bindLocked(s, b, h.clk.Now())
	h.r.mu.Unlock()
	if e == nil || status != http.StatusUnauthorized || h.state(d) != "" {
		t.Fatalf("orphan binding: %d %+v %q", status, e, h.state(d))
	}
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}
