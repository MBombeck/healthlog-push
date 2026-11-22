package apns

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		status int
		reason string
		want   Outcome
	}{
		{200, "", Accepted}, {410, "Unregistered", Unregistered}, {410, "ExpiredToken", Unregistered},
		{400, "BadDeviceToken", SoftInvalid}, {400, "DeviceTokenNotForTopic", SoftInvalid},
		{400, "BadTopic", Rejected}, {400, "PayloadTooLarge", Rejected}, {413, "PayloadTooLarge", Rejected},
		{403, "ExpiredProviderToken", ProviderExpired}, {403, "InvalidProviderToken", ProviderInvalid},
		{429, "TooManyProviderTokenUpdates", ProviderTooMany}, {429, "TooManyRequests", DeviceThrottled},
		{500, "InternalServerError", Unavailable}, {503, "ServiceUnavailable", Unavailable},
	}
	for _, c := range cases {
		if got := Classify(c.status, c.reason); got != c.want {
			t.Errorf("%d %s: %s, want %s", c.status, c.reason, got, c.want)
		}
	}
	// Only 410 is final: nothing else maps to Unregistered.
	for s := 100; s < 600; s++ {
		if s != 410 && Classify(s, "Unregistered") == Unregistered {
			t.Errorf("status %d classified as Unregistered", s)
		}
	}
}

func TestTemplates(t *testing.T) {
	env := []byte{1, 1, 1, 0xff}
	for _, p := range [][]byte{AlertPayload(env), SilentPayload(env), ChallengePayload("abc"), LiveActivityEndPayload(time.Unix(1795000000, 0))} {
		var m map[string]any
		if err := json.Unmarshal(p, &m); err != nil {
			t.Fatalf("invalid JSON %s", p)
		}
	}
	a := string(AlertPayload(env))
	if strings.Contains(a, "category") || strings.Contains(a, "thread-id") || strings.Contains(a, "interruption-level") || strings.Contains(a, `"title"`) {
		t.Fatalf("alert template carries visible fields: %s", a)
	}
	var la struct {
		APS struct {
			Event string         `json:"event"`
			TS    int64          `json:"timestamp"`
			CS    map[string]any `json:"content-state"`
		} `json:"aps"`
	}
	_ = json.Unmarshal(LiveActivityEndPayload(time.Unix(1795000000, 0)), &la)
	if la.APS.Event != "end" || la.APS.TS != 1795000000 || len(la.APS.CS) != 6 {
		t.Fatalf("live activity end: %+v", la)
	}
}

type fixedTokens struct{}

func (fixedTokens) Token() (string, int64, bool) { return "h.c.s", 1, true }
func (fixedTokens) RequestRefresh()              {}

// TestWarmUpEndsAfterFirstAttempt: when Apple cannot be reached at start, the one-at-a-time warm-up must
// end after the first attempt, or every sender would queue behind one lock for the full timeout.
func TestWarmUpEndsAfterFirstAttempt(t *testing.T) {
	c := &Client{HTTP: NewHTTPClient(nil), BaseURL: "https://127.0.0.1:1", Topic: "t", Tokens: fixedTokens{}}
	res := c.Send(context.Background(), &Push{Token: []byte{1}, Payload: []byte("{}"), Expiration: time.Now()})
	if res.Outcome != Unavailable {
		t.Fatalf("outcome %s", res.Outcome)
	}
	if !c.warm.Load() {
		t.Fatal("warm-up still active after a failed first attempt")
	}
}

// TestPriorities: alert 10; silent and challenge 5; a Live Activity 10 only when urgent.
func TestPriorities(t *testing.T) {
	c := &Client{Topic: "dev.example.app"}
	cases := []struct {
		p        Push
		priority string
		pushType string
		topic    string
	}{
		{Push{Class: wire.ClassAlert}, "10", "alert", "dev.example.app"},
		{Push{Class: wire.ClassSilent}, "5", "background", "dev.example.app"},
		{Push{Class: wire.ClassAlert, Challenge: true}, "5", "background", "dev.example.app"},
		{Push{Class: wire.ClassLiveActivity, Urgent: true}, "10", "liveactivity", "dev.example.app.push-type.liveactivity"},
		{Push{Class: wire.ClassLiveActivity}, "5", "liveactivity", "dev.example.app.push-type.liveactivity"},
	}
	for _, k := range cases {
		h := http.Header{}
		c.setHeaders(h, &k.p, "jwt")
		if h.Get("apns-priority") != k.priority || h.Get("apns-push-type") != k.pushType || h.Get("apns-topic") != k.topic || h.Get("apns-id") != "" {
			t.Errorf("%+v: %v", k.p, h)
		}
	}
}

// TestLiveActivityUrgent: due, overdue and the end are urgent; every other state is not.
func TestLiveActivityUrgent(t *testing.T) {
	st := func(s string) *wire.ContentState { return &wire.ContentState{Status: &s} }
	for _, s := range wire.StateStatuses {
		want := s == "due" || s == "overdue"
		for _, ev := range []string{wire.EventStart, wire.EventUpdate} {
			if got := LiveActivityUrgent(ev, st(s)); got != want {
				t.Errorf("%s %s: %v", ev, s, got)
			}
		}
	}
	if !LiveActivityUrgent(wire.EventEnd, nil) {
		t.Error("end not urgent")
	}
	if LiveActivityUrgent(wire.EventUpdate, nil) || LiveActivityUrgent(wire.EventUpdate, &wire.ContentState{}) {
		t.Error("update without a state urgent")
	}
}

// TestSendReadsTimestampAndUniqueID: a 410 carries Apple's timestamp in milliseconds, any answer may
// carry apns-unique-id (development only); implausible values are dropped.
func TestSendReadsTimestampAndUniqueID(t *testing.T) {
	type answer struct {
		status int
		body   string
		uid    string
	}
	var next answer
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if next.uid != "" {
			w.Header().Set("apns-unique-id", next.uid)
		}
		w.WriteHeader(next.status)
		_, _ = io.WriteString(w, next.body)
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c := &Client{HTTP: NewHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}), BaseURL: srv.URL, Topic: "t", Tokens: fixedTokens{}}
	send := func(a answer) Result {
		next = a
		return c.Send(context.Background(), &Push{Token: []byte{1}, Payload: []byte("{}"), Expiration: time.Now()})
	}
	const uid, lower = "0A1B2C3D-4E5F-4a6b-8c7d-9e0f1a2b3c4d", "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d"
	r := send(answer{410, `{"reason":"Unregistered","timestamp":1795000000123}`, uid})
	if r.Outcome != Unregistered || !r.InvalidSince.Equal(time.UnixMilli(1795000000123)) || r.UniqueID != lower {
		t.Fatalf("410: %+v", r)
	}
	for name, body := range map[string]string{
		"no timestamp": `{"reason":"Unregistered"}`,
		"seconds":      `{"reason":"Unregistered","timestamp":1795000000}`,
		"negative":     `{"reason":"Unregistered","timestamp":-5}`,
		"string":       `{"reason":"Unregistered","timestamp":"1795000000123"}`,
	} {
		if r := send(answer{410, body, ""}); r.Outcome != Unregistered || !r.InvalidSince.IsZero() {
			t.Errorf("%s: %+v", name, r)
		}
	}
	// A timestamp on anything but a 410 is ignored.
	if r := send(answer{400, `{"reason":"BadDeviceToken","timestamp":1795000000123}`, ""}); !r.InvalidSince.IsZero() {
		t.Errorf("timestamp kept on a 400: %+v", r)
	}
	for _, bad := range []string{"x", "0a1b2c3d4e5f4a6b8c7d9e0f1a2b3c4d", "0a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4z", "0a1b2c3d-4e5f-4a6b-8c7d_9e0f1a2b3c4d"} {
		if r := send(answer{200, "", bad}); r.Outcome != Accepted || r.UniqueID != "" {
			t.Errorf("unique id %q kept: %+v", bad, r)
		}
	}
	if r := send(answer{200, "", uid}); r.UniqueID != lower {
		t.Errorf("unique id on 200: %+v", r)
	}
}
