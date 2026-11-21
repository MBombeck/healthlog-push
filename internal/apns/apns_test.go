package apns

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
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
