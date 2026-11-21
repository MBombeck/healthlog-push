package relay

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/signer"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

const host = "push.example.org"

// clock is a settable test clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

// verifyJWT checks an ES256 token against a public key.
func verifyJWT(pub *ecdsa.PublicKey, jwt string) bool {
	i := strings.LastIndexByte(jwt, '.')
	if i < 0 {
		return false
	}
	sig, err := wire.DecodeB64(jwt[i+1:], 64)
	if err != nil {
		return false
	}
	sum := sha256.Sum256([]byte(jwt[:i]))
	return ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}

// fakeAPNs is an HTTP/2 TLS server that checks the provider JWT and answers per token.
type fakeAPNs struct {
	srv    *httptest.Server
	pub    *ecdsa.PublicKey
	mu     sync.Mutex
	reqs   []apnsReq
	answer func(token string, push apnsReq) (int, string)
}

type apnsReq struct {
	Token  string
	Header http.Header
	Body   string
	Proto  string
}

func newFakeAPNs(t *testing.T, pub *ecdsa.PublicKey) *fakeAPNs {
	f := &fakeAPNs{pub: pub, answer: func(string, apnsReq) (int, string) { return 200, "" }}
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		tok := strings.TrimPrefix(r.URL.Path, "/3/device/")
		ar := apnsReq{Token: tok, Header: r.Header.Clone(), Body: string(b), Proto: r.Proto}
		if !verifyJWT(f.pub, strings.TrimPrefix(r.Header.Get("authorization"), "bearer ")) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(w, `{"reason":"InvalidProviderToken"}`)
			return
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, ar)
		ans := f.answer
		f.mu.Unlock()
		status, reason := ans(tok, ar)
		w.WriteHeader(status)
		if reason != "" {
			_, _ = io.WriteString(w, `{"reason":"`+reason+`"}`)
		}
	}))
	f.srv.EnableHTTP2 = true
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAPNs) setAnswer(a func(token string, push apnsReq) (int, string)) {
	f.mu.Lock()
	f.answer = a
	f.mu.Unlock()
}

func (f *fakeAPNs) requests() []apnsReq {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]apnsReq(nil), f.reqs...)
}

// staticTokens hands out a JWT signed by the test provider key.
type staticTokens struct {
	mu      sync.Mutex
	key     *ecdsa.PrivateKey
	jwt     string
	iat     int64
	refresh int
}

func (s *staticTokens) Token() (string, int64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.jwt, s.iat, s.jwt != ""
}
func (s *staticTokens) RequestRefresh() { s.mu.Lock(); s.refresh++; s.mu.Unlock() }
func (s *staticTokens) renew(t *testing.T, iat time.Time) {
	j, err := signer.MakeJWT(s.key, "KEYID12345", "TEAMID1234", iat)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	s.jwt, s.iat = j, iat.Unix()
	s.mu.Unlock()
}

type harness struct {
	t      *testing.T
	clk    *clock
	r      *Relay
	st     *store.Store
	apns   *fakeAPNs
	tokens *staticTokens
	srv    *httptest.Server
	client *http.Client
	relayP ed25519.PublicKey
	logs   *bytes.Buffer
	dir    string
}

type syncBuf struct {
	mu sync.Mutex
	b  *bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }

type option func(*Config)

func newHarness(t *testing.T, opts ...option) *harness {
	t.Helper()
	pk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f := newFakeAPNs(t, &pk.PublicKey)
	clk := &clock{t: time.Date(2026, 12, 1, 10, 0, 0, 0, time.UTC)}
	tokens := &staticTokens{key: pk}
	tokens.renew(t, clk.Now())
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "relay.db"))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(f.srv.Certificate())
	client := &apns.Client{HTTP: apns.NewHTTPClient(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}), BaseURL: f.srv.URL, SandboxURL: f.srv.URL,
		Topic: "dev.example.app", Tokens: tokens}
	idPub, idKey, _ := ed25519.GenerateKey(rand.Reader)
	cfg := Config{Host: host, Identity: idKey, MACKeys: [][]byte{bytes.Repeat([]byte{7}, 32)}, Workers: 8, Now: clk.Now,
		ExportDir: dir, Registrations: limits.RegistrationLimits{PerNarrowDay: 1000, PerWideDay: 1000, GlobalHour: 1000, GlobalDay: 1000}}
	// Request and push rates are raised so tests can issue many calls inside one fake minute; the tests of
	// those limits pass withDefaultLimits.
	fast := DefaultLimits
	fast.Probation.RequestsMinute, fast.Probation.PushesMinute = 100000, 100000
	cfg.Limits = fast
	for _, o := range opts {
		o(&cfg)
	}
	logs := &bytes.Buffer{}
	logx.SetOutput(&syncBuf{b: logs})
	r, err := New(cfg, st, client)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(r.Handler())
	srv.EnableHTTP2 = true
	srv.StartTLS()
	h := &harness{t: t, clk: clk, r: r, st: st, apns: f, tokens: tokens, srv: srv, client: srv.Client(), relayP: idPub, logs: logs, dir: dir}
	t.Cleanup(func() { srv.Close(); r.Close(); _ = st.Close() })
	return h
}

// response is a parsed, signature-checked relay answer.
type response struct {
	Status int
	Body   map[string]any
	Raw    []byte
	Header http.Header
}

func (rp response) str(k string) string { s, _ := rp.Body[k].(string); return s }

// send performs a request and verifies the response signature against the relay identity key, the method,
// the path and the nonce. A /v1 request without a nonce gets a fresh one, as every client must send.
func (h *harness) send(req *http.Request, nonce string) response {
	h.t.Helper()
	if nonce == "" && strings.HasPrefix(req.URL.Path, "/v1/") && req.Header.Get("HL-Nonce") == "" {
		nonce = randNonce()
		req.Header.Set("HL-Nonce", nonce)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	if nonce == "" {
		nonce = "-"
	}
	sig, err := wire.ParseSignature(resp.Header.Get("HL-Relay-Signature"))
	if err != nil || !wire.Verify(h.relayP, wire.ResponseText(host, req.Method, req.URL.RequestURI(), nonce, resp.StatusCode, raw), sig) {
		h.t.Fatalf("%s %s: response signature invalid (status %d)", req.Method, req.URL.Path, resp.StatusCode)
	}
	out := response{Status: resp.StatusCode, Raw: raw, Header: resp.Header}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out.Body)
	}
	return out
}

// hexSHA256 is the lowercase hex SHA-256 of b, the body hash in a signed request text.
func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func randNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return wire.EncodeB64(b)
}

// instance is a simulated HealthLog server.
type instance struct {
	h   *harness
	key ed25519.PrivateKey
	id  string
}

func (h *harness) register() *instance {
	h.t.Helper()
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	i := &instance{h: h, key: key}
	rp := i.registerRaw("")
	if rp.Status != http.StatusCreated {
		h.t.Fatalf("register: %d %s", rp.Status, rp.Raw)
	}
	i.id = rp.str("instanceId")
	return i
}

func (i *instance) registerRaw(invite string) response {
	pub := ed25519.PublicKey(i.key[32:])
	ts := i.h.clk.Now().Unix()
	b, _ := json.Marshal(wire.RegisterBody{PublicKey: wire.EncodeB64(pub), Client: "healthlog/1.49.0", Time: ts, Invite: invite,
		Proof: wire.EncodeB64(ed25519.Sign(i.key, []byte(wire.RegisterText(host, pub, ts))))})
	req, _ := http.NewRequest(http.MethodPost, i.h.srv.URL+"/v1/instances", bytes.NewReader(b))
	return i.h.send(req, "")
}

// do sends an instance-signed request.
func (i *instance) do(method, path string, body any) response {
	i.h.t.Helper()
	var b []byte
	switch v := body.(type) {
	case nil:
	case []byte:
		b = v
	default:
		b, _ = json.Marshal(v)
	}
	return i.doRaw(method, path, b, i.h.clk.Now().Unix(), randNonce(), nil)
}

func (i *instance) doRaw(method, path string, body []byte, ts int64, nonce string, mutate func(text string) string) response {
	text := wire.RequestText(host, i.id, method, path, ts, nonce, body)
	if mutate != nil {
		text = mutate(text)
	}
	req, _ := http.NewRequest(method, i.h.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("HL-Instance", i.id)
	req.Header.Set("HL-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("HL-Nonce", nonce)
	req.Header.Set("HL-Signature", wire.EncodeB64(ed25519.Sign(i.key, []byte(text))))
	return i.h.send(req, nonce)
}

// device is a simulated app installation with its binding key and APNs token.
type device struct {
	key   ed25519.PrivateKey
	token []byte
	seq   int64
}

func newDevice(n byte) *device {
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	tok := bytes.Repeat([]byte{n}, 32)
	return &device{key: key, token: tok}
}

func (d *device) hex() string { return hex.EncodeToString(d.token) }

func (d *device) bindBody(instID string, iat int64) wire.BindBody {
	d.seq++
	tag := wire.TokenTag(d.token)
	return wire.BindBody{
		Token: d.hex(), Env: "production", BindingKey: wire.EncodeB64(ed25519.PublicKey(d.key[32:])),
		Statement: wire.Statement{InstanceID: instID, TokenTag: hex.EncodeToString(tag), Kind: "device", Seq: d.seq, Iat: iat},
		Signature: wire.EncodeB64(ed25519.Sign(d.key, []byte(wire.BindText(host, instID, tag, "device", d.seq, iat)))),
		Consent:   wire.Consent{TextVersion: "2026-11-21", Day: "2026-11-21"},
	}
}

// heldBody signs the statement of the device's current seq again: what an instance the device left still
// holds and can replay.
func (d *device) heldBody(instID string, iat int64) wire.BindBody {
	d.seq--
	return d.bindBody(instID, iat)
}

func (i *instance) bind(d *device) response {
	return i.do(http.MethodPost, "/v1/bindings", d.bindBody(i.id, i.h.clk.Now().Unix()))
}

func envelope(c wire.Class) string {
	e := make([]byte, c.EnvelopeLength())
	e[0], e[1], e[2] = 1, 1, c.ClassByte()
	_, _ = rand.Read(e[3:])
	return wire.EncodeB64(e)
}

var collapse = strings.Repeat("C", 22)

func alertItem(ref string, d *device) wire.PushItem {
	return wire.PushItem{Ref: ref, Token: d.hex(), Env: "production", Class: wire.ClassAlert, TTLSeconds: 3600, Envelope: envelope(wire.ClassAlert), Collapse: collapse}
}

func silentItem(ref string, d *device) wire.PushItem {
	return wire.PushItem{Ref: ref, Token: d.hex(), Env: "production", Class: wire.ClassSilent, TTLSeconds: 600, Envelope: envelope(wire.ClassSilent)}
}

// push sends items and returns the per-item results.
func (i *instance) push(items ...wire.PushItem) (response, []ItemResult) {
	i.h.t.Helper()
	rp := i.do(http.MethodPost, "/v1/push", wire.PushBody{Items: items})
	var pr pushResp
	_ = json.Unmarshal(rp.Raw, &pr)
	return rp, pr.Results
}

func (i *instance) push1(it wire.PushItem) ItemResult {
	i.h.t.Helper()
	rp, res := i.push(it)
	if rp.Status != http.StatusOK || len(res) != 1 {
		i.h.t.Fatalf("push: %d %s", rp.Status, rp.Raw)
	}
	return res[0]
}

// answer answers a conflict challenge for the device's token, signed with its binding key.
func (d *device) answer(h *harness, challenge string) response {
	tag := wire.TokenTag(d.token)
	b, _ := json.Marshal(wire.ChallengeBody{BindingKey: wire.EncodeB64(ed25519.PublicKey(d.key[32:])), Challenge: challenge,
		TokenTag: hex.EncodeToString(tag), Signature: wire.EncodeB64(ed25519.Sign(d.key, []byte(wire.ChallengeText(host, challenge, tag))))})
	req, _ := http.NewRequest(http.MethodPost, h.srv.URL+"/v1/bindings/challenge", bytes.NewReader(b))
	return h.send(req, "")
}

// activity is a Live Activity end for the activity token la, with an activity statement signed by the
// device's binding key at iat.
func (d *device) activity(ref, instID string, la []byte, iat int64) wire.PushItem {
	tag, laTag := wire.TokenTag(d.token), wire.TokenTag(la)
	a := &wire.Activity{Token: hex.EncodeToString(la), BindingKey: wire.EncodeB64(ed25519.PublicKey(d.key[32:])),
		Signature: wire.EncodeB64(ed25519.Sign(d.key, []byte(wire.ActivityText(host, instID, tag, laTag, iat))))}
	a.Statement.InstanceID, a.Statement.TokenTag, a.Statement.LATokenTag, a.Statement.Iat = instID, hex.EncodeToString(tag), hex.EncodeToString(laTag), iat
	return wire.PushItem{Ref: ref, Token: d.hex(), Env: "production", Class: wire.ClassLiveActivity, TTLSeconds: 3600, Activity: a}
}

// rotate asks the relay to replace the instance key with key, with a proof of possession of the new key.
func (i *instance) rotate(key ed25519.PrivateKey) response {
	pub := ed25519.PublicKey(key[32:])
	ts := i.h.clk.Now().Unix()
	return i.do(http.MethodPost, "/v1/instances/self/rotate", wire.RegisterBody{PublicKey: wire.EncodeB64(pub), Time: ts,
		Proof: wire.EncodeB64(ed25519.Sign(key, []byte(wire.RegisterText(host, pub, ts))))})
}

// selfRead calls GET /v1/bindings/self as the app.
func (h *harness) selfRead(d *device) response {
	iat := h.clk.Now().Unix()
	tag := wire.TokenTag(d.token)
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/v1/bindings/self", http.NoBody)
	nonce := randNonce()
	req.Header.Set("HL-Nonce", nonce)
	req.Header.Set("HL-Token", d.hex())
	req.Header.Set("HL-Binding-Key", wire.EncodeB64(ed25519.PublicKey(d.key[32:])))
	req.Header.Set("HL-Iat", strconv.FormatInt(iat, 10))
	req.Header.Set("HL-Signature", wire.EncodeB64(ed25519.Sign(d.key, []byte(wire.SelfReadText(host, tag, iat)))))
	return h.send(req, nonce)
}

// unbindSelf calls DELETE /v1/bindings/self signed by key.
func (h *harness) unbindSelf(d *device, key ed25519.PrivateKey, instID string) response {
	iat := h.clk.Now().Unix()
	tag := wire.TokenTag(d.token)
	body := map[string]any{"token": d.hex(), "bindingKey": wire.EncodeB64(ed25519.PublicKey(key[32:])),
		"statement": map[string]any{"instanceId": instID, "tokenTag": hex.EncodeToString(tag), "iat": iat},
		"signature": wire.EncodeB64(ed25519.Sign(key, []byte(wire.UnbindText(host, instID, tag, iat))))}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodDelete, h.srv.URL+"/v1/bindings/self", bytes.NewReader(b))
	return h.send(req, "")
}

func (h *harness) state(d *device) string {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	if b := h.r.bindings[mac(h.r.cfg.MACKeys[0], d.token)]; b != nil {
		return b.State
	}
	return ""
}

func (h *harness) bindingOwner(d *device) string {
	h.r.mu.Lock()
	defer h.r.mu.Unlock()
	if b := h.r.bindings[mac(h.r.cfg.MACKeys[0], d.token)]; b != nil {
		return b.InstanceID
	}
	return ""
}

// activate binds a device and sends one accepted push so the binding is active.
func (i *instance) activate(d *device) {
	i.h.t.Helper()
	if rp := i.bind(d); rp.Status != http.StatusCreated {
		i.h.t.Fatalf("bind: %d %s", rp.Status, rp.Raw)
	}
	if res := i.push1(alertItem("act-"+d.hex()[:6]+strconv.Itoa(int(d.seq)), d)); res.Result != "accepted" {
		i.h.t.Fatalf("activate: %+v", res)
	}
}

func withDefaultLimits(c *Config) { c.Limits = DefaultLimits }
