// Command healthlog-push is the HealthLog push relay. One binary, two processes: "relay" serves the API and
// talks to Apple; "signer" holds the APNs key without network access and writes short-lived JWTs.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/MBombeck/healthlog-push/internal/admin"
	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/buildinfo"
	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/relay"
	"github.com/MBombeck/healthlog-push/internal/signer"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"relay"}
	}
	var err error
	switch args[0] {
	case "relay":
		err = runRelay()
	case "signer":
		err = runSigner()
	case "admin":
		if len(args) == 1 {
			fmt.Print(admin.Usage)
			return
		}
		var ar *relay.AdminRequest
		if ar, err = admin.Parse(args[1:]); err == nil {
			err = admin.Run(env("HLP_ADMIN_SOCKET", "/data/admin.sock"), ar, os.Stdout)
		}
	case "keygen":
		err = keygen(arg(args, 1), os.Stdout)
	case "healthcheck":
		err = healthcheck(slices.Contains(args, "--signer"))
	case "version":
		fmt.Println(buildinfo.Version, buildinfo.Commit)
	default:
		err = fmt.Errorf("unknown command %q (relay, signer, admin, keygen, healthcheck, version)", args[0])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthlog-push:", err)
		os.Exit(1)
	}
}

func arg(a []string, i int) string {
	if i < len(a) {
		return a[i]
	}
	return ""
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// envOrFile reads K, or the file named by K_FILE.
func envOrFile(k string) (string, error) {
	if v := os.Getenv(k); v != "" {
		return v, nil
	}
	if f := os.Getenv(k + "_FILE"); f != "" {
		b, err := os.ReadFile(f) //nolint:gosec // operator-provided path
		return strings.TrimSpace(string(b)), err
	}
	return "", fmt.Errorf("%s or %s_FILE is required", k, k)
}

func readSecret(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name)) //nolint:gosec // fixed names in the secrets directory
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", name, err)
	}
	return []byte(strings.TrimSpace(string(b))), nil
}

// decodeKeyMaterial accepts base64url or standard base64, padded or not.
func decodeKeyMaterial(b []byte) ([]byte, error) {
	s := string(b)
	for _, dec := range []func(string) ([]byte, error){base64.RawURLEncoding.DecodeString, base64.StdEncoding.DecodeString, base64.RawStdEncoding.DecodeString} {
		if v, err := dec(s); err == nil {
			return v, nil
		}
	}
	return nil, errors.New("not base64")
}

// loadIdentity reads the relay identity key: a PKCS#8 PEM Ed25519 key or a base64 32-byte seed.
func loadIdentity(b []byte) (ed25519.PrivateKey, error) {
	if blk, _ := pem.Decode(b); blk != nil {
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("relay_id_key is not Ed25519")
		}
		return ek, nil
	}
	seed, err := decodeKeyMaterial(b)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("relay_id_key must be PEM or a base64 32-byte seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func runRelay() error {
	host := os.Getenv("HLP_PUBLIC_HOST")
	if host == "" {
		return errors.New("HLP_PUBLIC_HOST is required")
	}
	secrets := env("HLP_SECRETS_DIR", "/run/secrets/relay")
	idb, err := readSecret(secrets, "relay_id_key")
	if err != nil {
		return err
	}
	id, err := loadIdentity(idb)
	if err != nil {
		return err
	}
	var macKeys [][]byte
	for _, n := range []string{"token_mac_key", "token_mac_key_previous"} {
		b, err := readSecret(secrets, n)
		if err != nil {
			if n == "token_mac_key_previous" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		k, err := decodeKeyMaterial(b)
		if err != nil || len(k) < 32 {
			return fmt.Errorf("%s must be base64 of at least 32 bytes", n)
		}
		macKeys = append(macKeys, k)
	}
	dataDir := env("HLP_DATA_DIR", "/data")
	exportDir := env("HLP_EXPORT_DIR", "/export")
	st, recovered, err := openStore(dataDir, exportDir)
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	tokens := &apns.FileTokens{Dir: env("HLP_JWT_DIR", "/run/jwt"), RefreshDir: env("HLP_JWT_REFRESH_DIR", "/run/jwt-refresh")}
	base := env("HLP_APNS_URL", "https://api.push.apple.com")
	client := &apns.Client{HTTP: apns.NewHTTPClient(nil), BaseURL: base, SandboxURL: env("HLP_APNS_SANDBOX_URL", "https://api.sandbox.push.apple.com"),
		Topic: env("HLP_APNS_TOPIC", "dev.healthlog.app"), Tokens: tokens}
	envs := map[string]bool{}
	for _, e := range strings.Split(env("HLP_APNS_ENVIRONMENT", "production"), ",") {
		envs[strings.TrimSpace(e)] = true
	}
	var minClient [3]int
	if v := os.Getenv("HLP_MIN_CLIENT_VERSION"); v != "" {
		if _, minClient, err = wire.ParseClient("healthlog/" + v); err != nil {
			return errors.New("HLP_MIN_CLIENT_VERSION must look like 1.49.0")
		}
	}
	r, err := relay.New(relay.Config{
		Host: host, Identity: id, MACKeys: macKeys, Environments: envs, ExportDir: exportDir, MinClient: minClient,
		Version: buildinfo.Version, Commit: buildinfo.Commit, ImageDigest: os.Getenv("HLP_IMAGE_DIGEST"),
		ProviderTokenOK: func() bool { _, _, ok := tokens.Token(); return ok },
	}, st, client)
	if err != nil {
		return err
	}
	if recovered {
		if _, err := r.SetRecovery(store.Day(time.Now())+14, nil); err != nil {
			return err
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	tlsCfg, err := tlsConfig(host)
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", env("HLP_LISTEN", ":8443"))
	if err != nil {
		return err
	}
	cl := limits.NewConnLimiter(ln, 2000, 50)
	cl.Rejected = func() { r.M.Inc("hlp_connections_rejected_total") }
	srv := &http.Server{
		Handler:           r.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(r.ErrLog, "", 0),
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: 100},
	}
	metricsSrv := &http.Server{Addr: env("HLP_METRICS_LISTEN", "127.0.0.1:9464"), Handler: r.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	adminSrv, adminLn, err := adminSocket(env("HLP_ADMIN_SOCKET", filepath.Join(dataDir, "admin.sock")), r)
	if err != nil {
		return err
	}
	errc := make(chan error, 3)
	go func() { errc <- srv.ServeTLS(cl, "", "") }()
	go func() { errc <- metricsSrv.ListenAndServe() }()
	go func() { errc <- adminSrv.Serve(adminLn) }()
	go r.Run(ctx)
	logx.Event("relay.start", logx.Str(logx.KVersion, buildinfo.Version))
	select {
	case <-ctx.Done():
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			logx.Event("relay.listener_failed")
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	r.Close()
	_ = metricsSrv.Close()
	_ = adminSrv.Close()
	logx.Event("relay.stop")
	return nil
}

// openStore opens the database. A damaged file is moved aside, an empty store is created, and the latest
// registry export is imported; the caller then opens the recovery window.
func openStore(dataDir, exportDir string) (*store.Store, bool, error) {
	path := filepath.Join(dataDir, "relay.db")
	_, statErr := os.Stat(path)
	fresh := errors.Is(statErr, os.ErrNotExist)
	st, err := store.Open(path)
	if err == nil {
		if cerr := st.Check(); cerr == nil {
			if fresh {
				return importExport(st, exportDir)
			}
			return st, false, nil
		}
		_ = st.Close()
	}
	aside := path + ".damaged-" + time.Now().UTC().Format("20060102")
	if rerr := os.Rename(path, aside); rerr != nil {
		return nil, false, fmt.Errorf("database unusable and cannot be moved aside: %w", rerr)
	}
	logx.Event("store.damaged_moved_aside")
	st, err = store.Open(path)
	if err != nil {
		return nil, false, err
	}
	return importExport(st, exportDir)
}

func importExport(st *store.Store, exportDir string) (*store.Store, bool, error) {
	ex, err := store.ReadExport(filepath.Join(exportDir, "registry.json"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, false, nil
		}
		return nil, false, fmt.Errorf("registry export unreadable: %w", err)
	}
	n, err := st.Import(ex, store.Day(time.Now()))
	if err != nil {
		return nil, false, err
	}
	logx.Event("store.imported_export", logx.Int(logx.KCount, int64(n)))
	return st, true, nil
}

func tlsConfig(host string) (*tls.Config, error) {
	switch mode := env("HLP_TLS_MODE", "acme"); mode {
	case "files":
		cert, err := tls.LoadX509KeyPair(os.Getenv("HLP_TLS_CERT_FILE"), os.Getenv("HLP_TLS_KEY_FILE"))
		if err != nil {
			return nil, err
		}
		return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}, nil
	case "acme":
		kb, err := os.ReadFile(env("HLP_ACME_ACCOUNT_KEY_FILE", "/run/secrets/relay/acme_account_key"))
		if err != nil {
			return nil, fmt.Errorf("acme account key: %w", err)
		}
		blk, _ := pem.Decode(kb)
		if blk == nil {
			return nil, errors.New("acme account key: no PEM block")
		}
		key, err := parseSigner(blk.Bytes)
		if err != nil {
			return nil, err
		}
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(host),
			Cache:      autocert.DirCache(env("HLP_ACME_CACHE_DIR", "/acme")),
			Email:      os.Getenv("HLP_ACME_EMAIL"),
			Client:     &acme.Client{Key: key, DirectoryURL: env("HLP_ACME_DIRECTORY", autocert.DefaultACMEDirectory)},
		}
		base := m.TLSConfig()
		base.MinVersion = tls.VersionTLS13
		// The TLS-ALPN-01 validation handshake may use TLS 1.2; everything else needs TLS 1.3.
		challenge := base.Clone()
		challenge.MinVersion = tls.VersionTLS12
		base.GetConfigForClient = func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			if slices.Contains(h.SupportedProtos, acme.ALPNProto) {
				return challenge, nil
			}
			return nil, nil
		}
		return base, nil
	default:
		return nil, fmt.Errorf("HLP_TLS_MODE %q: use acme or files", mode)
	}
}

func parseSigner(der []byte) (*ecdsa.PrivateKey, error) {
	if k, err := x509.ParseECPrivateKey(der); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("acme account key must be an EC key")
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("acme account key must be an EC key")
	}
	return ek, nil
}

func adminSocket(path string, r *relay.Relay) (*http.Server, net.Listener, error) {
	_ = os.Remove(path)
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "unix", path)
	if err != nil {
		return nil, nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, nil, err
	}
	return &http.Server{Handler: r.AdminHandler(), ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}, ln, nil
}

func runSigner() error {
	key, err := signer.LoadKey(env("HLP_APNS_KEY_FILE", "/run/secrets/signer/apns.p8"))
	if err != nil {
		return err
	}
	keyID, err := envOrFile("HLP_APNS_KEY_ID")
	if err != nil {
		return err
	}
	teamID, err := envOrFile("HLP_APNS_TEAM_ID")
	if err != nil {
		return err
	}
	s := &signer.Signer{Key: key, KeyID: keyID, TeamID: teamID, Dir: env("HLP_JWT_DIR", "/run/jwt"),
		RefreshDir: env("HLP_JWT_REFRESH_DIR", "/run/jwt-refresh"), Now: time.Now}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	logx.Event("signer.start", logx.Str(logx.KVersion, buildinfo.Version))
	t := time.NewTicker(signer.PollInterval)
	defer t.Stop()
	for {
		if wrote, err := s.Step(); err != nil {
			logx.Event("signer.write_failed")
		} else if wrote {
			logx.Event("signer.token_written")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func keygen(kind string, out io.Writer) error {
	switch kind {
	case "relay-id":
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]string{
			"relay_id_key": base64.RawURLEncoding.EncodeToString(priv.Seed()),
			"publicKey":    wire.EncodeB64(pub),
		})
	case "token-mac":
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, base64.RawURLEncoding.EncodeToString(b))
		return err
	case "acme-account":
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return err
		}
		return pem.Encode(out, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	}
	return errors.New("keygen relay-id|token-mac|acme-account")
}

func healthcheck(isSigner bool) error {
	if isSigner {
		if !signer.Fresh(env("HLP_JWT_DIR", "/run/jwt"), 60*time.Minute, time.Now()) {
			return errors.New("no fresh provider token")
		}
		return nil
	}
	c := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+env("HLP_METRICS_LISTEN", "127.0.0.1:9464")+"/healthz", http.NoBody)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	var h struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&h); err != nil {
		return err
	}
	if h.Status != "ok" {
		return fmt.Errorf("status %s", h.Status)
	}
	return nil
}
