package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/MBombeck/healthlog-push/internal/apns"
	"github.com/MBombeck/healthlog-push/internal/buildinfo"
	"github.com/MBombeck/healthlog-push/internal/limits"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/relay"
	"github.com/MBombeck/healthlog-push/internal/store"
	"github.com/MBombeck/healthlog-push/internal/wire"
)

// maxStreams bounds concurrent HTTP/2 streams per connection; an instance never needs more, and together
// with the connection limits it bounds the request bodies that can be in flight.
const maxStreams = 16

func runRelay() error {
	host := os.Getenv("HLP_PUBLIC_HOST")
	if err := checkPublicHost(host); err != nil {
		return err
	}
	topic := os.Getenv("HLP_APNS_TOPIC")
	if topic == "" {
		return errors.New("HLP_APNS_TOPIC is required")
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
	macKeys, err := loadMACKeys(secrets)
	if err != nil {
		return err
	}
	exportDir := env("HLP_EXPORT_DIR", "/export")
	st, recovered, err := openStore(dataDir(), exportDir, exportTrust{pub: ed25519.PublicKey(id[32:]), host: host})
	if err != nil {
		return err
	}
	defer func() { _ = st.Close() }()

	tokens := &apns.FileTokens{Dir: jwtDir(), RefreshDir: jwtRefreshDir()}
	client := &apns.Client{HTTP: apns.NewHTTPClient(nil), BaseURL: apns.ProductionURL, SandboxURL: apns.SandboxURL,
		Topic: topic, Tokens: tokens}
	cfg, err := relayConfig(host, id, macKeys, exportDir)
	if err != nil {
		return err
	}
	cfg.ProviderTokenOK = func() bool { _, _, ok := tokens.Token(); return ok }
	r, err := relay.New(cfg, st, client)
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
	return serve(ctx, r, tlsCfg)
}

// relayConfig assembles the relay configuration from the environment.
func relayConfig(host string, id ed25519.PrivateKey, macKeys [][]byte, exportDir string) (relay.Config, error) {
	envs := map[string]bool{}
	for _, e := range strings.Split(env("HLP_APNS_ENVIRONMENT", "production"), ",") {
		e = strings.TrimSpace(e)
		if e != "production" && e != "sandbox" {
			return relay.Config{}, fmt.Errorf("HLP_APNS_ENVIRONMENT: %q is not production or sandbox", e)
		}
		envs[e] = true
	}
	var minClient [3]int
	if v := os.Getenv("HLP_MIN_CLIENT_VERSION"); v != "" {
		var err error
		if _, minClient, err = wire.ParseClient("healthlog/" + v); err != nil {
			return relay.Config{}, errors.New("HLP_MIN_CLIENT_VERSION must look like 1.49.0")
		}
	}
	return relay.Config{
		Host: host, Identity: id, MACKeys: macKeys, Environments: envs, ExportDir: exportDir, MinClient: minClient,
		Version: buildinfo.Version, Commit: buildinfo.Commit, ImageDigest: os.Getenv("HLP_IMAGE_DIGEST"),
	}, nil
}

// listenerExit is how one of the three listeners ended; name is public, metrics or admin.
type listenerExit struct {
	name string
	err  error
}

// serve runs the public, metrics and admin listeners and the maintenance loop until ctx ends or a listener
// fails, then shuts everything down.
func serve(ctx context.Context, r *relay.Relay, tlsCfg *tls.Config) error {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", env("HLP_LISTEN", ":8443"))
	if err != nil {
		return err
	}
	cl := limits.NewConnLimiter(ln, limits.DefaultConnTotal, limits.DefaultConnPerAddr, limits.DefaultConnPerWide)
	cl.Rejected = func() { r.Metrics.Inc("hlp_connections_rejected_total") }
	srv := &http.Server{
		Handler:           r.Handler(),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(r.ErrLog, "", 0),
		HTTP2:             &http.HTTP2Config{MaxConcurrentStreams: maxStreams},
	}
	metricsSrv := &http.Server{Addr: metricsListen(), Handler: r.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second, ErrorLog: log.New(io.Discard, "", 0)}
	adminSrv, adminLn, err := adminSocket(adminSocketPath(), r)
	if err != nil {
		return err
	}
	var exitErr error // non-nil when a listener failed, so the process exits with an error code
	errc := make(chan listenerExit, 3)
	go func() { errc <- listenerExit{"public", srv.ServeTLS(cl, "", "")} }()
	go func() { errc <- listenerExit{"metrics", metricsSrv.ListenAndServe()} }()
	go func() { errc <- listenerExit{"admin", adminSrv.Serve(adminLn)} }()
	go r.Run(ctx)
	logx.Event("relay.start", logx.Str(logx.KVersion, buildinfo.Version))
	select {
	case <-ctx.Done():
	case e := <-errc:
		if !errors.Is(e.err, http.ErrServerClosed) {
			logx.Event("relay.listener_failed", logx.Str(logx.KState, e.name))
			exitErr = fmt.Errorf("%s listener stopped: %w", e.name, e.err)
		}
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(sctx)
	r.Close()
	_ = metricsSrv.Close()
	_ = adminSrv.Close()
	logx.Event("relay.stop")
	return exitErr
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

var hostRE = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// checkPublicHost refuses a host name that would silently break every signature: it is part of every
// signed text, so it must be the bare lower-case DNS name clients use, without port or trailing dot.
func checkPublicHost(h string) error {
	if !hostRE.MatchString(h) {
		return fmt.Errorf("HLP_PUBLIC_HOST %q must be a lower-case DNS name without port, for example push.example.org", h)
	}
	return nil
}
