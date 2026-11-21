package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/MBombeck/healthlog-push/internal/buildinfo"
	"github.com/MBombeck/healthlog-push/internal/logx"
	"github.com/MBombeck/healthlog-push/internal/signer"
)

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
	s := &signer.Signer{Key: key, KeyID: keyID, TeamID: teamID, Dir: jwtDir(),
		RefreshDir: jwtRefreshDir(), Now: time.Now}
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

func healthcheck(isSigner bool) error {
	if isSigner {
		if !signer.Fresh(jwtDir(), 60*time.Minute, time.Now()) {
			return errors.New("no fresh provider token")
		}
		return nil
	}
	c := &http.Client{Timeout: 5 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+metricsListen()+"/healthz", http.NoBody)
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
