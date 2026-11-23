package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/MBombeck/healthlog-push/internal/signer"
)

// ticks returns a channel that always has a tick ready, so the loop runs without waiting.
func ticks() <-chan time.Time {
	c := make(chan time.Time)
	go func() {
		for {
			c <- time.Time{}
		}
	}()
	return c
}

// TestSignerExitsOnPersistentWriteFailure: a token directory that cannot be written (here: missing) makes
// every step fail; the loop ends with an error after maxFailures steps instead of logging forever.
func TestSignerExitsOnPersistentWriteFailure(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s := &signer.Signer{Key: key, KeyID: "K", TeamID: "T", Dir: filepath.Join(t.TempDir(), "missing"), Now: time.Now}
	steps := 0
	step := func() (bool, error) { steps++; return s.Step() }
	done := make(chan error, 1)
	go func() { done <- signerLoop(context.Background(), step, ticks(), signerMaxFailures) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("loop ended without an error")
		}
		if steps != signerMaxFailures {
			t.Fatalf("ended after %d steps, want %d", steps, signerMaxFailures)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("signer loop kept running on a persistent write failure")
	}
}

// TestSignerFailureCountResets: failures that are interrupted by a success do not end the signer.
func TestSignerFailureCountResets(t *testing.T) {
	n := 0
	ctx, cancel := context.WithCancel(context.Background())
	step := func() (bool, error) {
		n++
		if n == 4*signerMaxFailures {
			cancel()
		}
		if n%signerMaxFailures == 0 {
			return true, nil
		}
		return false, errors.New("write failed")
	}
	if err := signerLoop(ctx, step, ticks(), signerMaxFailures); err != nil {
		t.Fatalf("loop ended with %v although every run of failures was shorter than the limit", err)
	}
}
