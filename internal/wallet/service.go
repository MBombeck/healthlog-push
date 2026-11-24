// Package wallet is the process without network access that holds the Apple Wallet pass certificate key.
// It signs the manifest of a HealthLog pass (a list of file hashes, never a file) after checking it against
// the closed file set and the pinned brand images, and it sends pass update pushes to Apple through a byte
// tunnel of the relay, with TLS ending at Apple. Nothing else uses the key.
package wallet

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/MBombeck/healthlog-push/internal/wire"
)

// Pusher sends pass update pushes; *Notifier implements it.
type Pusher interface {
	Push(ctx context.Context, tokens [][]byte) []string
}

// Service answers the requests of the relay.
type Service struct {
	ID     *Identity
	Pins   Pins
	Pusher Pusher // nil: notify answers unavailable
	Now    func() time.Time

	keyUses atomic.Int64
}

// NewService checks the pins and returns a service. The identity has been checked by LoadIdentity.
func NewService(id *Identity, pins Pins, p Pusher) (*Service, error) {
	if id == nil {
		return nil, errors.New("wallet: no identity")
	}
	if err := pins.Validate(); err != nil {
		return nil, err
	}
	return &Service{ID: id, Pins: pins, Pusher: p, Now: time.Now}, nil
}

// KeyUses counts the signatures made with the pass key, for tests that prove a refusal never reached it.
func (s *Service) KeyUses() int64 { return s.keyUses.Load() }

// Info describes the identity at the current time.
func (s *Service) Info() wire.WalletInfo {
	now := s.Now()
	return wire.WalletInfo{PassTypeIdentifier: s.ID.PassTypeID, TeamIdentifier: s.ID.TeamID, SignerSubjectO: s.ID.SubjectO,
		CertNotAfterDay: s.ID.NotAfterDay(), CertDaysLeft: s.ID.DaysLeft(now), Usable: s.ID.Usable(now)}
}

// Sign checks the manifest and signs it. The key is touched only after every check passed.
func (s *Service) Sign(manifest []byte) ([]byte, error) {
	if _, err := ParseManifest(manifest, s.Pins); err != nil {
		return nil, err
	}
	now := s.Now()
	if !s.ID.Usable(now) {
		return nil, errUnusable
	}
	s.keyUses.Add(1)
	return SignedData(manifest, s.ID.Key, s.ID.Cert, s.ID.Intermediate, now)
}

var errUnusable = errors.New("wallet: pass certificate expires within seven days")

// Handle answers one request. Every answer carries the current Info.
func (s *Service) Handle(ctx context.Context, req *wire.WalletRequest) *wire.WalletReply {
	rep := &wire.WalletReply{Info: s.Info()}
	if !req.ValidOp() {
		rep.Error = wire.WalletErrBadRequest
		return rep
	}
	switch req.Op {
	case wire.WalletOpSign:
		sig, err := s.Sign(req.Manifest)
		switch reason := ManifestReason(err); {
		case reason != "":
			rep.Error, rep.Reason = wire.WalletErrManifest, reason
		case err != nil:
			rep.Error = wire.WalletErrUnavailable
		default:
			rep.Signature = sig
		}
	case wire.WalletOpNotify:
		if s.Pusher == nil || !rep.Info.Usable {
			rep.Error = wire.WalletErrUnavailable
			return rep
		}
		rep.Results = s.Pusher.Push(ctx, req.Tokens)
	}
	return rep
}
