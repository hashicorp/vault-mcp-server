// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrTokenExpired is returned when a token's exp is in the past.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenTypeMismatch is returned when a token is parsed as the wrong type.
	ErrTokenTypeMismatch = errors.New("token type mismatch")
	// ErrTokenInvalid is returned when a token cannot be opened or decoded.
	ErrTokenInvalid = errors.New("token invalid")
)

// Clock returns the current time; injectable for tests.
type Clock func() time.Time

// Service mints and parses typed, expiring, sealed tokens on top of a Sealer.
type Service struct {
	sealer *Sealer
	now    Clock
}

// NewService creates a token Service. If now is nil, time.Now is used.
func NewService(sealer *Sealer, now Clock) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{sealer: sealer, now: now}
}

// Envelope is the JSON structure sealed into every token.
type Envelope struct {
	Typ  string          `json:"typ"`
	Iat  int64           `json:"iat"`
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"data"`
}

// Meta describes a token's issuance and expiry.
type Meta struct {
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Mint seals data into a typed token valid for ttl.
func (s *Service) Mint(typ string, ttl time.Duration, data any) (string, Meta, error) {
	now := s.now().UTC()
	exp := now.Add(ttl)

	payload, err := json.Marshal(data)
	if err != nil {
		return "", Meta{}, fmt.Errorf("marshal token payload: %w", err)
	}

	env := Envelope{
		Typ:  typ,
		Iat:  now.Unix(),
		Exp:  exp.Unix(),
		Data: payload,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return "", Meta{}, fmt.Errorf("marshal token envelope: %w", err)
	}
	tok, err := s.sealer.Seal(b)
	if err != nil {
		return "", Meta{}, fmt.Errorf("seal token: %w", err)
	}
	return tok, Meta{IssuedAt: now, ExpiresAt: exp}, nil
}

// ParseEnvelope opens a token and validates its expiry, returning the raw envelope.
func (s *Service) ParseEnvelope(token string) (Envelope, Meta, error) {
	b, err := s.sealer.Open(token)
	if err != nil {
		return Envelope{}, Meta{}, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}

	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return Envelope{}, Meta{}, fmt.Errorf("%w: unmarshal", ErrTokenInvalid)
	}

	now := s.now().UTC().Unix()
	if now >= env.Exp {
		return Envelope{}, Meta{}, ErrTokenExpired
	}

	meta := Meta{
		IssuedAt:  time.Unix(env.Iat, 0).UTC(),
		ExpiresAt: time.Unix(env.Exp, 0).UTC(),
	}
	return env, meta, nil
}

// Parse opens a token, checks its type against expectedType, and unmarshals its
// payload into out (which may be nil to only validate).
func (s *Service) Parse(expectedType string, token string, out any) (Meta, error) {
	env, meta, err := s.ParseEnvelope(token)
	if err != nil {
		return Meta{}, err
	}

	if env.Typ != expectedType {
		return Meta{}, fmt.Errorf("%w: got %q want %q", ErrTokenTypeMismatch, env.Typ, expectedType)
	}

	if out == nil {
		return meta, nil
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return Meta{}, fmt.Errorf("%w: unmarshal payload", ErrTokenInvalid)
	}
	return meta, nil
}
