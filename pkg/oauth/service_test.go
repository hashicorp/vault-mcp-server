// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"errors"
	"testing"
	"time"
)

type payload struct {
	A string `json:"a"`
}

func newTestService(t *testing.T, now Clock) *Service {
	t.Helper()
	sealer, err := NewSealer(testKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return NewService(sealer, now)
}

func TestService_MintParse(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	svc := newTestService(t, func() time.Time { return fixed })

	tok, _, err := svc.Mint("t1", 10*time.Second, payload{A: "x"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var out payload
	if _, err := svc.Parse("t1", tok, &out); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if out.A != "x" {
		t.Fatalf("data mismatch: got %q", out.A)
	}
}

func TestService_TypeMismatch(t *testing.T) {
	svc := newTestService(t, time.Now)

	tok, _, err := svc.Mint("t1", 10*time.Second, payload{A: "x"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	var out payload
	if _, err := svc.Parse("t2", tok, &out); !errors.Is(err, ErrTokenTypeMismatch) {
		t.Fatalf("expected ErrTokenTypeMismatch, got %v", err)
	}
}

func TestService_Expired(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := start
	svc := newTestService(t, func() time.Time { return now })

	tok, _, err := svc.Mint("t1", 1*time.Second, payload{A: "x"})
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	now = start.Add(2 * time.Second)
	var out payload
	if _, err := svc.Parse("t1", tok, &out); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}
