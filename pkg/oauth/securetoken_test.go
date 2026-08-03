// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func testKey(t *testing.T) string {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(key)
}

func TestSealer_RoundTrip(t *testing.T) {
	s, err := NewSealer(testKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}

	plaintext := []byte("hello vault")
	tok, err := s.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	got, err := s.Open(tok)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(got) != string(plaintext) {
		t.Fatalf("roundtrip mismatch: got %q want %q", got, plaintext)
	}
}

func TestSealer_WrongKey(t *testing.T) {
	s1, err := NewSealer(testKey(t))
	if err != nil {
		t.Fatalf("NewSealer(1): %v", err)
	}
	s2, err := NewSealer(testKey(t))
	if err != nil {
		t.Fatalf("NewSealer(2): %v", err)
	}

	tok, err := s1.Seal([]byte("secret"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := s2.Open(tok); err == nil {
		t.Fatalf("expected error opening with wrong key")
	}
}

func TestSealer_InvalidToken(t *testing.T) {
	s, err := NewSealer(testKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if _, err := s.Open("not-base64!!"); err == nil {
		t.Fatalf("expected error")
	}
}

func TestValidateKey(t *testing.T) {
	if err := ValidateKey(testKey(t)); err != nil {
		t.Fatalf("ValidateKey valid: %v", err)
	}
	if err := ValidateKey("short"); err == nil {
		t.Fatalf("expected error for short key")
	}
}
