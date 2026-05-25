// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"testing"
)

func TestGeneratePKCEChallenge(t *testing.T) {
	pkce, err := GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("Failed to generate PKCE challenge: %v", err)
	}

	if pkce == nil {
		t.Fatal("PKCE challenge is nil")
	}

	if pkce.CodeVerifier == "" {
		t.Error("Code verifier is empty")
	}

	if pkce.CodeChallenge == "" {
		t.Error("Code challenge is empty")
	}

	if pkce.Method != "S256" {
		t.Errorf("Expected method S256, got %s", pkce.Method)
	}

	// Verify code verifier length is reasonable
	if len(pkce.CodeVerifier) < 43 || len(pkce.CodeVerifier) > 128 {
		t.Errorf("Code verifier length %d is outside RFC 7636 recommended range [43-128]", len(pkce.CodeVerifier))
	}

	// Verify code challenge is base64-URL encoded (no padding)
	if len(pkce.CodeChallenge) != 43 { // SHA-256 produces 32 bytes, base64-url encoded without padding = 43 chars
		t.Errorf("Expected code challenge length 43, got %d", len(pkce.CodeChallenge))
	}
}

func TestGeneratePKCEChallengeUniqueness(t *testing.T) {
	pkce1, err := GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("Failed to generate first PKCE challenge: %v", err)
	}

	pkce2, err := GeneratePKCEChallenge()
	if err != nil {
		t.Fatalf("Failed to generate second PKCE challenge: %v", err)
	}

	// Verify that two generated challenges are different
	if pkce1.CodeVerifier == pkce2.CodeVerifier {
		t.Error("Generated code verifiers are not unique")
	}

	if pkce1.CodeChallenge == pkce2.CodeChallenge {
		t.Error("Generated code challenges are not unique")
	}
}

func TestGenerateState(t *testing.T) {
	state, err := GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate state: %v", err)
	}

	if state == "" {
		t.Error("State is empty")
	}

	if len(state) != StateLength {
		t.Errorf("Expected state length %d, got %d", StateLength, len(state))
	}
}

func TestGenerateStateUniqueness(t *testing.T) {
	state1, err := GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate first state: %v", err)
	}

	state2, err := GenerateState()
	if err != nil {
		t.Fatalf("Failed to generate second state: %v", err)
	}

	// Verify that two generated states are different
	if state1 == state2 {
		t.Error("Generated states are not unique")
	}
}

func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"short", 8},
		{"medium", 32},
		{"long", 128},
		{"very long", 256},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str, err := generateRandomString(tt.length)
			if err != nil {
				t.Fatalf("Failed to generate random string: %v", err)
			}

			if len(str) != tt.length {
				t.Errorf("Expected length %d, got %d", tt.length, len(str))
			}

			// Verify string contains only URL-safe base64 characters
			for _, ch := range str {
				if !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_') {
					t.Errorf("String contains non-URL-safe character: %c", ch)
					break
				}
			}
		})
	}
}

func BenchmarkGeneratePKCEChallenge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GeneratePKCEChallenge()
		if err != nil {
			b.Fatalf("Failed to generate PKCE challenge: %v", err)
		}
	}
}

func BenchmarkGenerateState(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GenerateState()
		if err != nil {
			b.Fatalf("Failed to generate state: %v", err)
		}
	}
}
