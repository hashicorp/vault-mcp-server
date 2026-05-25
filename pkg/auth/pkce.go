// Copyright IBM Corp. 2025
// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const (
	// PKCECodeVerifierLength is the length of the PKCE code verifier
	// RFC 7636 recommends 43-128 characters
	PKCECodeVerifierLength = 64

	// StateLength is the length of the OAuth state parameter for CSRF protection
	StateLength = 32
)

// PKCEChallenge contains the PKCE code challenge and verifier
type PKCEChallenge struct {
	CodeVerifier  string
	CodeChallenge string
	Method        string // S256 for SHA-256
}

// GeneratePKCEChallenge generates a PKCE code verifier and challenge
// Uses SHA-256 as the challenge method (S256) per RFC 7636
func GeneratePKCEChallenge() (*PKCEChallenge, error) {
	// Generate random code verifier
	codeVerifier, err := generateRandomString(PKCECodeVerifierLength)
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	// Create SHA-256 hash of code verifier
	hash := sha256.Sum256([]byte(codeVerifier))

	// Base64-URL encode the hash (without padding per RFC 7636)
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	return &PKCEChallenge{
		CodeVerifier:  codeVerifier,
		CodeChallenge: codeChallenge,
		Method:        "S256",
	}, nil
}

// GenerateState generates a random state parameter for CSRF protection
func GenerateState() (string, error) {
	state, err := generateRandomString(StateLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return state, nil
}

// generateRandomString generates a cryptographically secure random string
// suitable for OAuth parameters (URL-safe base64 encoding)
func generateRandomString(length int) (string, error) {
	// Calculate byte length needed for desired string length
	// Base64 encoding produces 4 characters for every 3 bytes
	byteLength := (length * 3) / 4
	if byteLength < 1 {
		byteLength = 1
	}

	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Base64-URL encode without padding
	encoded := base64.RawURLEncoding.EncodeToString(bytes)

	// Trim to exact length requested
	if len(encoded) > length {
		encoded = encoded[:length]
	}

	return encoded, nil
}
