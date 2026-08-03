// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// CodeChallengeS256 computes the PKCE S256 challenge for a verifier.
func CodeChallengeS256(codeVerifier string) string {
	sum := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// VerifyCodeChallengeS256 reports whether codeVerifier matches expectedChallenge
// under the PKCE S256 method.
func VerifyCodeChallengeS256(codeVerifier string, expectedChallenge string) bool {
	got := CodeChallengeS256(codeVerifier)
	return strings.EqualFold(got, expectedChallenge)
}
