// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package oauth

import "testing"

func TestVerifyCodeChallengeS256(t *testing.T) {
	// Well-known PKCE test vector from RFC 7636 Appendix B.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if !VerifyCodeChallengeS256(verifier, challenge) {
		t.Fatalf("expected verifier to match challenge")
	}
	if VerifyCodeChallengeS256(verifier, "wrong-challenge") {
		t.Fatalf("expected mismatch for wrong challenge")
	}
}
