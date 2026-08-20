// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

// Package auth provides authentication helpers for the MCP Agentic Auth pipeline,
// including lightweight (unsigned) parsing of Delegation JWTs issued by an STS
// following RFC 8693 and RFC 9396 (RAR).
package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrTokenExpired is returned by ParseUnsigned when the JWT's exp claim is in the past.
var ErrTokenExpired = errors.New("delegation JWT has expired")

// ActorClaim represents the act claim from RFC 8693 §4.1.
// It identifies the actor (the MCP Server) on whose behalf the delegation was issued.
type ActorClaim struct {
	Sub string `json:"sub"`
}

// DelegationJWT holds the parsed, unsigned payload of a Delegation JWT issued by
// an STS following RFC 8693. Signature verification is intentionally omitted —
// Vault, configured as an OAuth Resource Server, is the authoritative enforcement point.
type DelegationJWT struct {
	// Sub is the human user's identity (subject claim).
	Sub string
	// Act is the actor (MCP Server) identity per RFC 8693.
	Act ActorClaim
	// Exp is the expiry time extracted from the exp claim.
	Exp time.Time
	// AuthorizationDetails holds the raw RAR authorization_details array (RFC 9396).
	// Each element is a raw JSON object; callers decode individual entries as needed.
	AuthorizationDetails []json.RawMessage
	// Raw is the original JWT string, suitable for use as a Vault token.
	Raw string
}

// jwtPayload is the internal struct used only during JSON unmarshalling of the JWT payload.
type jwtPayload struct {
	Sub                  string             `json:"sub"`
	Act                  ActorClaim         `json:"act"`
	Exp                  int64              `json:"exp"`
	AuthorizationDetails []json.RawMessage  `json:"authorization_details"`
}

// ParseUnsigned decodes and parses the payload of a JWT without verifying its signature.
// It extracts exp, sub, act, and authorization_details, checks that the token has not
// expired, and returns a populated DelegationJWT.
//
// Errors:
//   - ErrTokenExpired if exp is in the past.
//   - A descriptive error for malformed input (wrong segment count, bad base64, bad JSON).
func ParseUnsigned(token string) (*DelegationJWT, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("auth: malformed JWT: expected 3 segments, got %d", len(parts))
	}

	// Base64url-decode the payload (index 1). Use RawURLEncoding — JWTs omit padding.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("auth: failed to decode JWT payload: %w", err)
	}

	var p jwtPayload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		return nil, fmt.Errorf("auth: failed to parse JWT payload JSON: %w", err)
	}

	exp := time.Unix(p.Exp, 0)
	// Only check expiry when exp is explicitly set (non-zero). A zero value
	// would produce epoch time (1970) and always appear expired.
	if p.Exp > 0 && time.Now().After(exp) {
		return nil, ErrTokenExpired
	}

	return &DelegationJWT{
		Sub:                  p.Sub,
		Act:                  p.Act,
		Exp:                  exp,
		AuthorizationDetails: p.AuthorizationDetails,
		Raw:                  token,
	}, nil
}
