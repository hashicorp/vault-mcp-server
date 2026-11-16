// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
)

func TestSessionConfigFromEnv(t *testing.T) {
	logger := log.New()
	logger.SetLevel(log.PanicLevel)

	cases := []struct {
		name, idle, life string
		wantIdle         time.Duration
		wantLife         time.Duration
	}{
		{"defaults", "", "", 30 * time.Minute, 7 * 24 * time.Hour},
		{"custom", "2m", "48h", 2 * time.Minute, 48 * time.Hour},
		{"invalid falls back", "later", "a week", 30 * time.Minute, 7 * 24 * time.Hour},
		{"zero and negative fall back", "-1m", "0", 30 * time.Minute, 7 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("VAULT_MCP_SESSION_IDLE_TIMEOUT", tc.idle)
			t.Setenv("VAULT_MCP_SESSION_MAX_LIFETIME", tc.life)
			cfg := sessionConfigFromEnv(logger)
			require.Equal(t, tc.wantIdle, cfg.IdleTimeout)
			require.Equal(t, tc.wantLife, cfg.MaxLifetime)
		})
	}
}
