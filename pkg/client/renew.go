// Copyright IBM Corp. 2025, 2026
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
)

// activeRenewers stores context.CancelFunc values keyed by session ID so the
// background renewal goroutine can be stopped when a session ends.
var activeRenewers sync.Map

// StartTokenRenewal begins a background loop that renews the Vault token for
// sessionID before it expires. It is a no-op for non-renewable tokens (batch
// tokens, tokens that have already hit their max TTL, etc.).
func StartTokenRenewal(sessionID string, vc *api.Client, logger *log.Logger) {
	ttl, renewable := lookupTokenTTL(context.Background(), vc)
	if !renewable || ttl <= 0 {
		logger.WithField("session_id", sessionID).Debug("vault token is not renewable — skipping auto-renewal")
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	activeRenewers.Store(sessionID, cancel)

	go func() {
		defer activeRenewers.Delete(sessionID)

		interval := renewalInterval(ttl)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		logger.WithFields(log.Fields{
			"session_id":       sessionID,
			"token_ttl":        ttl,
			"renewal_interval": interval,
		}).Info("vault token auto-renewal started")

		for {
			select {
			case <-ctx.Done():
				logger.WithField("session_id", sessionID).Debug("vault token renewal loop cancelled")
				return
			case <-ticker.C:
				secret, err := vc.Auth().Token().RenewSelfWithContext(ctx, int(ttl.Seconds()))
				if err != nil {
					logger.WithField("session_id", sessionID).WithError(err).Warn(
						"vault token renewal failed — token will expire at its current TTL; " +
							"re-authenticate when the session is rejected")
					return
				}
				if secret == nil || secret.Auth == nil {
					logger.WithField("session_id", sessionID).Warn(
						"vault token renewal returned no auth data — stopping renewal loop")
					return
				}

				newTTL := time.Duration(secret.Auth.LeaseDuration) * time.Second
				if newTTL > 0 {
					ttl = newTTL
				}

				newInterval := renewalInterval(ttl)
				logger.WithFields(log.Fields{
					"session_id":  sessionID,
					"new_ttl_s":   secret.Auth.LeaseDuration,
					"next_renew":  newInterval,
				}).Debug("vault token renewed successfully")

				if newInterval != interval {
					interval = newInterval
					ticker.Reset(interval)
				}
			}
		}
	}()
}

// StopTokenRenewal cancels the background renewal goroutine for sessionID.
// It is safe to call even if no renewal is running.
func StopTokenRenewal(sessionID string) {
	if v, ok := activeRenewers.LoadAndDelete(sessionID); ok {
		v.(context.CancelFunc)()
	}
}

// renewalInterval returns a safe renewal interval for the given remaining TTL.
// It targets half the TTL, clamped to [1 minute, 30 minutes] to avoid both
// too-frequent calls and last-minute renewal attempts.
func renewalInterval(ttl time.Duration) time.Duration {
	d := ttl / 2
	if d < time.Minute {
		d = time.Minute
	}
	if d > 30*time.Minute {
		d = 30 * time.Minute
	}
	return d
}

// lookupTokenTTL queries Vault for the current token's remaining TTL and
// renewability. Returns (0, false) when the lookup fails or the token is not
// renewable (e.g. batch tokens produced by OIDC flows).
func lookupTokenTTL(ctx context.Context, vc *api.Client) (time.Duration, bool) {
	secret, err := vc.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil || secret == nil || secret.Data == nil {
		return 0, false
	}

	renewable, _ := secret.Data["renewable"].(bool)
	if !renewable {
		return 0, false
	}

	ttl := jsonNumToDuration(secret.Data["ttl"])
	return ttl, ttl > 0
}

// jsonNumToDuration converts a Vault API response value (json.Number or float64)
// to a time.Duration in seconds. Vault's Go SDK uses UseNumber() so numeric
// fields in Data are always json.Number.
func jsonNumToDuration(v interface{}) time.Duration {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return time.Duration(i) * time.Second
		}
	case float64:
		return time.Duration(int64(n)) * time.Second
	}
	return 0
}
