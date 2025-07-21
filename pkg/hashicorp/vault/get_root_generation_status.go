package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// RootGenerationStatus represents root token generation status information
type RootGenerationStatus struct {
	Started            bool   `json:"started"`
	Nonce              string `json:"nonce,omitempty"`
	Progress           int    `json:"progress"`
	Required           int    `json:"required"`
	EncodedToken       string `json:"encoded_token,omitempty"`
	PGPFingerprint     string `json:"pgp_fingerprint,omitempty"`
	OTPLength          int    `json:"otp_length,omitempty"`
	Complete           bool   `json:"complete"`
	GenerationInEffect bool   `json:"generation_in_effect"`

	// Metadata
	Timestamp string                 `json:"timestamp"`
	Source    string                 `json:"source"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// getRootGenerationStatus retrieves the root token generation status from Vault
func getRootGenerationStatus(client *api.Client, ctx context.Context) (*RootGenerationStatus, error) {
	// Get root generation status
	secret, err := client.Logical().Read("sys/generate-root/attempt")
	if err != nil {
		return nil, fmt.Errorf("failed to read root generation status: %w", err)
	}

	status := &RootGenerationStatus{
		Timestamp: getCurrentTimestamp(),
		Source:    "vault_api",
		Metadata:  make(map[string]interface{}),
	}

	if secret != nil && secret.Data != nil {
		// Parse root generation status
		if v, ok := secret.Data["started"].(bool); ok {
			status.Started = v
		}
		if v, ok := secret.Data["nonce"].(string); ok {
			status.Nonce = v
		}
		if v, ok := secret.Data["progress"].(int); ok {
			status.Progress = v
		}
		if v, ok := secret.Data["required"].(int); ok {
			status.Required = v
		}
		if v, ok := secret.Data["encoded_token"].(string); ok {
			status.EncodedToken = v
		}
		if v, ok := secret.Data["pgp_fingerprint"].(string); ok {
			status.PGPFingerprint = v
		}
		if v, ok := secret.Data["otp_length"].(int); ok {
			status.OTPLength = v
		}
		if v, ok := secret.Data["complete"].(bool); ok {
			status.Complete = v
		}

		// Determine if generation is actively in effect
		status.GenerationInEffect = status.Started && !status.Complete

		// Add metadata
		status.Metadata["progress_percentage"] = float64(status.Progress) / float64(status.Required) * 100
		if status.Required > 0 {
			status.Metadata["keys_remaining"] = status.Required - status.Progress
		}
	} else {
		// No active root generation
		status.Started = false
		status.Complete = true
		status.GenerationInEffect = false
	}

	return status, nil
}
