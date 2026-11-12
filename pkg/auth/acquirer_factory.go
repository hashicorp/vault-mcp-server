package auth

import (
	"fmt"
	"strings"
)

func NewAcquirer(cfg AuthConfig) (TokenAcquirer, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.IdP)) {
	case "", "ibm-verify":
		return &IBMVerifyAcquirer{
			Config: cfg,
			Provider: &IBMVerifyProvider{
				Config:     cfg,
				PKCEConfig: cfg.SubjectPKCEConfig(),
			},
		}, nil
	default:
		return nil, fmt.Errorf("auth: unsupported IdP %q", cfg.IdP)
	}
}
