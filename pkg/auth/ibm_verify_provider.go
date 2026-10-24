package auth

import (
	"context"
	"fmt"
)

type IBMVerifyProvider struct {
	PKCEConfig PKCEConfig
	Config     AuthConfig
}

func (p *IBMVerifyProvider) AuthenticateSubject(ctx context.Context) (*Token, error) {
	subjectToken, err := runSinglePKCEFlow(ctx, p.PKCEConfig, "Subject")
	if err != nil {
		return nil, fmt.Errorf("IBM Verify subject login: %w", err)
	}
	return &Token{AccessToken: subjectToken}, nil
}

func (p *IBMVerifyProvider) AuthenticateActor(ctx context.Context) (*Token, error) {
	return PasswordGrant(ctx, p.Config)
}
