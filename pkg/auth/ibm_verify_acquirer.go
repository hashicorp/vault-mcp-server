package auth

import (
	"context"
	"fmt"
	"os"
)

type IBMVerifyAcquirer struct {
	Provider *IBMVerifyProvider
}

var _ TokenAcquirer = (*IBMVerifyAcquirer)(nil)

func (a *IBMVerifyAcquirer) AcquireTokens(ctx context.Context, cfg AuthConfig) (*DelegationJWT, error) {
	pkceCfg := cfg.SubjectPKCEConfig()

	provider := &IBMVerifyProvider{
		PKCEConfig: pkceCfg,
		Config:     cfg,
	}

	subject, err := provider.AuthenticateSubject(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: subject login failed: %w", err)
	}

	actor, err := provider.AuthenticateActor(ctx)
	if err != nil {
		return nil, err
	}

	jwt, err := ExchangeTokens(
		subject.AccessToken,
		actor.AccessToken,
		cfg.STSEndpoint,
		cfg.STSClientID,
		cfg.STSClientSecret,
		cfg.STSAuthorizationDetails)
	if err != nil {
		return nil, err
	}

	fmt.Fprintf(os.Stderr, "[vault-mcp-server] Delegation JWT (sub=%s act.sub=%s): %s\n", jwt.Sub, jwt.Act.Sub, jwt.Raw)

	return jwt, nil
}
