package auth

import (
	"context"
	"fmt"
)

type IBMVerifyProvider struct {
	PKCEConfig PKCEConfig
	Config     AuthConfig
}

var _ IdentityProvider = (*IBMVerifyProvider)(nil)
var _ InteractiveIdentityProvider = (*IBMVerifyProvider)(nil)

func (p *IBMVerifyProvider) StartSubjectLogin(ctx context.Context) (string, <-chan SubjectLoginResult, error) {
	return startPKCETokenFlow(ctx, p.PKCEConfig, "Subject")
}

func (p *IBMVerifyProvider) AuthenticateSubject(ctx context.Context) (Token, error) {
	subjectToken, err := runSinglePKCETokenFlow(ctx, p.PKCEConfig, "Subject")
	if err != nil {
		return Token{}, fmt.Errorf("IBM Verify subject login: %w", err)
	}
	return *subjectToken, nil
}

func (p *IBMVerifyProvider) AuthenticateActor(ctx context.Context) (Token, error) {
	token, err := PasswordGrant(ctx, p.Config)
	if err != nil {
		return Token{}, err
	}
	return *token, nil
}
