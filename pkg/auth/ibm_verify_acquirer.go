package auth

import (
	"context"
	"fmt"
	"time"
)

type IBMVerifyAcquirer struct {
	Config   AuthConfig
	Provider IdentityProvider
}

var _ TokenAcquirer = (*IBMVerifyAcquirer)(nil)
var _ InteractiveTokenAcquirer = (*IBMVerifyAcquirer)(nil)

func (a *IBMVerifyAcquirer) StartLogin(ctx context.Context) (string, <-chan LoginResult, error) {
	provider, ok := a.Provider.(InteractiveIdentityProvider)
	if !ok {
		return "", nil, fmt.Errorf("auth: provider does not support interactive login")
	}
	url, subjectResults, err := provider.StartSubjectLogin(ctx)
	if err != nil {
		return "", nil, err
	}
	results := make(chan LoginResult, 1)
	go func() {
		defer close(results)
		subject := <-subjectResults
		if subject.Err != nil {
			results <- LoginResult{Err: subject.Err}
			return
		}
		jwt, err := a.completeLogin(ctx, subject.Token)
		results <- LoginResult{JWT: jwt, Err: err}
	}()
	return url, results, nil
}

func (a *IBMVerifyAcquirer) AcquireTokens(ctx context.Context) (*DelegationJWT, error) {
	if a.Provider == nil {
		return nil, fmt.Errorf("auth: identity provider is required")
	}
	subject, err := a.Provider.AuthenticateSubject(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: subject login failed: %w", err)
	}
	return a.completeLogin(ctx, subject)
}

func (a *IBMVerifyAcquirer) completeLogin(ctx context.Context, subject Token) (*DelegationJWT, error) {
	actor, err := a.Provider.AuthenticateActor(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: actor login failed: %w", err)
	}
	if subject.AccessToken == "" || actor.AccessToken == "" {
		return nil, fmt.Errorf("auth: subject and actor access tokens are required")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	var exchanger TokenExchanger = &IBMVerifySTS{
		Config: a.Config, Subject: subject, Actor: actor,
	}
	jwt, err := exchanger.Exchange(ctx)
	if err != nil {
		return nil, fmt.Errorf("auth: STS exchange failed: %w", err)
	}
	if jwt == nil || jwt.Raw == "" || jwt.Sub == "" || jwt.Act.Sub == "" {
		return nil, fmt.Errorf("auth: STS delegation JWT must contain sub and act.sub")
	}
	if !jwt.Exp.After(time.Now()) {
		return nil, ErrTokenExpired
	}
	return jwt, nil
}
