package auth

import "context"

type IdentityProvider interface {
	AuthenticateSubject(ctx context.Context) (Token, error)
	AuthenticateActor(ctx context.Context) (Token, error)
}

type SubjectLoginResult struct {
	Token Token
	Err   error
}

type InteractiveIdentityProvider interface {
	StartSubjectLogin(ctx context.Context) (string, <-chan SubjectLoginResult, error)
}
