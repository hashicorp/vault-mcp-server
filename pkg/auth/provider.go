package auth

import "context"

type IdentityProvider interface {
	AuthenticateSubject(ctx context.Context) (*Token, error)
	AuthenticateActor(ctx context.Context) (*Token, error)
}
