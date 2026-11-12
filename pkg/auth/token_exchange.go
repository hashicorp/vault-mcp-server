package auth

import "context"

type TokenExchanger interface {
	Exchange(ctx context.Context) (*DelegationJWT, error)
}
