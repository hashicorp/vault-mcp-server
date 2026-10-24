package auth

import (
	"fmt"
)

func NewAcquirer(idp string) (TokenAcquirer, error) {
	switch idp {
	case "", "ibm-verify":
		return &IBMVerifyAcquirer{}, nil
	default:
		return nil, fmt.Errorf("auth: unsupported IdP %q", idp)
	}
}
