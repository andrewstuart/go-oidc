package oidc

import (
	"errors"
	"time"

	"github.com/coreos/go-oidc/jose"
)

//Identity is an internal abstraction of the OpenID connect standard claims,
//with well-known named fields for easier verification.
type Identity struct {
	ID        string
	Name      string
	Email     string
	ExpiresAt time.Time
	Claims    jose.Claims
}

//IdentityFromClaims returns an Identity from jose JWT Claims
func IdentityFromClaims(claims jose.Claims) (*Identity, error) {
	if claims == nil {
		return nil, errors.New("nil claim set")
	}

	ident := Identity{Claims: claims}
	var err error
	var ok bool

	if ident.ID, ok, err = claims.StringClaim("sub"); err != nil {
		return nil, err
	} else if !ok {
		return nil, errors.New("missing required claim: sub")
	}

	if ident.Email, _, err = claims.StringClaim("email"); err != nil {
		return nil, err
	}

	exp, ok, err := claims.TimeClaim("exp")
	if err != nil {
		return nil, err
	} else if ok {
		ident.ExpiresAt = exp
	}

	return &ident, nil
}
