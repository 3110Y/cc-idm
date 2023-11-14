package claims

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"time"
)

type Claims struct {
	Type      string `json:"typ,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
}

func (c *Claims) verifyExp() bool {
	if c.ExpiresAt == 0 {
		return true
	}
	return time.Now().Unix() <= c.ExpiresAt
}

func (c *Claims) Valid() error {
	vErr := new(jwt.ValidationError)

	if !c.verifyExp() {
		vErr.Inner = errors.New("token is expired")
		vErr.Errors |= jwt.ValidationErrorExpired
	}

	return vErr
}
