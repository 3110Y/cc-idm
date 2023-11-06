package service

//go:generate mockgen -destination mock_JWTService_test.go -package service . ProfileServiceClientInterface

import (
	"context"
	"errors"
	"fmt"
	"github.com/3110Y/cc-idm/internal/application/claims"
	"github.com/3110Y/cc-idm/internal/application/config"
	"github.com/3110Y/cc-idm/internal/application/dto"
	"github.com/golang-jwt/jwt"
	"time"
)

const ACCESS = "Access"
const REFRESH = "Refresh"

type ProfileServiceClientInterface interface {
	Login(ctx context.Context, email string, phone uint64, password string) (*string, error)
}

type JWTService struct {
	ProfileServiceClient ProfileServiceClientInterface
	SigningMethod        *jwt.SigningMethodHMAC
	TLSKey               *config.TLS
}

func NewJWTService(profileServiceClient ProfileServiceClientInterface, TLSKey *config.TLS) *JWTService {
	return &JWTService{
		ProfileServiceClient: profileServiceClient,
		SigningMethod:        jwt.SigningMethodHS256,
		TLSKey:               TLSKey,
	}
}

func (g *JWTService) keyFunc(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
		return nil, fmt.Errorf("неправильный метод подписи")
	}

	return g.TLSKey.Key.Public(), nil
}

func (g *JWTService) getAccess(id string) (*string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		&claims.Claims{
			Type:      ACCESS,
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			Id:        id,
		})
	access, err := token.SignedString(g.TLSKey.Key)
	if err != nil {
		return nil, err
	}
	return &access, nil
}

func (g *JWTService) getRefresh(id string) (*string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		&claims.Claims{
			Type:      REFRESH,
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			Id:        id,
		})
	refresh, err := token.SignedString(g.TLSKey.Key)
	if err != nil {
		return nil, err
	}
	return &refresh, nil
}

func (g *JWTService) getJWT(id string) (*dto.JWTDTO, error) {
	access, err := g.getAccess(id)
	if err != nil {
		return nil, err
	}
	refresh, err := g.getRefresh(id)
	if err != nil {
		return nil, err
	}
	JWT := dto.JWTDTO{
		Access:  *access,
		Refresh: *refresh,
	}
	return &JWT, err
}

func (g *JWTService) parse(token string) (*claims.Claims, error) {
	a := &claims.Claims{}
	_, err := jwt.ParseWithClaims(token, a, g.keyFunc)
	return a, err
}

func (g *JWTService) FromLoginAndPassword(
	ctx context.Context,
	email string,
	phone uint64,
	password string,
) (*dto.JWTDTO, error) {
	id, err := g.ProfileServiceClient.Login(ctx, email, phone, password)
	if err != nil {
		return nil, err
	}
	return g.getJWT(*id)
}

func (g *JWTService) FromRefresh(refresh string) (*dto.JWTDTO, error) {
	claimsJWT, err := g.parse(refresh)
	if err != nil {
		return nil, err
	}
	if claimsJWT.Type != REFRESH {
		return nil, errors.New("token is not refresh")
	}
	return g.getJWT(claimsJWT.Id)
}

func (g *JWTService) IsValidAccess(token string) error {
	a := &claims.Claims{}
	withClaims, err := jwt.ParseWithClaims(token, a, g.keyFunc)
	if err != nil {
		return err
	}
	if !withClaims.Valid {
		return errors.New("token is invalid")
	}
	if a.Type != ACCESS {
		return errors.New("token is not access")
	}
	return nil
}

func (g *JWTService) IsValidRefresh(token string) error {
	a := &claims.Claims{}
	withClaims, err := jwt.ParseWithClaims(token, a, g.keyFunc)
	if err != nil {
		return err
	}
	if !withClaims.Valid {
		return errors.New("token is invalid")
	}
	if a.Type != REFRESH {
		return errors.New("token is not refresh")
	}
	return nil
}
