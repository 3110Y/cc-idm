package service

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/3110Y/cc-idm/internal/application/claims"
	"github.com/3110Y/cc-idm/internal/application/config"
	utlits "github.com/3110Y/cc-utlits"
	"github.com/golang-jwt/jwt"
	"github.com/golang/mock/gomock"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
	"time"
)

var ctx context.Context

func init() {
	ctx = context.Background()
	err := godotenv.Load("../../../.env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func prepare(t *testing.T) (
	func(),
	*JWTService,
	*MockProfileServiceClientInterface,
) {
	err := godotenv.Load("../../../.env")
	assert.Nil(t, err)
	ctrl := gomock.NewController(t)
	profileServiceClient := NewMockProfileServiceClientInterface(ctrl)
	key, err := generationKey()
	assert.Nil(t, err)

	tls := &config.TLS{Key: key}
	profileJWTService := NewJWTService(
		profileServiceClient,
		tls,
	)
	return ctrl.Finish, profileJWTService, profileServiceClient
}

func generationKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Key generation error: %s", err))
	}
	return privateKey, err
}

func TestJWTService_getAccess(t *testing.T) {
	id := "123"
	finish, service, _ := prepare(t)
	defer finish()
	access, err := service.getAccess(id)
	assert.Nil(t, err)
	assert.Len(t, *access, 164)
	a := claims.Claims{}
	token, err := jwt.ParseWithClaims(*access, &a, service.keyFunc)
	assert.Nil(t, err)
	assert.Equal(t, id, a.Id)
	assert.True(t, token.Valid)
}

func TestJWTService_getRefresh(t *testing.T) {
	id := "123"
	finish, service, _ := prepare(t)
	defer finish()
	access, err := service.getRefresh(id)
	assert.Nil(t, err)
	assert.Len(t, *access, 164)
	a := claims.Claims{}
	token, err := jwt.ParseWithClaims(*access, &a, service.keyFunc)
	assert.Nil(t, err)
	assert.Equal(t, id, a.Id)
	assert.True(t, token.Valid)
}

func TestJWTService_getJWT(t *testing.T) {
	id := "123"
	finish, service, _ := prepare(t)
	defer finish()
	jwtStruct, err := service.getJWT(id)
	assert.Nil(t, err)
	assert.Len(t, jwtStruct.Refresh, 164)
	assert.Len(t, jwtStruct.Access, 164)
}

func TestJWTService_FromLoginAndPassword(t *testing.T) {
	t.Parallel()
	const email = "test@test.test"
	const phone uint64 = 79062579331
	const password = "password"
	finish, service, client := prepare(t)
	defer finish()
	client.EXPECT().Login(ctx, email, phone, password).Return(utlits.Pointer("123"), nil)
	jwtToken, err := service.FromLoginAndPassword(ctx, email, phone, password)
	assert.Nil(t, err)
	assert.Len(t, jwtToken.Access, 164)
	assert.Len(t, jwtToken.Refresh, 164)
}

func TestJWTService_parse(t *testing.T) {
	id := "123"
	finish, service, _ := prepare(t)
	defer finish()
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		&claims.Claims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			Id:        id,
		})
	access, err := token.SignedString(service.TLSKey.Key)
	assert.Nil(t, err)
	claimsJWT, err := service.parse(access)
	assert.Nil(t, err)
	assert.Equal(t, id, claimsJWT.Id)
}

func TestJWTService_FromRefresh(t *testing.T) {
	id := "123"
	finish, service, _ := prepare(t)
	defer finish()
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		&claims.Claims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			Id:        id,
		})
	refresh, err := token.SignedString(service.TLSKey.Key)
	jwtToken, err := service.FromRefresh(refresh)
	assert.Nil(t, err)
	assert.Len(t, jwtToken.Access, 164)
	assert.Len(t, jwtToken.Refresh, 164)
}

func TestJWTService_IsValidAccess(t *testing.T) {
	id := "123"
	finish, service, _ := prepare(t)
	defer finish()
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		&claims.Claims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			Id:        id,
		})
	refresh, err := token.SignedString(service.TLSKey.Key)
	err = service.IsValidAccess(refresh)
	assert.Nil(t, err)
}

func TestJWTService_IsValidRefresh(t *testing.T) {
	id := "123"
	finish, service, _ := prepare(t)
	defer finish()
	token := jwt.NewWithClaims(jwt.SigningMethodES256,
		&claims.Claims{
			ExpiresAt: time.Now().Add(15 * time.Minute).Unix(),
			Id:        id,
		})
	refresh, err := token.SignedString(service.TLSKey.Key)
	err = service.IsValidRefresh(refresh)
	assert.Nil(t, err)
}
