package rpc

import (
	"github.com/3110Y/cc-idm/internal/application/dto"
	"github.com/3110Y/cc-idm/pkg/idmGRPC"
	"github.com/golang/mock/gomock"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/context"
	"log"
	"testing"
)

var ctx context.Context

func init() {
	var err error
	ctx = context.Background()
	err = godotenv.Load("../../../.env")
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}
}

func prepare(t *testing.T) (
	func(),
	*MockJWTServiceInterface,
	*IdmRPC,
) {
	err := godotenv.Load("../../../.env")
	assert.Nil(t, err)
	ctrl := gomock.NewController(t)
	serviceClient := NewMockJWTServiceInterface(ctrl)
	profileRPC := NewIdmRPC(serviceClient)
	return ctrl.Finish, serviceClient, profileRPC
}

func TestIdmRPC_FromLoginAndPassword(t *testing.T) {
	t.Parallel()
	const access = "Access"
	const refresh = "Refresh"
	const email = "test@test.test"
	const phone uint64 = 79062579331
	const password = "password"
	f, service, rpc := prepare(t)
	defer f()
	service.EXPECT().FromLoginAndPassword(ctx, email, phone, password).Return(&dto.JWTDTO{
		Access:  access,
		Refresh: refresh,
	}, nil)
	jwtToken, err := rpc.FromLoginAndPassword(ctx, &idmGRPC.ProfileEmailPhonePassword{
		Email:    email,
		Phone:    phone,
		Password: password,
	})
	assert.Nil(t, err)
	assert.Equal(t, access, jwtToken.Access)
	assert.Equal(t, refresh, jwtToken.Refresh)
}

func TestIdmRPC_FromRefresh(t *testing.T) {
	t.Parallel()
	const access = "Access"
	const refresh = "Refresh"
	f, service, rpc := prepare(t)
	defer f()
	service.EXPECT().FromRefresh(refresh).Return(&dto.JWTDTO{
		Access:  access,
		Refresh: refresh,
	}, nil)
	jwtToken, err := rpc.FromRefresh(ctx, &idmGRPC.Refresh{
		Refresh: refresh,
	})
	assert.Nil(t, err)
	assert.Equal(t, access, jwtToken.Access)
	assert.Equal(t, refresh, jwtToken.Refresh)
}

func TestIdmRPC_IsValidAccess(t *testing.T) {
	t.Parallel()
	const access = "Access"
	f, service, rpc := prepare(t)
	defer f()
	service.EXPECT().IsValidAccess(access).Return(nil)
	_, err := rpc.IsValidAccess(ctx, &idmGRPC.Access{
		Access: access,
	})
	assert.Nil(t, err)
}

func TestIdmRPC_IsValidRefresh(t *testing.T) {
	t.Parallel()
	const refresh = "Refresh"
	f, service, rpc := prepare(t)
	defer f()
	service.EXPECT().IsValidRefresh(refresh).Return(nil)
	_, err := rpc.IsValidRefresh(ctx, &idmGRPC.Refresh{
		Refresh: refresh,
	})
	assert.Nil(t, err)
}
