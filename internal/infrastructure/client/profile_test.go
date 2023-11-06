package client

import (
	"context"
	"github.com/3110Y/profile/pkg/profileGRPC"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestProfileServiceClient_Login(t *testing.T) {
	id := "123"
	email := "test@test.test"
	phone := uint64(79062579331)
	password := "password"
	ctx := context.Background()
	ctrl := gomock.NewController(t)
	//defer ctrl.Finish()
	clientInterface := NewMockProfileServiceClientInterface(ctrl)
	client := ProfileServiceClient{
		URI:                  "",
		ProfileServiceClient: clientInterface,
	}
	clientInterface.EXPECT().GetByEmailOrPhone(ctx, gomock.Any()).Return(&profileGRPC.ProfileWithoutPassword{
		Id: id,
	}, nil)
	idFill, err := client.Login(ctx, email, phone, password)
	assert.Nil(t, err)
	assert.Equal(t, id, *idFill)
}
