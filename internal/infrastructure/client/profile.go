package client

//go:generate mockgen -destination mock_profile_test.go -package client . ProfileServiceClientInterface

import (
	"context"
	utlits "github.com/3110Y/cc-utlits"
	"github.com/3110Y/profile/pkg/profileGRPC"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"os"
)

type ProfileServiceClientInterface interface {
	GetByEmailOrPhone(ctx context.Context, in *profileGRPC.ProfileEmailPhonePassword, opts ...grpc.CallOption) (*profileGRPC.ProfileWithoutPassword, error)
}

type ProfileServiceClient struct {
	URI                  string
	ProfileServiceClient ProfileServiceClientInterface
}

func NewProfileServiceClient() (*ProfileServiceClient, error) {
	conn, err := grpc.Dial(os.Getenv("URL_PROFILE"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	client := profileGRPC.NewProfileServiceClient(conn)
	return &ProfileServiceClient{
			URI:                  os.Getenv("URL_PROFILE"),
			ProfileServiceClient: client,
		},
		nil
}

func (c *ProfileServiceClient) Login(
	ctx context.Context,
	email string,
	phone uint64,
	password string) (*string, error) {
	profileWithoutPassword, err := c.ProfileServiceClient.GetByEmailOrPhone(ctx, &profileGRPC.ProfileEmailPhonePassword{
		Email:    email,
		Phone:    phone,
		Password: password,
	})
	if err != nil {
		return nil, err
	}
	return utlits.Pointer(profileWithoutPassword.Id), err
}
