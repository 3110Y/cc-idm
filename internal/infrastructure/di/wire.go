//go:build wireinject
// +build wireinject

package di

//go:generate wire

import (
	"github.com/3110Y/cc-idm/internal/application/config"
	"github.com/3110Y/cc-idm/internal/application/service"
	"github.com/3110Y/cc-idm/internal/infrastructure/client"
	"github.com/3110Y/cc-idm/internal/presentation/rpc"
	"github.com/google/wire"
)

type DI struct {
	IdmRPC               *rpc.IdmRPC
	ProfileServiceClient *client.ProfileServiceClient
	TLS                  *config.TLS
	JWTService           *service.JWTService
}

func NewDI(
	idmRPC *rpc.IdmRPC,
	profileServiceClient *client.ProfileServiceClient,
	TLS *config.TLS,
	JWTService *service.JWTService,
) *DI {
	return &DI{IdmRPC: idmRPC, ProfileServiceClient: profileServiceClient, TLS: TLS, JWTService: JWTService}
}

func InitializeDI() (*DI, error) {
	wire.Build(
		NewDI,
		wire.Bind(new(service.ProfileServiceClientInterface), new(*client.ProfileServiceClient)),
		wire.Bind(new(rpc.JWTServiceInterface), new(*service.JWTService)),
		rpc.NewIdmRPC,
		client.NewProfileServiceClient,
		config.NewTLS,
		service.NewJWTService,
	)
	return &DI{}, nil
}
