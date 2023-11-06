package rpc

//go:generate mockgen -destination mock_idmRPC_test.go -package rpc . JWTServiceInterface

import (
	"context"
	"github.com/3110Y/cc-idm/internal/application/dto"
	"github.com/3110Y/cc-idm/pkg/idmGRPC"
)

type JWTServiceInterface interface {
	FromLoginAndPassword(ctx context.Context, email string, phone uint64, password string) (*dto.JWTDTO, error)
	FromRefresh(refresh string) (*dto.JWTDTO, error)
	IsValidAccess(token string) error
	IsValidRefresh(token string) error
}

type IdmRPC struct {
	idmGRPC.UnimplementedIDMServiceServer
	JWTService JWTServiceInterface
}

func NewIdmRPC(JWTService JWTServiceInterface) *IdmRPC {
	return &IdmRPC{JWTService: JWTService}
}

func (c *IdmRPC) FromLoginAndPassword(ctx context.Context, in *idmGRPC.ProfileEmailPhonePassword) (*idmGRPC.AccessAndRefresh, error) {
	JWT, err := c.JWTService.FromLoginAndPassword(ctx, in.Email, in.Phone, in.Password)
	if err != nil {
		return nil, err
	}
	return &idmGRPC.AccessAndRefresh{
		Access:  JWT.Access,
		Refresh: JWT.Refresh,
	}, nil
}

func (c *IdmRPC) FromRefresh(_ context.Context, in *idmGRPC.Refresh) (*idmGRPC.AccessAndRefresh, error) {
	JWT, err := c.JWTService.FromRefresh(in.Refresh)
	if err != nil {
		return nil, err
	}
	return &idmGRPC.AccessAndRefresh{
		Access:  JWT.Access,
		Refresh: JWT.Refresh,
	}, nil
}

func (c *IdmRPC) IsValidAccess(ctx context.Context, in *idmGRPC.Access) (*idmGRPC.EmptyResponse, error) {
	err := c.JWTService.IsValidAccess(in.Access)
	if err != nil {
		return nil, err
	}
	return &idmGRPC.EmptyResponse{}, nil
}

func (c *IdmRPC) IsValidRefresh(ctx context.Context, in *idmGRPC.Refresh) (*idmGRPC.EmptyResponse, error) {
	err := c.JWTService.IsValidRefresh(in.Refresh)
	if err != nil {
		return nil, err
	}
	return &idmGRPC.EmptyResponse{}, nil
}
