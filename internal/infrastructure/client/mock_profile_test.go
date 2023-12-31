// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/3110Y/cc-idm/internal/infrastructure/client (interfaces: ProfileServiceClientInterface)

// Package client is a generated GoMock package.
package client

import (
	context "context"
	reflect "reflect"

	profileGRPC "github.com/3110Y/profile/pkg/profileGRPC"
	gomock "github.com/golang/mock/gomock"
	grpc "google.golang.org/grpc"
)

// MockProfileServiceClientInterface is a mock of ProfileServiceClientInterface interface.
type MockProfileServiceClientInterface struct {
	ctrl     *gomock.Controller
	recorder *MockProfileServiceClientInterfaceMockRecorder
}

// MockProfileServiceClientInterfaceMockRecorder is the mock recorder for MockProfileServiceClientInterface.
type MockProfileServiceClientInterfaceMockRecorder struct {
	mock *MockProfileServiceClientInterface
}

// NewMockProfileServiceClientInterface creates a new mock instance.
func NewMockProfileServiceClientInterface(ctrl *gomock.Controller) *MockProfileServiceClientInterface {
	mock := &MockProfileServiceClientInterface{ctrl: ctrl}
	mock.recorder = &MockProfileServiceClientInterfaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockProfileServiceClientInterface) EXPECT() *MockProfileServiceClientInterfaceMockRecorder {
	return m.recorder
}

// GetByEmailOrPhone mocks base method.
func (m *MockProfileServiceClientInterface) GetByEmailOrPhone(arg0 context.Context, arg1 *profileGRPC.ProfileEmailPhonePassword, arg2 ...grpc.CallOption) (*profileGRPC.ProfileWithoutPassword, error) {
	m.ctrl.T.Helper()
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetByEmailOrPhone", varargs...)
	ret0, _ := ret[0].(*profileGRPC.ProfileWithoutPassword)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetByEmailOrPhone indicates an expected call of GetByEmailOrPhone.
func (mr *MockProfileServiceClientInterfaceMockRecorder) GetByEmailOrPhone(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetByEmailOrPhone", reflect.TypeOf((*MockProfileServiceClientInterface)(nil).GetByEmailOrPhone), varargs...)
}
