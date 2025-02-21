// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/runfinch/finch-daemon/api/handlers/image (interfaces: Service)

// Package mocks_image is a generated GoMock package.
package mocks_image

import (
	context "context"
	io "io"
	reflect "reflect"

	dockercompat "github.com/containerd/nerdctl/v2/pkg/inspecttypes/dockercompat"
	types "github.com/docker/cli/cli/config/types"
	gomock "github.com/golang/mock/gomock"
	types0 "github.com/runfinch/finch-daemon/api/types"
)

// MockService is a mock of Service interface.
type MockService struct {
	ctrl     *gomock.Controller
	recorder *MockServiceMockRecorder
}

// MockServiceMockRecorder is the mock recorder for MockService.
type MockServiceMockRecorder struct {
	mock *MockService
}

// NewMockService creates a new mock instance.
func NewMockService(ctrl *gomock.Controller) *MockService {
	mock := &MockService{ctrl: ctrl}
	mock.recorder = &MockServiceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockService) EXPECT() *MockServiceMockRecorder {
	return m.recorder
}

// Inspect mocks base method.
func (m *MockService) Inspect(arg0 context.Context, arg1 string) (*dockercompat.Image, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Inspect", arg0, arg1)
	ret0, _ := ret[0].(*dockercompat.Image)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Inspect indicates an expected call of Inspect.
func (mr *MockServiceMockRecorder) Inspect(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Inspect", reflect.TypeOf((*MockService)(nil).Inspect), arg0, arg1)
}

// List mocks base method.
func (m *MockService) List(arg0 context.Context) ([]types0.ImageSummary, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "List", arg0)
	ret0, _ := ret[0].([]types0.ImageSummary)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// List indicates an expected call of List.
func (mr *MockServiceMockRecorder) List(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "List", reflect.TypeOf((*MockService)(nil).List), arg0)
}

// Load mocks base method.
func (m *MockService) Load(arg0 context.Context, arg1 io.Reader, arg2 io.Writer, arg3 bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Load", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// Load indicates an expected call of Load.
func (mr *MockServiceMockRecorder) Load(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Load", reflect.TypeOf((*MockService)(nil).Load), arg0, arg1, arg2, arg3)
}

// Pull mocks base method.
func (m *MockService) Pull(arg0 context.Context, arg1, arg2, arg3 string, arg4 *types.AuthConfig, arg5 io.Writer) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Pull", arg0, arg1, arg2, arg3, arg4, arg5)
	ret0, _ := ret[0].(error)
	return ret0
}

// Pull indicates an expected call of Pull.
func (mr *MockServiceMockRecorder) Pull(arg0, arg1, arg2, arg3, arg4, arg5 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Pull", reflect.TypeOf((*MockService)(nil).Pull), arg0, arg1, arg2, arg3, arg4, arg5)
}

// Push mocks base method.
func (m *MockService) Push(arg0 context.Context, arg1, arg2 string, arg3 *types.AuthConfig, arg4 io.Writer) (*types0.PushResult, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Push", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(*types0.PushResult)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Push indicates an expected call of Push.
func (mr *MockServiceMockRecorder) Push(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Push", reflect.TypeOf((*MockService)(nil).Push), arg0, arg1, arg2, arg3, arg4)
}

// Remove mocks base method.
func (m *MockService) Remove(arg0 context.Context, arg1 string, arg2 bool) ([]string, []string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Remove", arg0, arg1, arg2)
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].([]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// Remove indicates an expected call of Remove.
func (mr *MockServiceMockRecorder) Remove(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Remove", reflect.TypeOf((*MockService)(nil).Remove), arg0, arg1, arg2)
}

// Tag mocks base method.
func (m *MockService) Tag(arg0 context.Context, arg1, arg2, arg3 string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Tag", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(error)
	return ret0
}

// Tag indicates an expected call of Tag.
func (mr *MockServiceMockRecorder) Tag(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Tag", reflect.TypeOf((*MockService)(nil).Tag), arg0, arg1, arg2, arg3)
}
