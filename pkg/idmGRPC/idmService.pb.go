// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.21.12
// source: idmService.proto

package idmGRPC

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ProfileEmailPhonePassword struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Email    string `protobuf:"bytes,1,opt,name=email,proto3" json:"email,omitempty"`
	Phone    uint64 `protobuf:"varint,2,opt,name=phone,proto3" json:"phone,omitempty"`
	Password string `protobuf:"bytes,3,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *ProfileEmailPhonePassword) Reset() {
	*x = ProfileEmailPhonePassword{}
	if protoimpl.UnsafeEnabled {
		mi := &file_idmService_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProfileEmailPhonePassword) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProfileEmailPhonePassword) ProtoMessage() {}

func (x *ProfileEmailPhonePassword) ProtoReflect() protoreflect.Message {
	mi := &file_idmService_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProfileEmailPhonePassword.ProtoReflect.Descriptor instead.
func (*ProfileEmailPhonePassword) Descriptor() ([]byte, []int) {
	return file_idmService_proto_rawDescGZIP(), []int{0}
}

func (x *ProfileEmailPhonePassword) GetEmail() string {
	if x != nil {
		return x.Email
	}
	return ""
}

func (x *ProfileEmailPhonePassword) GetPhone() uint64 {
	if x != nil {
		return x.Phone
	}
	return 0
}

func (x *ProfileEmailPhonePassword) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type AccessAndRefresh struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Access  string `protobuf:"bytes,1,opt,name=Access,proto3" json:"Access,omitempty"`
	Refresh string `protobuf:"bytes,2,opt,name=Refresh,proto3" json:"Refresh,omitempty"`
}

func (x *AccessAndRefresh) Reset() {
	*x = AccessAndRefresh{}
	if protoimpl.UnsafeEnabled {
		mi := &file_idmService_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AccessAndRefresh) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AccessAndRefresh) ProtoMessage() {}

func (x *AccessAndRefresh) ProtoReflect() protoreflect.Message {
	mi := &file_idmService_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AccessAndRefresh.ProtoReflect.Descriptor instead.
func (*AccessAndRefresh) Descriptor() ([]byte, []int) {
	return file_idmService_proto_rawDescGZIP(), []int{1}
}

func (x *AccessAndRefresh) GetAccess() string {
	if x != nil {
		return x.Access
	}
	return ""
}

func (x *AccessAndRefresh) GetRefresh() string {
	if x != nil {
		return x.Refresh
	}
	return ""
}

type Refresh struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Refresh string `protobuf:"bytes,2,opt,name=Refresh,proto3" json:"Refresh,omitempty"`
}

func (x *Refresh) Reset() {
	*x = Refresh{}
	if protoimpl.UnsafeEnabled {
		mi := &file_idmService_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Refresh) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Refresh) ProtoMessage() {}

func (x *Refresh) ProtoReflect() protoreflect.Message {
	mi := &file_idmService_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Refresh.ProtoReflect.Descriptor instead.
func (*Refresh) Descriptor() ([]byte, []int) {
	return file_idmService_proto_rawDescGZIP(), []int{2}
}

func (x *Refresh) GetRefresh() string {
	if x != nil {
		return x.Refresh
	}
	return ""
}

type Access struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Access string `protobuf:"bytes,2,opt,name=Access,proto3" json:"Access,omitempty"`
}

func (x *Access) Reset() {
	*x = Access{}
	if protoimpl.UnsafeEnabled {
		mi := &file_idmService_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Access) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Access) ProtoMessage() {}

func (x *Access) ProtoReflect() protoreflect.Message {
	mi := &file_idmService_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Access.ProtoReflect.Descriptor instead.
func (*Access) Descriptor() ([]byte, []int) {
	return file_idmService_proto_rawDescGZIP(), []int{3}
}

func (x *Access) GetAccess() string {
	if x != nil {
		return x.Access
	}
	return ""
}

type EmptyResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *EmptyResponse) Reset() {
	*x = EmptyResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_idmService_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EmptyResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EmptyResponse) ProtoMessage() {}

func (x *EmptyResponse) ProtoReflect() protoreflect.Message {
	mi := &file_idmService_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EmptyResponse.ProtoReflect.Descriptor instead.
func (*EmptyResponse) Descriptor() ([]byte, []int) {
	return file_idmService_proto_rawDescGZIP(), []int{4}
}

var File_idmService_proto protoreflect.FileDescriptor

var file_idmService_proto_rawDesc = []byte{
	0x0a, 0x10, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x12, 0x0a, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x22, 0x63,
	0x0a, 0x19, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x45, 0x6d, 0x61, 0x69, 0x6c, 0x50, 0x68,
	0x6f, 0x6e, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x65,
	0x6d, 0x61, 0x69, 0x6c, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x6d, 0x61, 0x69,
	0x6c, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x05, 0x70, 0x68, 0x6f, 0x6e, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77,
	0x6f, 0x72, 0x64, 0x22, 0x44, 0x0a, 0x10, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x41, 0x6e, 0x64,
	0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x12, 0x16, 0x0a, 0x06, 0x41, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12,
	0x18, 0x0a, 0x07, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x07, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x22, 0x23, 0x0a, 0x07, 0x52, 0x65, 0x66,
	0x72, 0x65, 0x73, 0x68, 0x12, 0x18, 0x0a, 0x07, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x22, 0x20,
	0x0a, 0x06, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x16, 0x0a, 0x06, 0x41, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x22, 0x0f, 0x0a, 0x0d, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x32, 0xad, 0x02, 0x0a, 0x0a, 0x49, 0x44, 0x4d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65,
	0x12, 0x5b, 0x0a, 0x14, 0x46, 0x72, 0x6f, 0x6d, 0x4c, 0x6f, 0x67, 0x69, 0x6e, 0x41, 0x6e, 0x64,
	0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x12, 0x25, 0x2e, 0x69, 0x64, 0x6d, 0x53, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x50, 0x72, 0x6f, 0x66, 0x69, 0x6c, 0x65, 0x45, 0x6d, 0x61,
	0x69, 0x6c, 0x50, 0x68, 0x6f, 0x6e, 0x65, 0x50, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x1a,
	0x1c, 0x2e, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x41, 0x6e, 0x64, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x12, 0x40, 0x0a,
	0x0b, 0x46, 0x72, 0x6f, 0x6d, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x12, 0x13, 0x2e, 0x69,
	0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73,
	0x68, 0x1a, 0x1c, 0x2e, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x41,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x41, 0x6e, 0x64, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x12,
	0x3e, 0x0a, 0x0d, 0x49, 0x73, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73,
	0x12, 0x12, 0x2e, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x41, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x1a, 0x19, 0x2e, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63,
	0x65, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x40, 0x0a, 0x0e, 0x49, 0x73, 0x56, 0x61, 0x6c, 0x69, 0x64, 0x52, 0x65, 0x66, 0x72, 0x65, 0x73,
	0x68, 0x12, 0x13, 0x2e, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x2e, 0x52,
	0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x1a, 0x19, 0x2e, 0x69, 0x64, 0x6d, 0x53, 0x65, 0x72, 0x76,
	0x69, 0x63, 0x65, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x42, 0x21, 0x5a, 0x1f, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x33, 0x31, 0x31, 0x30, 0x59, 0x2f, 0x63, 0x63, 0x2d, 0x69, 0x64, 0x6d, 0x3b, 0x69, 0x64, 0x6d,
	0x47, 0x52, 0x50, 0x43, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_idmService_proto_rawDescOnce sync.Once
	file_idmService_proto_rawDescData = file_idmService_proto_rawDesc
)

func file_idmService_proto_rawDescGZIP() []byte {
	file_idmService_proto_rawDescOnce.Do(func() {
		file_idmService_proto_rawDescData = protoimpl.X.CompressGZIP(file_idmService_proto_rawDescData)
	})
	return file_idmService_proto_rawDescData
}

var file_idmService_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_idmService_proto_goTypes = []interface{}{
	(*ProfileEmailPhonePassword)(nil), // 0: idmService.ProfileEmailPhonePassword
	(*AccessAndRefresh)(nil),          // 1: idmService.AccessAndRefresh
	(*Refresh)(nil),                   // 2: idmService.Refresh
	(*Access)(nil),                    // 3: idmService.Access
	(*EmptyResponse)(nil),             // 4: idmService.EmptyResponse
}
var file_idmService_proto_depIdxs = []int32{
	0, // 0: idmService.IDMService.FromLoginAndPassword:input_type -> idmService.ProfileEmailPhonePassword
	2, // 1: idmService.IDMService.FromRefresh:input_type -> idmService.Refresh
	3, // 2: idmService.IDMService.IsValidAccess:input_type -> idmService.Access
	2, // 3: idmService.IDMService.IsValidRefresh:input_type -> idmService.Refresh
	1, // 4: idmService.IDMService.FromLoginAndPassword:output_type -> idmService.AccessAndRefresh
	1, // 5: idmService.IDMService.FromRefresh:output_type -> idmService.AccessAndRefresh
	4, // 6: idmService.IDMService.IsValidAccess:output_type -> idmService.EmptyResponse
	4, // 7: idmService.IDMService.IsValidRefresh:output_type -> idmService.EmptyResponse
	4, // [4:8] is the sub-list for method output_type
	0, // [0:4] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_idmService_proto_init() }
func file_idmService_proto_init() {
	if File_idmService_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_idmService_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProfileEmailPhonePassword); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_idmService_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AccessAndRefresh); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_idmService_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Refresh); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_idmService_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Access); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_idmService_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EmptyResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_idmService_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_idmService_proto_goTypes,
		DependencyIndexes: file_idmService_proto_depIdxs,
		MessageInfos:      file_idmService_proto_msgTypes,
	}.Build()
	File_idmService_proto = out.File
	file_idmService_proto_rawDesc = nil
	file_idmService_proto_goTypes = nil
	file_idmService_proto_depIdxs = nil
}
