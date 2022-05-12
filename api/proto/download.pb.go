// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.19.3
// source: download.proto

package proto

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

type CreateDownloadRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	FlowId   string `protobuf:"bytes,1,opt,name=flow_id,json=flowId,proto3" json:"flow_id,omitempty"`
	ClientId string `protobuf:"bytes,2,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	HuntId   string `protobuf:"bytes,3,opt,name=hunt_id,json=huntId,proto3" json:"hunt_id,omitempty"`
	// When set we only create combined hunt output and not individual
	// flow breakdowns.
	OnlyCombinedHunt bool `protobuf:"varint,4,opt,name=only_combined_hunt,json=onlyCombinedHunt,proto3" json:"only_combined_hunt,omitempty"`
	JsonFormat       bool `protobuf:"varint,5,opt,name=json_format,json=jsonFormat,proto3" json:"json_format,omitempty"`
	CsvFormat        bool `protobuf:"varint,6,opt,name=csv_format,json=csvFormat,proto3" json:"csv_format,omitempty"`
	// Can be "report" for html report or "" for just files.
	DownloadType string `protobuf:"bytes,7,opt,name=download_type,json=downloadType,proto3" json:"download_type,omitempty"`
	// If set we lock the file with this password.
	Password string `protobuf:"bytes,8,opt,name=password,proto3" json:"password,omitempty"`
}

func (x *CreateDownloadRequest) Reset() {
	*x = CreateDownloadRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_download_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateDownloadRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateDownloadRequest) ProtoMessage() {}

func (x *CreateDownloadRequest) ProtoReflect() protoreflect.Message {
	mi := &file_download_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateDownloadRequest.ProtoReflect.Descriptor instead.
func (*CreateDownloadRequest) Descriptor() ([]byte, []int) {
	return file_download_proto_rawDescGZIP(), []int{0}
}

func (x *CreateDownloadRequest) GetFlowId() string {
	if x != nil {
		return x.FlowId
	}
	return ""
}

func (x *CreateDownloadRequest) GetClientId() string {
	if x != nil {
		return x.ClientId
	}
	return ""
}

func (x *CreateDownloadRequest) GetHuntId() string {
	if x != nil {
		return x.HuntId
	}
	return ""
}

func (x *CreateDownloadRequest) GetOnlyCombinedHunt() bool {
	if x != nil {
		return x.OnlyCombinedHunt
	}
	return false
}

func (x *CreateDownloadRequest) GetJsonFormat() bool {
	if x != nil {
		return x.JsonFormat
	}
	return false
}

func (x *CreateDownloadRequest) GetCsvFormat() bool {
	if x != nil {
		return x.CsvFormat
	}
	return false
}

func (x *CreateDownloadRequest) GetDownloadType() string {
	if x != nil {
		return x.DownloadType
	}
	return ""
}

func (x *CreateDownloadRequest) GetPassword() string {
	if x != nil {
		return x.Password
	}
	return ""
}

type CreateDownloadResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	VfsPath string `protobuf:"bytes,1,opt,name=vfs_path,json=vfsPath,proto3" json:"vfs_path,omitempty"`
}

func (x *CreateDownloadResponse) Reset() {
	*x = CreateDownloadResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_download_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateDownloadResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateDownloadResponse) ProtoMessage() {}

func (x *CreateDownloadResponse) ProtoReflect() protoreflect.Message {
	mi := &file_download_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateDownloadResponse.ProtoReflect.Descriptor instead.
func (*CreateDownloadResponse) Descriptor() ([]byte, []int) {
	return file_download_proto_rawDescGZIP(), []int{1}
}

func (x *CreateDownloadResponse) GetVfsPath() string {
	if x != nil {
		return x.VfsPath
	}
	return ""
}

type FormUploadMetadata struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Filename string `protobuf:"bytes,1,opt,name=filename,proto3" json:"filename,omitempty"`
	Url      string `protobuf:"bytes,2,opt,name=url,proto3" json:"url,omitempty"`
}

func (x *FormUploadMetadata) Reset() {
	*x = FormUploadMetadata{}
	if protoimpl.UnsafeEnabled {
		mi := &file_download_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FormUploadMetadata) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FormUploadMetadata) ProtoMessage() {}

func (x *FormUploadMetadata) ProtoReflect() protoreflect.Message {
	mi := &file_download_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FormUploadMetadata.ProtoReflect.Descriptor instead.
func (*FormUploadMetadata) Descriptor() ([]byte, []int) {
	return file_download_proto_rawDescGZIP(), []int{2}
}

func (x *FormUploadMetadata) GetFilename() string {
	if x != nil {
		return x.Filename
	}
	return ""
}

func (x *FormUploadMetadata) GetUrl() string {
	if x != nil {
		return x.Url
	}
	return ""
}

var File_download_proto protoreflect.FileDescriptor

var file_download_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x95, 0x02, 0x0a, 0x15, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x12, 0x17, 0x0a, 0x07, 0x66, 0x6c, 0x6f, 0x77, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x66, 0x6c, 0x6f, 0x77, 0x49, 0x64, 0x12, 0x1b, 0x0a, 0x09, 0x63, 0x6c,
	0x69, 0x65, 0x6e, 0x74, 0x5f, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x63,
	0x6c, 0x69, 0x65, 0x6e, 0x74, 0x49, 0x64, 0x12, 0x17, 0x0a, 0x07, 0x68, 0x75, 0x6e, 0x74, 0x5f,
	0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x68, 0x75, 0x6e, 0x74, 0x49, 0x64,
	0x12, 0x2c, 0x0a, 0x12, 0x6f, 0x6e, 0x6c, 0x79, 0x5f, 0x63, 0x6f, 0x6d, 0x62, 0x69, 0x6e, 0x65,
	0x64, 0x5f, 0x68, 0x75, 0x6e, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x10, 0x6f, 0x6e,
	0x6c, 0x79, 0x43, 0x6f, 0x6d, 0x62, 0x69, 0x6e, 0x65, 0x64, 0x48, 0x75, 0x6e, 0x74, 0x12, 0x1f,
	0x0a, 0x0b, 0x6a, 0x73, 0x6f, 0x6e, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x0a, 0x6a, 0x73, 0x6f, 0x6e, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12,
	0x1d, 0x0a, 0x0a, 0x63, 0x73, 0x76, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x08, 0x52, 0x09, 0x63, 0x73, 0x76, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x12, 0x23,
	0x0a, 0x0d, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x64, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61, 0x64, 0x54,
	0x79, 0x70, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x22,
	0x33, 0x0a, 0x16, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x44, 0x6f, 0x77, 0x6e, 0x6c, 0x6f, 0x61,
	0x64, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x19, 0x0a, 0x08, 0x76, 0x66, 0x73,
	0x5f, 0x70, 0x61, 0x74, 0x68, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x66, 0x73,
	0x50, 0x61, 0x74, 0x68, 0x22, 0x42, 0x0a, 0x12, 0x46, 0x6f, 0x72, 0x6d, 0x55, 0x70, 0x6c, 0x6f,
	0x61, 0x64, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x12, 0x1a, 0x0a, 0x08, 0x66, 0x69,
	0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x66, 0x69,
	0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x10, 0x0a, 0x03, 0x75, 0x72, 0x6c, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x75, 0x72, 0x6c, 0x42, 0x31, 0x5a, 0x2f, 0x77, 0x77, 0x77, 0x2e,
	0x76, 0x65, 0x6c, 0x6f, 0x63, 0x69, 0x64, 0x65, 0x78, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67, 0x6f,
	0x6c, 0x61, 0x6e, 0x67, 0x2f, 0x76, 0x65, 0x6c, 0x6f, 0x63, 0x69, 0x72, 0x61, 0x70, 0x74, 0x6f,
	0x72, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x33,
}

var (
	file_download_proto_rawDescOnce sync.Once
	file_download_proto_rawDescData = file_download_proto_rawDesc
)

func file_download_proto_rawDescGZIP() []byte {
	file_download_proto_rawDescOnce.Do(func() {
		file_download_proto_rawDescData = protoimpl.X.CompressGZIP(file_download_proto_rawDescData)
	})
	return file_download_proto_rawDescData
}

var file_download_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_download_proto_goTypes = []interface{}{
	(*CreateDownloadRequest)(nil),  // 0: proto.CreateDownloadRequest
	(*CreateDownloadResponse)(nil), // 1: proto.CreateDownloadResponse
	(*FormUploadMetadata)(nil),     // 2: proto.FormUploadMetadata
}
var file_download_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_download_proto_init() }
func file_download_proto_init() {
	if File_download_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_download_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateDownloadRequest); i {
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
		file_download_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CreateDownloadResponse); i {
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
		file_download_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FormUploadMetadata); i {
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
			RawDescriptor: file_download_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_download_proto_goTypes,
		DependencyIndexes: file_download_proto_depIdxs,
		MessageInfos:      file_download_proto_msgTypes,
	}.Build()
	File_download_proto = out.File
	file_download_proto_rawDesc = nil
	file_download_proto_goTypes = nil
	file_download_proto_depIdxs = nil
}
