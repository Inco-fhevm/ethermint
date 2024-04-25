// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: ethermint/evm/v1/params_v4.proto

package types

import (
	fmt "fmt"
	_ "github.com/cosmos/gogoproto/gogoproto"
	proto "github.com/cosmos/gogoproto/proto"
	io "io"
	math "math"
	math_bits "math/bits"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

// V4Params defines the EVM module parameters
type V4Params struct {
	// evm_denom represents the token denomination used to run the EVM state
	// transitions.
	EvmDenom string `protobuf:"bytes,1,opt,name=evm_denom,json=evmDenom,proto3" json:"evm_denom,omitempty" yaml:"evm_denom"`
	// enable_create toggles state transitions that use the vm.Create function
	EnableCreate bool `protobuf:"varint,2,opt,name=enable_create,json=enableCreate,proto3" json:"enable_create,omitempty" yaml:"enable_create"`
	// enable_call toggles state transitions that use the vm.Call function
	EnableCall bool `protobuf:"varint,3,opt,name=enable_call,json=enableCall,proto3" json:"enable_call,omitempty" yaml:"enable_call"`
	// extra_eips defines the additional EIPs for the vm.Config
	ExtraEIPs ExtraEIPs `protobuf:"bytes,4,opt,name=extra_eips,json=extraEips,proto3" json:"extra_eips"`
	// chain_config defines the EVM chain configuration parameters
	ChainConfig V0ChainConfig `protobuf:"bytes,5,opt,name=chain_config,json=chainConfig,proto3" json:"chain_config"`
	// allow_unprotected_txs defines if replay-protected (i.e non EIP155
	// signed) transactions can be executed on the state machine.
	AllowUnprotectedTxs bool `protobuf:"varint,6,opt,name=allow_unprotected_txs,json=allowUnprotectedTxs,proto3" json:"allow_unprotected_txs,omitempty"`
}

func (m *V4Params) Reset()         { *m = V4Params{} }
func (m *V4Params) String() string { return proto.CompactTextString(m) }
func (*V4Params) ProtoMessage()    {}
func (*V4Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_33bcd56473e886c3, []int{0}
}
func (m *V4Params) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *V4Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_V4Params.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *V4Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_V4Params.Merge(m, src)
}
func (m *V4Params) XXX_Size() int {
	return m.Size()
}
func (m *V4Params) XXX_DiscardUnknown() {
	xxx_messageInfo_V4Params.DiscardUnknown(m)
}

var xxx_messageInfo_V4Params proto.InternalMessageInfo

func (m *V4Params) GetEvmDenom() string {
	if m != nil {
		return m.EvmDenom
	}
	return ""
}

func (m *V4Params) GetEnableCreate() bool {
	if m != nil {
		return m.EnableCreate
	}
	return false
}

func (m *V4Params) GetEnableCall() bool {
	if m != nil {
		return m.EnableCall
	}
	return false
}

func (m *V4Params) GetExtraEIPs() ExtraEIPs {
	if m != nil {
		return m.ExtraEIPs
	}
	return ExtraEIPs{}
}

func (m *V4Params) GetChainConfig() V0ChainConfig {
	if m != nil {
		return m.ChainConfig
	}
	return V0ChainConfig{}
}

func (m *V4Params) GetAllowUnprotectedTxs() bool {
	if m != nil {
		return m.AllowUnprotectedTxs
	}
	return false
}

// ExtraEIPs represents extra EIPs for the vm.Config
type ExtraEIPs struct {
	// eips defines the additional EIPs for the vm.Config
	EIPs []int64 `protobuf:"varint,1,rep,packed,name=eips,proto3" json:"eips,omitempty" yaml:"eips"`
}

func (m *ExtraEIPs) Reset()         { *m = ExtraEIPs{} }
func (m *ExtraEIPs) String() string { return proto.CompactTextString(m) }
func (*ExtraEIPs) ProtoMessage()    {}
func (*ExtraEIPs) Descriptor() ([]byte, []int) {
	return fileDescriptor_33bcd56473e886c3, []int{1}
}
func (m *ExtraEIPs) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ExtraEIPs) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ExtraEIPs.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ExtraEIPs) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ExtraEIPs.Merge(m, src)
}
func (m *ExtraEIPs) XXX_Size() int {
	return m.Size()
}
func (m *ExtraEIPs) XXX_DiscardUnknown() {
	xxx_messageInfo_ExtraEIPs.DiscardUnknown(m)
}

var xxx_messageInfo_ExtraEIPs proto.InternalMessageInfo

func (m *ExtraEIPs) GetEIPs() []int64 {
	if m != nil {
		return m.EIPs
	}
	return nil
}

func init() {
	proto.RegisterType((*V4Params)(nil), "ethermint.evm.v1.V4Params")
	proto.RegisterType((*ExtraEIPs)(nil), "ethermint.evm.v1.ExtraEIPs")
}

func init() { proto.RegisterFile("ethermint/evm/v1/params_v4.proto", fileDescriptor_33bcd56473e886c3) }

var fileDescriptor_33bcd56473e886c3 = []byte{
	// 434 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0x52, 0xcf, 0x8a, 0xd3, 0x40,
	0x18, 0x6f, 0x6c, 0x5d, 0xda, 0xe9, 0x0a, 0xeb, 0x58, 0x35, 0xac, 0x90, 0x84, 0x1c, 0x96, 0x82,
	0x90, 0x6c, 0xd7, 0x05, 0x45, 0x10, 0x24, 0xb5, 0xa0, 0x07, 0x61, 0x09, 0xba, 0x07, 0x2f, 0xc3,
	0x34, 0xfb, 0xd9, 0x06, 0x66, 0x32, 0x21, 0x33, 0x3b, 0x76, 0xaf, 0x3e, 0x81, 0x8f, 0xb5, 0xc7,
	0x3d, 0x7a, 0x0a, 0x92, 0xbe, 0x41, 0x9f, 0x40, 0x66, 0x5a, 0xdb, 0x75, 0xf7, 0x36, 0xdf, 0xf7,
	0xfb, 0x93, 0x7c, 0x3f, 0x7e, 0x28, 0x00, 0x35, 0x87, 0x8a, 0xe7, 0x85, 0x8a, 0x41, 0xf3, 0x58,
	0x8f, 0xe2, 0x92, 0x56, 0x94, 0x4b, 0xa2, 0x4f, 0xa3, 0xb2, 0x12, 0x4a, 0xe0, 0x83, 0x2d, 0x23,
	0x02, 0xcd, 0x23, 0x3d, 0x3a, 0x1c, 0xcc, 0xc4, 0x4c, 0x58, 0x30, 0x36, 0xaf, 0x35, 0xef, 0xf0,
	0xe8, 0x9e, 0x53, 0x36, 0xa7, 0x79, 0x41, 0x32, 0x51, 0x7c, 0xcf, 0x67, 0x44, 0x1f, 0xaf, 0x79,
	0xe1, 0xcf, 0x36, 0xea, 0x9e, 0x9f, 0x9e, 0xd9, 0xaf, 0xe0, 0x11, 0xea, 0x81, 0xe6, 0xe4, 0x02,
	0x0a, 0xc1, 0x5d, 0x27, 0x70, 0x86, 0xbd, 0x64, 0xb0, 0xaa, 0xfd, 0x83, 0x2b, 0xca, 0xd9, 0xdb,
	0x70, 0x0b, 0x85, 0x69, 0x17, 0x34, 0xff, 0x60, 0x9e, 0xf8, 0x1d, 0x7a, 0x04, 0x05, 0x9d, 0x32,
	0x20, 0x59, 0x05, 0x54, 0x81, 0xfb, 0x20, 0x70, 0x86, 0xdd, 0xc4, 0x5d, 0xd5, 0xfe, 0x60, 0x23,
	0xbb, 0x0d, 0x87, 0xe9, 0xfe, 0x7a, 0x1e, 0xdb, 0x11, 0xbf, 0x46, 0xfd, 0x7f, 0x38, 0x65, 0xcc,
	0x6d, 0x5b, 0xf1, 0xb3, 0x55, 0xed, 0xe3, 0xff, 0xc5, 0x94, 0xb1, 0x30, 0x45, 0x1b, 0x29, 0x65,
	0x0c, 0x7f, 0x46, 0x08, 0x16, 0xaa, 0xa2, 0x04, 0xf2, 0x52, 0xba, 0x9d, 0xc0, 0x19, 0xf6, 0x4f,
	0x5e, 0x44, 0x77, 0xc3, 0x89, 0x26, 0x86, 0x33, 0xf9, 0x74, 0x26, 0x93, 0xc7, 0xd7, 0xb5, 0xdf,
	0x6a, 0x6a, 0xbf, 0xb7, 0x5d, 0xa5, 0x3d, 0xeb, 0x30, 0xc9, 0x4b, 0x89, 0x3f, 0xa2, 0xfd, 0xdb,
	0xf9, 0xb8, 0x0f, 0xad, 0xa1, 0x7f, 0xdf, 0xf0, 0xfc, 0x78, 0x6c, 0x78, 0x63, 0x4b, 0x4b, 0x3a,
	0xc6, 0x34, 0xed, 0x67, 0xbb, 0x15, 0x3e, 0x41, 0x4f, 0x29, 0x63, 0xe2, 0x07, 0xb9, 0x2c, 0x4c,
	0xc2, 0x90, 0x29, 0xb8, 0x20, 0x6a, 0x21, 0xdd, 0x3d, 0x73, 0x5b, 0xfa, 0xc4, 0x82, 0x5f, 0x77,
	0xd8, 0x97, 0x85, 0x0c, 0xdf, 0xa0, 0xdd, 0x5f, 0xe1, 0x97, 0xa8, 0x63, 0x6f, 0x72, 0x82, 0xf6,
	0xb0, 0x9d, 0x3c, 0x6f, 0x6a, 0xbf, 0x63, 0xf6, 0xab, 0xda, 0xef, 0x6f, 0x32, 0xc9, 0x4b, 0x19,
	0xa6, 0x96, 0x94, 0xbc, 0xbf, 0x6e, 0x3c, 0xe7, 0xa6, 0xf1, 0x9c, 0x3f, 0x8d, 0xe7, 0xfc, 0x5a,
	0x7a, 0xad, 0x9b, 0xa5, 0xd7, 0xfa, 0xbd, 0xf4, 0x5a, 0xdf, 0x8e, 0x66, 0xb9, 0x9a, 0x5f, 0x4e,
	0xa3, 0x4c, 0x70, 0xd3, 0x00, 0x21, 0xe3, 0x5d, 0x23, 0x16, 0xb6, 0x13, 0xea, 0xaa, 0x04, 0x39,
	0xdd, 0xb3, 0x3d, 0x78, 0xf5, 0x37, 0x00, 0x00, 0xff, 0xff, 0xd4, 0x07, 0x2c, 0x12, 0x7b, 0x02,
	0x00, 0x00,
}

func (m *V4Params) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *V4Params) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *V4Params) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if m.AllowUnprotectedTxs {
		i--
		if m.AllowUnprotectedTxs {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x30
	}
	{
		size, err := m.ChainConfig.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintParamsV4(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x2a
	{
		size, err := m.ExtraEIPs.MarshalToSizedBuffer(dAtA[:i])
		if err != nil {
			return 0, err
		}
		i -= size
		i = encodeVarintParamsV4(dAtA, i, uint64(size))
	}
	i--
	dAtA[i] = 0x22
	if m.EnableCall {
		i--
		if m.EnableCall {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x18
	}
	if m.EnableCreate {
		i--
		if m.EnableCreate {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x10
	}
	if len(m.EvmDenom) > 0 {
		i -= len(m.EvmDenom)
		copy(dAtA[i:], m.EvmDenom)
		i = encodeVarintParamsV4(dAtA, i, uint64(len(m.EvmDenom)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ExtraEIPs) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ExtraEIPs) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ExtraEIPs) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.EIPs) > 0 {
		dAtA4 := make([]byte, len(m.EIPs)*10)
		var j3 int
		for _, num1 := range m.EIPs {
			num := uint64(num1)
			for num >= 1<<7 {
				dAtA4[j3] = uint8(uint64(num)&0x7f | 0x80)
				num >>= 7
				j3++
			}
			dAtA4[j3] = uint8(num)
			j3++
		}
		i -= j3
		copy(dAtA[i:], dAtA4[:j3])
		i = encodeVarintParamsV4(dAtA, i, uint64(j3))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintParamsV4(dAtA []byte, offset int, v uint64) int {
	offset -= sovParamsV4(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *V4Params) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.EvmDenom)
	if l > 0 {
		n += 1 + l + sovParamsV4(uint64(l))
	}
	if m.EnableCreate {
		n += 2
	}
	if m.EnableCall {
		n += 2
	}
	l = m.ExtraEIPs.Size()
	n += 1 + l + sovParamsV4(uint64(l))
	l = m.ChainConfig.Size()
	n += 1 + l + sovParamsV4(uint64(l))
	if m.AllowUnprotectedTxs {
		n += 2
	}
	return n
}

func (m *ExtraEIPs) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	if len(m.EIPs) > 0 {
		l = 0
		for _, e := range m.EIPs {
			l += sovParamsV4(uint64(e))
		}
		n += 1 + sovParamsV4(uint64(l)) + l
	}
	return n
}

func sovParamsV4(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozParamsV4(x uint64) (n int) {
	return sovParamsV4(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (m *V4Params) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowParamsV4
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: V4Params: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: V4Params: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field EvmDenom", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthParamsV4
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthParamsV4
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.EvmDenom = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		case 2:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field EnableCreate", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.EnableCreate = bool(v != 0)
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field EnableCall", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.EnableCall = bool(v != 0)
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ExtraEIPs", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthParamsV4
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthParamsV4
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ExtraEIPs.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 5:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field ChainConfig", wireType)
			}
			var msglen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				msglen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if msglen < 0 {
				return ErrInvalidLengthParamsV4
			}
			postIndex := iNdEx + msglen
			if postIndex < 0 {
				return ErrInvalidLengthParamsV4
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			if err := m.ChainConfig.Unmarshal(dAtA[iNdEx:postIndex]); err != nil {
				return err
			}
			iNdEx = postIndex
		case 6:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field AllowUnprotectedTxs", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.AllowUnprotectedTxs = bool(v != 0)
		default:
			iNdEx = preIndex
			skippy, err := skipParamsV4(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthParamsV4
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ExtraEIPs) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowParamsV4
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ExtraEIPs: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ExtraEIPs: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType == 0 {
				var v int64
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowParamsV4
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					v |= int64(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				m.EIPs = append(m.EIPs, v)
			} else if wireType == 2 {
				var packedLen int
				for shift := uint(0); ; shift += 7 {
					if shift >= 64 {
						return ErrIntOverflowParamsV4
					}
					if iNdEx >= l {
						return io.ErrUnexpectedEOF
					}
					b := dAtA[iNdEx]
					iNdEx++
					packedLen |= int(b&0x7F) << shift
					if b < 0x80 {
						break
					}
				}
				if packedLen < 0 {
					return ErrInvalidLengthParamsV4
				}
				postIndex := iNdEx + packedLen
				if postIndex < 0 {
					return ErrInvalidLengthParamsV4
				}
				if postIndex > l {
					return io.ErrUnexpectedEOF
				}
				var elementCount int
				var count int
				for _, integer := range dAtA[iNdEx:postIndex] {
					if integer < 128 {
						count++
					}
				}
				elementCount = count
				if elementCount != 0 && len(m.EIPs) == 0 {
					m.EIPs = make([]int64, 0, elementCount)
				}
				for iNdEx < postIndex {
					var v int64
					for shift := uint(0); ; shift += 7 {
						if shift >= 64 {
							return ErrIntOverflowParamsV4
						}
						if iNdEx >= l {
							return io.ErrUnexpectedEOF
						}
						b := dAtA[iNdEx]
						iNdEx++
						v |= int64(b&0x7F) << shift
						if b < 0x80 {
							break
						}
					}
					m.EIPs = append(m.EIPs, v)
				}
			} else {
				return fmt.Errorf("proto: wrong wireType = %d for field EIPs", wireType)
			}
		default:
			iNdEx = preIndex
			skippy, err := skipParamsV4(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if (skippy < 0) || (iNdEx+skippy) < 0 {
				return ErrInvalidLengthParamsV4
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipParamsV4(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowParamsV4
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowParamsV4
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthParamsV4
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupParamsV4
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthParamsV4
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthParamsV4        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowParamsV4          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupParamsV4 = fmt.Errorf("proto: unexpected end of group")
)
