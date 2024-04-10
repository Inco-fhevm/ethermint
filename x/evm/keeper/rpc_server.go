package keeper

import (
	"math/big"
	"net"
	"net/http"
	"net/rpc"

	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

func (k *Keeper) RunRPCServer() error {
	srv := EthmRpcServer{k: k}
	err := rpc.Register(&srv)
	if err != nil {
		// The emv module's RegisterServices is unfortunately called twice:
		// - once on app startup
		// - another time for autocli discovery
		// Calling twice will cause a panic on rpc.Register, that's why we
		// ignore the error, and return early.
		return nil
	}
	rpc.HandleHTTP()

	// TODO handle port customization
	l, err := net.Listen("tcp", ":9093")
	if err != nil {
		return err
	}
	// TODO Handle shutdown
	go http.Serve(l, nil)

	return nil
}

// EthmRpcServer is a RPC server wrapper around the keeper. It is updated on
// each new sdk.Message with the latest context and Ethereum core.Message.
type EthmRpcServer struct {
	k *Keeper
}

func (s *EthmRpcServer) CreateAccount(args *CreateAccountArgs, reply *CreateAccountReply) error {
	s.k.stateDB.CreateAccount(args.Address)
	return nil
}

func (s *EthmRpcServer) SubBalance(args *SubBalanceArgs, reply *SubBalanceReply) error {
	s.k.stateDB.SubBalance(args.Address, args.Amount)
	return nil
}

func (s *EthmRpcServer) AddBalance(args *AddBalanceArgs, reply *AddBalanceReply) error {
	s.k.stateDB.AddBalance(args.Address, args.Amount)
	return nil
}

func (s *EthmRpcServer) GetBalance(args *GetBalanceArgs, reply *GetBalanceReply) error {
	reply.Balance = s.k.stateDB.GetBalance(args.Address)
	return nil
}

func (s *EthmRpcServer) GetNonce(args *GetNonceArgs, reply *GetNonceReply) error {
	reply.Nonce = s.k.stateDB.GetNonce(args.Address)
	return nil
}

func (s *EthmRpcServer) SetNonce(args *SetNonceArgs, reply *SetNonceReply) error {
	s.k.stateDB.SetNonce(args.Address, args.Nonce)
	return nil
}

func (s *EthmRpcServer) GetCodeHash(args *GetCodeHashArgs, reply *GetCodeHashReply) error {
	reply.CodeHash = s.k.stateDB.GetCodeHash(args.Address)
	return nil
}

func (s *EthmRpcServer) GetCode(args *GetCodeArgs, reply *GetCodeReply) error {
	reply.Code = s.k.stateDB.GetCode(args.Address)
	return nil
}

func (s *EthmRpcServer) SetCode(args *SetCodeArgs, reply *SetCodeReply) error {
	s.k.stateDB.SetCode(args.Address, args.Code)
	return nil
}

func (s *EthmRpcServer) GetCodeSize(args *GetCodeSizeArgs, reply *GetCodeSizeReply) error {
	reply.CodeSize = s.k.stateDB.GetCodeSize(args.Address)
	return nil
}

func (s *EthmRpcServer) AddRefund(args *AddRefundArgs, reply *AddRefundReply) error {
	s.k.stateDB.AddRefund(args.Refund)
	return nil
}

func (s *EthmRpcServer) SubRefund(args *SubRefundArgs, reply *SubRefundReply) error {
	s.k.stateDB.SubRefund(args.Refund)
	return nil
}

func (s *EthmRpcServer) GetRefund(args *GetRefundArgs, reply *GetRefundReply) error {
	reply.Refund = s.k.stateDB.GetRefund()
	return nil
}

func (s *EthmRpcServer) GetCommittedState(args *GetCommittedStateArgs, reply *GetCommittedStateReply) error {
	reply.Value = s.k.stateDB.GetCommittedState(args.Address, args.Key)
	return nil
}

func (s *EthmRpcServer) GetState(args *GetStateArgs, reply *GetStateReply) error {
	reply.Value = s.k.stateDB.GetState(args.Address, args.Key)
	return nil
}

func (s *EthmRpcServer) SetState(args *SetStateArgs, reply *SetStateReply) error {
	s.k.stateDB.SetState(args.Address, args.Key, args.Value)
	return nil
}

func (s *EthmRpcServer) GetTransientState(args *GetTransientStateArgs, reply *GetTransientStateReply) error {
	reply.Value = s.k.stateDB.GetTransientState(args.Address, args.Key)
	return nil
}

func (s *EthmRpcServer) SetTransientState(args *SetTransientStateArgs, reply *SetTransientStateReply) error {
	s.k.stateDB.SetTransientState(args.Address, args.Key, args.Value)
	return nil
}

func (s *EthmRpcServer) SelfDestruct(args *SelfDestructArgs, reply *SelfDestructReply) error {
	s.k.stateDB.SelfDestruct(args.Address)
	return nil
}

func (s *EthmRpcServer) HasSelfDestructed(args *HasSelfDestructedArgs, reply *HasSelfDestructedReply) error {
	reply.HasSelfDestructed = s.k.stateDB.HasSelfDestructed(args.Address)
	return nil
}

func (s *EthmRpcServer) Selfdestruct6780(args *Selfdestruct6780Args, reply *Selfdestruct6780Reply) error {
	s.k.stateDB.Selfdestruct6780(args.Address)
	return nil
}

func (s *EthmRpcServer) Exist(args *ExistArgs, reply *ExistReply) error {
	reply.Exists = s.k.stateDB.Exist(args.Address)
	return nil
}

func (s *EthmRpcServer) Empty(args *EmptyArgs, reply *EmptyReply) error {
	reply.IsEmpty = s.k.stateDB.Empty(args.Address)
	return nil
}

func (s *EthmRpcServer) AddressInAccessList(args *AddressInAccessListArgs, reply *AddressInAccessListReply) error {
	reply.IsInAccessList = s.k.stateDB.AddressInAccessList(args.Address)
	return nil
}

func (s *EthmRpcServer) SlotInAccessList(args *SlotInAccessListArgs, reply *SlotInAccessListReply) error {
	reply.AddressOk, reply.SlotOk = s.k.stateDB.SlotInAccessList(args.Address, args.Slot)
	return nil
}

func (s *EthmRpcServer) AddAddressToAccessList(args *AddAddressToAccessListArgs, reply *AddAddressToAccessListReply) error {
	s.k.stateDB.AddAddressToAccessList(args.Address)
	return nil
}

func (s *EthmRpcServer) AddSlotToAccessList(args *AddSlotToAccessListArgs, reply *AddSlotToAccessListReply) error {
	s.k.stateDB.AddSlotToAccessList(args.Address, args.Slot)
	return nil
}

func (s *EthmRpcServer) Prepare(args *PrepareArgs, reply *PrepareReply) error {
	s.k.stateDB.Prepare(args.Rules, args.Sender, args.Coinbase, args.Dest, args.Precompiles, args.TxAccesses)
	return nil
}

func (s *EthmRpcServer) RevertToSnapshot(args *RevertToSnapshotArgs, reply *RevertToSnapshotReply) error {
	s.k.stateDB.RevertToSnapshot(args.Snapshot)
	return nil
}

func (s *EthmRpcServer) Snapshot(args *SnapshotArgs, reply *SnapshotReply) error {
	reply.Snapshot = s.k.stateDB.Snapshot()
	return nil
}

func (s *EthmRpcServer) AddLog(args *AddLogArgs, reply *AddLogReply) error {
	s.k.stateDB.AddLog(args.Log)
	return nil
}

func (s *EthmRpcServer) AddPreimage(args *AddPreimageArgs, reply *AddPreimageReply) error {
	s.k.stateDB.AddPreimage(args.Hash, args.Preimage)
	return nil
}

type CreateAccountArgs struct {
	Address common.Address
}

type CreateAccountReply struct {
}

type SubBalanceArgs struct {
	Address common.Address
	Amount  *big.Int
}

type SubBalanceReply struct {
}

type AddBalanceArgs struct {
	Address common.Address
	Amount  *big.Int
}

type AddBalanceReply struct {
}

type GetBalanceArgs struct {
	Address common.Address
}

type GetBalanceReply struct {
	Balance *big.Int
}

type GetNonceArgs struct {
	Address common.Address
}

type GetNonceReply struct {
	Nonce uint64
}

type SetNonceArgs struct {
	Address common.Address
	Nonce   uint64
}

type SetNonceReply struct {
}

type GetCodeHashArgs struct {
	Address common.Address
}

type GetCodeHashReply struct {
	CodeHash common.Hash
}

type GetCodeArgs struct {
	Address common.Address
}

type GetCodeReply struct {
	Code []byte
}

type SetCodeArgs struct {
	Address common.Address
	Code    []byte
}

type SetCodeReply struct {
}

type GetCodeSizeArgs struct {
	Address common.Address
}

type GetCodeSizeReply struct {
	CodeSize int
}

type AddRefundArgs struct {
	Refund uint64
}

type AddRefundReply struct {
}

type SubRefundArgs struct {
	Refund uint64
}

type SubRefundReply struct {
}

type GetRefundArgs struct {
}

type GetRefundReply struct {
	Refund uint64
}

type GetCommittedStateArgs struct {
	Address common.Address
	Key     common.Hash
}

type GetCommittedStateReply struct {
	Value common.Hash
}

type GetStateArgs struct {
	Address common.Address
	Key     common.Hash
}

type GetStateReply struct {
	Value common.Hash
}

type SetStateArgs struct {
	Address common.Address
	Key     common.Hash
	Value   common.Hash
}

type SetStateReply struct {
}

type GetTransientStateArgs struct {
	Address common.Address
	Key     common.Hash
}

type GetTransientStateReply struct {
	Value common.Hash
}

type SetTransientStateArgs struct {
	Address common.Address
	Key     common.Hash
	Value   common.Hash
}

type SetTransientStateReply struct {
}

type SelfDestructArgs struct {
	Address common.Address
}

type SelfDestructReply struct {
}

type HasSelfDestructedArgs struct {
	Address common.Address
}

type HasSelfDestructedReply struct {
	HasSelfDestructed bool
}

type Selfdestruct6780Args struct {
	Address common.Address
}

type Selfdestruct6780Reply struct {
}

type ExistArgs struct {
	Address common.Address
}

type ExistReply struct {
	Exists bool
}

type EmptyArgs struct {
	Address common.Address
}

type EmptyReply struct {
	IsEmpty bool
}

type AddressInAccessListArgs struct {
	Address common.Address
}

type AddressInAccessListReply struct {
	IsInAccessList bool
}

type SlotInAccessListArgs struct {
	Address common.Address
	Slot    common.Hash
}

type SlotInAccessListReply struct {
	AddressOk bool
	SlotOk    bool
}

type AddAddressToAccessListArgs struct {
	Address common.Address
}

type AddAddressToAccessListReply struct {
}

type AddSlotToAccessListArgs struct {
	Address common.Address
	Slot    common.Hash
}

type AddSlotToAccessListReply struct {
}

type PrepareArgs struct {
	Rules       params.Rules
	Sender      common.Address
	Coinbase    common.Address
	Dest        *common.Address
	Precompiles []common.Address
	TxAccesses  ethtypes.AccessList
}

type PrepareReply struct {
}

type RevertToSnapshotArgs struct {
	Snapshot int
}

type RevertToSnapshotReply struct {
}

type SnapshotArgs struct {
}

type SnapshotReply struct {
	Snapshot int
}

type AddLogArgs struct {
	Log *ethtypes.Log
}

type AddLogReply struct {
}

type AddPreimageArgs struct {
	Hash     common.Hash
	Preimage []byte
}

type AddPreimageReply struct {
}
