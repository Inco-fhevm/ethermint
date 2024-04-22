package keeper

import (
	"context"
	"encoding/json"
	"math/big"
	"net"

	"cosmossdk.io/log"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/params"
	evmtypes "github.com/evmos/ethermint/x/evm/types"
	sgxtypes "github.com/evmos/ethermint/x/sgx/types"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
)

type sgxGrpcClient struct {
	logger  log.Logger
	querier sgxtypes.QueryServiceClient
}

func newSgxGrpcClient(logger log.Logger) (*sgxGrpcClient, error) {
	// Create a new InterfaceRegistry
	interfaceRegistry := codectypes.NewInterfaceRegistry()
	evmtypes.RegisterInterfaces(interfaceRegistry)

	// Set the node
	rpcConn, err := grpc.Dial("localhost:9092",
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, url string) (net.Conn, error) {
			return net.Dial("tcp", url)
		}),
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to connect to sgx gRPC")
	}
	querier := sgxtypes.NewQueryServiceClient(rpcConn)

	return &sgxGrpcClient{querier: querier, logger: logger}, nil
}

// GetParams is here to satisfy the interface, but should never be called by
// the SGX binary to the Cosmos node.
func (c sgxGrpcClient) GetParams(sdk.Context) evmtypes.Params {
	panic("dead code")
}

func (c *sgxGrpcClient) PrepareTx(args PrepareTxArgs) (*sgxtypes.PrepareTxResponse, error) {
	ctx := context.Background()
	headerBytes, err := json.Marshal(args.Header)
	if err != nil {
		return nil, err
	}

	msgBytes, err := json.Marshal(args.Msg)
	if err != nil {
		return nil, err
	}

	evmConfigBytes, err := json.Marshal(args.EvmConfig)
	if err != nil {
		return nil, err
	}

	req := &sgxtypes.PrepareTxRequest{
		TxHash: args.TxHash,
		// Header is the Tendermint header of the block in which the transaction
		// will be executed.
		Header: headerBytes,
		// Msg is the EVM transaction message to run on the EVM.
		Msg: msgBytes,
		// EvmConfig is the EVM configuration to set.
		EvmConfig: evmConfigBytes,
	}

	resp, err := c.querier.PrepareTx(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to prepare tx")
	}

	c.logger.Info("Called gRPC PrepareTx")

	return resp, nil
}

func (c *sgxGrpcClient) Call(handlerId uint64, caller vm.AccountRef, addr common.Address, input []byte, gas uint64, value *big.Int) (*sgxtypes.CallResponse, error) {
	ctx := context.Background()
	callerBytes, err := json.Marshal(caller)
	if err != nil {
		return nil, err
	}

	valueBytes := value.Bytes()
	addrHex := addr.Hex()
	req := &sgxtypes.CallRequest{
		HandlerId: handlerId,
		Caller:    callerBytes,
		Addr:      addrHex,
		Input:     input,
		Gas:       gas,
		Value:     valueBytes,
	}

	resp, err := c.querier.Call(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to call")
	}

	c.logger.Info("Called gRPC Call")

	return resp, nil
}

func (c *sgxGrpcClient) Create(handlerId uint64, caller vm.AccountRef, code []byte, gas uint64, value *big.Int) (*sgxtypes.CreateResponse, error) {
	ctx := context.Background()
	callerBytes, err := json.Marshal(caller)
	if err != nil {
		return nil, err
	}

	valueBytes := value.Bytes()
	req := &sgxtypes.CreateRequest{
		HandlerId: handlerId,
		Caller:    callerBytes,
		Code:      code,
		Gas:       gas,
		Value:     valueBytes,
	}

	resp, err := c.querier.Create(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create")
	}

	c.logger.Info("Called gRPC Create")

	return resp, nil
}

func (c *sgxGrpcClient) Commit(handlerId uint64, commit bool) (*sgxtypes.CommitResponse, error) {
	ctx := context.Background()
	req := &sgxtypes.CommitRequest{
		HandlerId: handlerId,
		Commit:    commit,
	}

	resp, err := c.querier.Commit(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to commit")
	}

	c.logger.Info("Called gRPC Commit")

	return resp, nil
}

func (c *sgxGrpcClient) StateDBAddBalance(handlerId uint64, sender vm.AccountRef, msg core.Message, leftOverGas uint64) (*sgxtypes.StateDBAddBalanceResponse, error) {
	ctx := context.Background()
	senderBytes, err := json.Marshal(sender)
	if err != nil {
		return nil, err
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	req := &sgxtypes.StateDBAddBalanceRequest{
		HandlerId:   handlerId,
		Caller:      senderBytes,
		Msg:         msgBytes,
		LeftOverGas: leftOverGas,
	}

	resp, err := c.querier.StateDBAddBalance(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to add balance")
	}

	c.logger.Info("Called gRPC AddBalance")

	return resp, nil
}

func (c *sgxGrpcClient) StateDBSubBalance(handlerId uint64, sender vm.AccountRef, msg core.Message) (*sgxtypes.StateDBSubBalanceResponse, error) {
	ctx := context.Background()
	senderBytes, err := json.Marshal(sender)
	if err != nil {
		return nil, err
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	req := &sgxtypes.StateDBSubBalanceRequest{
		HandlerId: handlerId,
		Caller:    senderBytes,
		Msg:       msgBytes,
	}

	resp, err := c.querier.StateDBSubBalance(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to sub balance")
	}

	c.logger.Info("Called gRPC SubBalance")

	return resp, nil
}

func (c *sgxGrpcClient) StateDBSetNonce(handlerId uint64, caller vm.AccountRef, nonce uint64) (*sgxtypes.StateDBSetNonceResponse, error) {
	ctx := context.Background()
	callerBytes, err := json.Marshal(caller)
	if err != nil {
		return nil, err
	}

	req := &sgxtypes.StateDBSetNonceRequest{
		HandlerId: handlerId,
		Caller:    callerBytes,
		Nonce:     nonce,
	}

	resp, err := c.querier.StateDBSetNonce(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to set nonce")
	}

	c.logger.Info("Called gRPC Set Nonce")

	return resp, nil
}

func (c *sgxGrpcClient) StateDBIncreaseNonce(handlerId uint64, sender vm.AccountRef, msg core.Message) (*sgxtypes.StateDBIncreaseNonceResponse, error) {
	ctx := context.Background()
	senderBytes, err := json.Marshal(sender)
	if err != nil {
		return nil, err
	}

	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	req := &sgxtypes.StateDBIncreaseNonceRequest{
		HandlerId: handlerId,
		Caller:    senderBytes,
		Msg:       msgBytes,
	}

	resp, err := c.querier.StateDBIncreaseNonce(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to increase nonce")
	}

	c.logger.Info("Called gRPC Increase Nonce")

	return resp, nil
}

func (c *sgxGrpcClient) StateDBPrepare(handlerId uint64, msg core.Message, rules params.Rules) (*sgxtypes.StateDBPrepareResponse, error) {
	ctx := context.Background()
	msgBytes, err := json.Marshal(msg)
	if err != nil {
		return nil, err
	}

	rulesBytes, err := json.Marshal(rules)
	if err != nil {
		return nil, err
	}

	req := &sgxtypes.StateDBPrepareRequest{
		HandlerId: handlerId,
		Msg:       msgBytes,
		Rules:     rulesBytes,
	}

	resp, err := c.querier.StateDBPrepare(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to StateDb prepare")
	}

	c.logger.Info("Called gRPC StateDb Prepare")

	return resp, nil
}

func (c *sgxGrpcClient) StateDBGetRefund(handlerId uint64) (*sgxtypes.StateDBGetRefundResponse, error) {
	ctx := context.Background()
	req := &sgxtypes.StateDBGetRefundRequest{
		HandlerId: handlerId,
	}

	resp, err := c.querier.StateDBGetRefund(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to StateDb Get refund")
	}

	c.logger.Info("Called gRPC StateDb Get refund")

	return resp, nil
}

func (c *sgxGrpcClient) StateDBGetLogs(handlerId uint64) (*sgxtypes.StateDBGetLogsResponse, error) {
	ctx := context.Background()
	req := &sgxtypes.StateDBGetLogsRequest{
		HandlerId: handlerId,
	}

	resp, err := c.querier.StateDBGetLogs(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to StateDb get logs")
	}

	c.logger.Info("Called gRPC StateDb get logs")

	return resp, nil
}
