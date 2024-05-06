package keeper

import (
	"context"
	"math/big"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/evmos/ethermint/x/evm/statedb"
	"github.com/evmos/ethermint/x/evm/types"
	"github.com/pkg/errors"
)

// ------------------------------
// StateDB queries for TEE party
// ------------------------------

// GetHashStateDB queries hash in statedb for sgx
func (k Keeper) StateDBGetHash(_ context.Context, req *types.GetHashRequest) (*types.GetHashResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	hash := k.GetHashFn(*ctx)(req.Height)

	res := &types.GetHashResponse{
		Hash: hash.Bytes(),
	}

	return res, nil
}

// AddBalanceStateDB add balance in statedb for sgx
func (k Keeper) StateDBAddBalance(_ context.Context, req *types.AddBalanceRequest) (*types.AddBalanceResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	addr := sdk.AccAddress(req.Address)
	err := k.AddBalance(*ctx, addr, req.Amount)
	if err != nil {
		return nil, err
	}

	return &types.AddBalanceResponse{}, nil
}

// SubBalanceStateDB sub balance in statedb for sgx
func (k Keeper) StateDBSubBalance(_ context.Context, req *types.SubBalanceRequest) (*types.SubBalanceResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	addr := sdk.AccAddress(req.Address)
	err := k.SubBalance(*ctx, addr, req.Amount)
	if err != nil {
		return nil, err
	}

	return &types.SubBalanceResponse{}, nil
}

// SubBalanceStateDB sets the balances in statedb for sgx
func (k Keeper) StateDBSetBalance(_ context.Context, req *types.SetBalanceRequest) (*types.SetBalanceResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	addr := common.BytesToAddress(req.Address)
	amount, ok := new(big.Int).SetString(req.Amount, 10)
	if !ok {
		return nil, errors.Wrapf(types.ErrInvalidAmount, "invalid set balance amount: %s", req.Amount)
	}
	err := k.SetBalance(*ctx, addr, amount, req.Denom)
	if err != nil {
		return nil, err
	}

	return &types.SetBalanceResponse{}, nil
}

// GetBalanceStateDB queries balance in statedb for sgx
func (k Keeper) StateDBGetBalance(_ context.Context, req *types.GetBalanceRequest) (*types.GetBalanceResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	addr := sdk.AccAddress(req.Address)
	balance := k.GetBalance(*ctx, addr, req.Denom)

	return &types.GetBalanceResponse{
		Balance: balance.String(),
	}, nil
}

// GetAccountStateDB queries account in statedb for sgx
func (k Keeper) StateDBGetAccount(_ context.Context, req *types.GetAccountRequest) (*types.GetAccountResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	addr := common.BytesToAddress(req.Address)
	account := k.GetAccount(*ctx, addr)
	var protoAccount *types.Account
	if account != nil {
		protoAccount = &types.Account{
			Nonce:    account.Nonce,
			CodeHash: account.CodeHash,
		}
	}

	return &types.GetAccountResponse{
		Account: protoAccount,
	}, nil
}

// GetStateStateDB queries state in statedb for sgx
func (k Keeper) StateDBGetState(_ context.Context, req *types.GetStateRequest) (*types.GetStateResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	addr := common.BytesToAddress(req.Address)
	key := common.BytesToHash(req.Key)

	hash := k.GetState(*ctx, addr, key)
	return &types.GetStateResponse{
		Hash: hash.Bytes(),
	}, nil
}

// GetCodeStateDB queries code in statedb for sgx
func (k Keeper) StateDBGetCode(_ context.Context, req *types.GetCodeRequest) (*types.GetCodeResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	codeHash := common.BytesToHash(req.CodeHash)

	code := k.GetCode(*ctx, codeHash)
	return &types.GetCodeResponse{
		Code: code,
	}, nil
}

// SetAccountStateDB sets account in statedb for sgx
func (k Keeper) StateDBSetAccount(_ context.Context, req *types.SetAccountRequest) (*types.SetAccountResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	addr := common.BytesToAddress(req.Address)

	err := k.SetAccount(*ctx, addr, statedb.Account{
		Nonce:    req.Account.Nonce,
		CodeHash: req.Account.CodeHash,
	})
	if err != nil {
		return nil, err
	}

	return &types.SetAccountResponse{}, nil
}

// SetStateStateDB sets state in statedb for sgx
func (k Keeper) StateDBSetState(_ context.Context, req *types.SetStateRequest) (*types.SetStateResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	k.SetState(*ctx, common.BytesToAddress(req.Address), common.BytesToHash(req.Key), req.Value)
	return &types.SetStateResponse{}, nil
}

// SetCodeStateDB sets code in statedb for sgx
func (k Keeper) StateDBSetCode(_ context.Context, req *types.SetCodeRequest) (*types.SetCodeResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	k.SetCode(*ctx, req.CodeHash, req.Code)
	return &types.SetCodeResponse{}, nil
}

// DeleteAccountStateDB delete account in statedb for sgx
func (k Keeper) StateDBDeleteAccount(_ context.Context, req *types.DeleteAccountRequest) (*types.DeleteAccountResponse, error) {
	ctx := k.sdkCtxs[req.HandlerId]
	if ctx == nil {
		panic("context invalid")
	}

	err := k.DeleteAccount(*ctx, common.BytesToAddress(req.Address))
	return &types.DeleteAccountResponse{}, err
}
