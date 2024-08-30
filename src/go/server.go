package main

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	framework "github.com/mycel-labs/transferable-account/src/go/framework"
	pb "github.com/mycel-labs/transferable-account/src/go/pb"
)

type server struct {
	pb.UnimplementedAccountServiceServer
	fr              *framework.Framework
	taStoreContract *framework.Contract
}

type TimedSignature struct {
	ValidFor    uint64
	MessageHash [32]byte
	Signature   []byte
	Signer      common.Address
}

func (s *server) CreateAccount(ctx context.Context, req *pb.CreateAccountRequest) (*pb.BytesResponse, error) {
	var result *types.Receipt
	var err error
	sig := populateTimedSignature(req.Proof)

	// Use an anonymous function to handle potential panics
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Convert panic to error
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		result = s.taStoreContract.SendConfidentialRequest("createAccount", []interface{}{sig}, nil)
	}()

	// Check if a panic occurred and was converted to an error
	if err != nil {
		return nil, err
	}

	// Check if the transaction was successful
	if result == nil {
		return nil, fmt.Errorf("failed to create account")
	}
	caEvent, err := s.taStoreContract.Abi.Events["AccountCreated"].ParseLog(result.Logs[0])
	if err != nil {
		panic(err)
	}
	accountId := caEvent["accountId"].(string)

	return &pb.BytesResponse{Data: []byte(accountId)}, nil
}

func (s *server) TransferAccount(ctx context.Context, req *pb.TransferAccountRequest) (*pb.BytesResponse, error) {
	var result *types.Receipt
	var err error
	sig := populateTimedSignature(req.Base.Proof)

	// Use an anonymous function to handle potential panics
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Convert panic to error
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		// Execute the confidential request
		result = s.taStoreContract.SendConfidentialRequest("transferAccount", []interface{}{sig, req.Base.AccountId, common.HexToAddress(req.To)}, nil)
	}()

	// Check if a panic occurred and was converted to an error
	if err != nil {
		return nil, err
	}

	// Check if the transaction was successful
	if result == nil {
		return nil, fmt.Errorf("failed to transfer account")
	}

	// Return the account ID as a response
	return &pb.BytesResponse{Data: []byte(req.Base.AccountId)}, nil
}

func (s *server) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.BytesResponse, error) {
	var result *types.Receipt
	var err error
	sig := populateTimedSignature(req.Base.Proof)

	// Use an anonymous function to handle potential panics
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Convert panic to error
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		// Execute the confidential request
		result = s.taStoreContract.SendConfidentialRequest("deleteAccount", []interface{}{sig, req.Base.AccountId}, nil)
	}()

	// Check if a panic occurred and was converted to an error
	if err != nil {
		return nil, err
	}

	// Check if the transaction was successful
	if result == nil {
		return nil, fmt.Errorf("failed to delete account")
	}

	// Return the account ID as a response
	return &pb.BytesResponse{Data: []byte(req.Base.AccountId)}, nil
}

// func (s *server) UnlockAccount(ctx context.Context, req *pb.UnlockAccountRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

func (s *server) ApproveAddress(ctx context.Context, req *pb.ApproveAddressRequest) (*pb.BytesResponse, error) {
	var result *types.Receipt
	var err error
	sig := populateTimedSignature(req.Base.Proof)

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		result = s.taStoreContract.SendConfidentialRequest("approveAddress", []interface{}{sig, req.Base.AccountId, common.HexToAddress(req.Address)}, nil)
	}()

	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, fmt.Errorf("failed to approve address")
	}

	return &pb.BytesResponse{Data: []byte(req.Base.AccountId)}, nil
}

func (s *server) RevokeApproval(ctx context.Context, req *pb.RevokeApprovalRequest) (*pb.BoolResponse, error) {
	var result *types.Receipt
	var err error
	sig := populateTimedSignature(req.Base.Proof)

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		result = s.taStoreContract.SendConfidentialRequest("revokeApproval", []interface{}{sig, req.Base.AccountId, common.HexToAddress(req.Address)}, nil)
	}()

	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, fmt.Errorf("failed to revoke approval")
	}

	return &pb.BoolResponse{Result: true}, nil
}

// func (s *server) Sign(ctx context.Context, req *pb.SignRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

func (s *server) GetAccount(ctx context.Context, req *pb.AccountIdRequest) (*pb.AccountResponse, error) {
	result := s.taStoreContract.Call("getAccount", []interface{}{req.AccountId})

	if len(result) == 0 || result[0] == nil {
		return nil, fmt.Errorf("empty result")
	}

	ac, ok := result[0].(struct {
		AccountId  [16]uint8      `json:"accountId"`
		Owner      common.Address `json:"owner"`
		PublicKeyX *big.Int       `json:"publicKeyX"`
		PublicKeyY *big.Int       `json:"publicKeyY"`
		Curve      uint8          `json:"curve"`
		IsLocked   bool           `json:"isLocked"`
	})
	if !ok {
		return nil, fmt.Errorf("account data type is unexpected")
	}

	// check if the account exists
	if ac.Owner == (common.Address{}) {
		return nil, fmt.Errorf("account not found")
	}

	pbac := &pb.Account{
		AccountId:  req.AccountId,
		Owner:      ac.Owner.Hex(),
		PublicKeyX: ac.PublicKeyX.Uint64(),
		PublicKeyY: ac.PublicKeyY.Uint64(),
		Curve:      pb.Curve(ac.Curve),
		IsLocked:   ac.IsLocked,
	}

	return &pb.AccountResponse{Account: pbac}, nil
}

func (s *server) IsApproved(ctx context.Context, req *pb.AccountIdToAddressRequest) (*pb.BoolResponse, error) {
	result := s.taStoreContract.Call("isApproved", []interface{}{req.AccountId, common.HexToAddress(req.Address)})

	if len(result) == 0 || result[0] == nil {
		return nil, fmt.Errorf("empty result")
	}

	approved, ok := result[0].(bool)
	if !ok {
		return nil, fmt.Errorf("approved data type is unexpected")
	}

	return &pb.BoolResponse{Result: approved}, nil
}

func (s *server) IsOwner(ctx context.Context, req *pb.AccountIdToAddressRequest) (*pb.BoolResponse, error) {
	result := s.taStoreContract.Call("isOwner", []interface{}{req.AccountId, common.HexToAddress(req.Address)})

	if len(result) == 0 || result[0] == nil {
		return nil, fmt.Errorf("empty result")
	}

	isOwner, ok := result[0].(bool)
	if !ok {
		return nil, fmt.Errorf("isOwner data type is unexpected")
	}

	return &pb.BoolResponse{Result: isOwner}, nil
}

func (s *server) IsAccountLocked(ctx context.Context, req *pb.AccountIdRequest) (*pb.BoolResponse, error) {
	result := s.taStoreContract.Call("isAccountLocked", []interface{}{req.AccountId})

	if len(result) == 0 || result[0] == nil {
		return nil, fmt.Errorf("empty result")
	}

	isLocked, ok := result[0].(bool)
	if !ok {
		return nil, fmt.Errorf("isLocked data type is unexpected")
	}

	return &pb.BoolResponse{Result: isLocked}, nil
}

/*
** Helper functions
 */

func convertMessageHash(messageHash []byte) [32]byte {
	var messageHashBytes [32]byte
	copy(messageHashBytes[:], messageHash)
	return messageHashBytes
}

func populateTimedSignature(sig *pb.TimedSignature) *TimedSignature {
	return &TimedSignature{
		ValidFor:    sig.ValidFor,
		MessageHash: convertMessageHash(sig.MessageHash),
		Signature:   sig.Signature,
		Signer:      common.HexToAddress(sig.Signer),
	}
}
