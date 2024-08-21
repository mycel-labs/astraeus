package main

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	framework "github.com/mycel-labs/transferable-account/framework"

	pb "github.com/mycel-labs/transferable-account/pb"
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

// func (s *server) CreateAccount(ctx context.Context, req *pb.CreateAccountRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

// func (s *server) TransferAccount(ctx context.Context, req *pb.TransferAccountRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

// func (s *server) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

// func (s *server) LockAccount(ctx context.Context, req *pb.LockAccountRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

// func (s *server) UnlockAccount(ctx context.Context, req *pb.UnlockAccountRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

// func (s *server) ApproveAddress(ctx context.Context, req *pb.ApproveAddressRequest) (*pb.BytesResponse, error) {
// 	return &pb.BytesResponse{}, nil
// }

// func (s *server) RevokeApproval(ctx context.Context, req *pb.RevokeApprovalRequest) (*pb.BoolResponse, error) {
// 	return &pb.BoolResponse{}, nil
// }

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

// func (s *server) IsOwner(ctx context.Context, req *pb.ApproveAddressRequest) (*pb.BoolResponse, error) {
// 	return &pb.BoolResponse{}, nil
// }

// func (s *server) IsLocked(ctx context.Context, req *pb.AccountIdRequest) (*pb.BoolResponse, error) {
// 	return &pb.BoolResponse{}, nil
// }

// func (s *server) GetLock(ctx context.Context, req *pb.AccountIdRequest) (*pb.TimeLockResponse, error) {
// 	return &pb.TimeLockResponse{}, nil
// }
