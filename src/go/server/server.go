package server

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	framework "github.com/mycel-labs/astraeus/src/go/framework"
	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
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

const (
	grpcPort            = ":50052"
	restPort            = ":8080"
	taStoreContractPath = "TransferableAccountStore.sol/TransferableAccountStore.json"
)

var (
	privKey             string
	taStoreContractAddr string
)

func checkEnvVars(fatal bool) {
	taStoreContractAddr = os.Getenv("TA_STORE_CONTRACT_ADDRESS")
	privKey = os.Getenv("PRIVATE_KEY")

	if taStoreContractAddr == "" {
		if fatal {
			log.Fatalf("error: TA_STORE_CONTRACT_ADDRESS is not set")
		} else {
			log.Printf("warning: TA_STORE_CONTRACT_ADDRESS is not set")
		}
	}
	if privKey == "" {
		if fatal {
			log.Fatalf("error: PRIVATE_KEY is not set")
		} else {
			log.Printf("warning: PRIVATE_KEY is not set")
		}
	}
}

func init() {
	checkEnvVars(false)
}

func StartServer(wg *sync.WaitGroup) {
	defer wg.Done()

	// Ensure env variables are set
	checkEnvVars(true)

	// Setup framework and contract
	fr := framework.New(framework.WithCustomConfig(os.Getenv("PRIVATE_KEY"), os.Getenv("RPC_URL")))
	taStoreContract, err := fr.Suave.BindToExistingContract(common.HexToAddress(taStoreContractAddr), taStoreContractPath)
	if err != nil {
		log.Fatalf("Failed to bind to existing contract: %v", err)
	}

	// gRPC server
	s := grpc.NewServer()
	lis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen for gRPC server: %v", err)
	}
	pb.RegisterAccountServiceServer(s, &server{fr: fr, taStoreContract: taStoreContract})
	log.Println("gRPC server started on", grpcPort)

	go func() {
		if err := s.Serve(lis); err != nil {
			log.Fatalf("Failed to serve gRPC server: %v", err)
		}
	}()

	// Set up REST proxy
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	err = pb.RegisterAccountServiceHandlerFromEndpoint(ctx, mux, fmt.Sprintf("localhost%s", grpcPort), opts)
	if err != nil {
		log.Fatalf("Failed to register REST proxy: %v", err)
	}

	// Start HTTP server
	log.Println("REST proxy started on :8080")
	if err := http.ListenAndServe(restPort, mux); err != nil {
		log.Fatalf("Failed to serve REST proxy: %v", err)
	}
}
func (s *server) CreateAccount(ctx context.Context, req *pb.CreateAccountRequest) (*pb.CreateAccountResponse, error) {
	var result *types.Receipt
	var err error
	sig, err := populateTimedSignature(req.Proof)
	if err != nil {
		return nil, err
	}

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

	return &pb.CreateAccountResponse{TxHash: result.TxHash.Hex(), AccountId: accountId}, nil
}

func (s *server) TransferAccount(ctx context.Context, req *pb.TransferAccountRequest) (*pb.TransferAccountResponse, error) {
	var result *types.Receipt
	var err error
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		return nil, err
	}

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

	return &pb.TransferAccountResponse{TxHash: result.TxHash.Hex()}, nil
}

func (s *server) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.DeleteAccountResponse, error) {
	var result *types.Receipt
	var err error
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		return nil, err
	}

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

	return &pb.DeleteAccountResponse{TxHash: result.TxHash.Hex()}, nil
}

func (s *server) UnlockAccount(ctx context.Context, req *pb.UnlockAccountRequest) (*pb.UnlockAccountResponse, error) {
	var result *types.Receipt
	var err error
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		return nil, err
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		result = s.taStoreContract.SendConfidentialRequest("unlockAccount", []interface{}{sig, req.Base.AccountId}, nil)
	}()

	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, fmt.Errorf("failed to unlock account")
	}

	return &pb.UnlockAccountResponse{TxHash: result.TxHash.Hex()}, nil
}

func (s *server) ApproveAddress(ctx context.Context, req *pb.ApproveAddressRequest) (*pb.ApproveAddressResponse, error) {
	var result *types.Receipt
	var err error
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		return nil, err
	}

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

	return &pb.ApproveAddressResponse{TxHash: result.TxHash.Hex()}, nil
}

func (s *server) RevokeApproval(ctx context.Context, req *pb.RevokeApprovalRequest) (*pb.RevokeApprovalResponse, error) {
	var result *types.Receipt
	var err error
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		return nil, err
	}

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

	return &pb.RevokeApprovalResponse{TxHash: result.TxHash.Hex()}, nil
}

func (s *server) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
	var result *types.Receipt
	var err error
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		return nil, err
	}

	data, err := hex.DecodeString(req.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %v", err)
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		result = s.taStoreContract.SendConfidentialRequest("sign", []interface{}{sig, req.Base.AccountId, data}, nil)
	}()

	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, fmt.Errorf("failed to sign")
	}

	caEvent, err := s.taStoreContract.Abi.Events["Signature"].ParseLog(result.Logs[0])
	if err != nil {
		panic(err)
	}
	signature := caEvent["signature"].([]byte)

	return &pb.SignResponse{
		TxHash:    result.TxHash.Hex(),
		Signature: hex.EncodeToString(signature),
	}, nil
}

func (s *server) GetAccount(ctx context.Context, req *pb.GetAccountRequest) (*pb.GetAccountResponse, error) {
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
		return nil, status.Errorf(codes.InvalidArgument, "account data type is invalid or unexpected")
	}

	// check if the account exists
	if ac.Owner == (common.Address{}) {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	pbac := &pb.Account{
		AccountId:  req.AccountId,
		Owner:      ac.Owner.Hex(),
		PublicKeyX: ac.PublicKeyX.Text(16),
		PublicKeyY: ac.PublicKeyY.Text(16),
		Curve:      pb.Curve(ac.Curve),
		IsLocked:   ac.IsLocked,
	}

	return &pb.GetAccountResponse{Account: pbac}, nil
}

func (s *server) IsApproved(ctx context.Context, req *pb.IsApprovedRequest) (*pb.IsApprovedResponse, error) {
	result := s.taStoreContract.Call("isApproved", []interface{}{req.AccountId, common.HexToAddress(req.Address)})

	if len(result) == 0 || result[0] == nil {
		return nil, fmt.Errorf("empty result")
	}

	approved, ok := result[0].(bool)
	if !ok {
		return nil, fmt.Errorf("approved data type is unexpected")
	}

	return &pb.IsApprovedResponse{Result: approved}, nil
}

func (s *server) IsOwner(ctx context.Context, req *pb.IsOwnerRequest) (*pb.IsOwnerResponse, error) {
	result := s.taStoreContract.Call("isOwner", []interface{}{req.AccountId, common.HexToAddress(req.Address)})

	if len(result) == 0 || result[0] == nil {
		return nil, fmt.Errorf("empty result")
	}

	isOwner, ok := result[0].(bool)
	if !ok {
		return nil, fmt.Errorf("isOwner data type is unexpected")
	}

	return &pb.IsOwnerResponse{Result: isOwner}, nil
}

func (s *server) IsAccountLocked(ctx context.Context, req *pb.IsAccountLockedRequest) (*pb.IsAccountLockedResponse, error) {
	result := s.taStoreContract.Call("isAccountLocked", []interface{}{req.AccountId})

	if len(result) == 0 || result[0] == nil {
		return nil, fmt.Errorf("empty result")
	}

	isLocked, ok := result[0].(bool)
	if !ok {
		return nil, fmt.Errorf("isLocked data type is unexpected")
	}

	return &pb.IsAccountLockedResponse{Result: isLocked}, nil
}

/*
** Helper functions
 */

func convertMessageHash(messageHash []byte) ([32]byte, error) {
	var messageHashBytes [32]byte
	if len(messageHash) != 32 {
		return messageHashBytes, fmt.Errorf("invalid message hash length: expected 32, got %d", len(messageHash))
	}
	copy(messageHashBytes[:], messageHash)
	return messageHashBytes, nil
}

func populateTimedSignature(sig *pb.TimedSignature) (*TimedSignature, error) {
	messageHash, err := hex.DecodeString(sig.MessageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode message hash: %v", err)
	}

	signature, err := hex.DecodeString(sig.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %v", err)
	}

	messageHashBytes, err := convertMessageHash(messageHash)
	if err != nil {
		return nil, fmt.Errorf("failed to convert message hash: %v", err)
	}

	return &TimedSignature{
		ValidFor:    sig.ValidFor,
		MessageHash: messageHashBytes,
		Signature:   signature,
		Signer:      common.HexToAddress(sig.Signer),
	}, nil
}
