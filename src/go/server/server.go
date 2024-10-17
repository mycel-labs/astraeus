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

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	tas "github.com/mycel-labs/astraeus/src/go/contract/transferable_account_store"
	framework "github.com/mycel-labs/astraeus/src/go/framework"
	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
)

type server struct {
	pb.UnimplementedAccountServiceServer
	fr                  *framework.Framework
	taStoreContract     *framework.Contract
	taStoreContractBind *tas.Contract
	auth                *bind.TransactOpts
	client              *ethclient.Client
}

const (
	grpcPort            = ":50052"
	restPort            = ":8080"
	taStoreContractPath = "TransferableAccountStore.sol/TransferableAccountStore.json"
)

func checkEnvVars(fatal bool) {
	taStoreContractAddr := os.Getenv("TA_STORE_CONTRACT_ADDRESS")
	privKey := os.Getenv("PRIVATE_KEY")

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

func NewServer(rpcUrl string, privateKey string, taStoreContractAddr string) (*server, error) {

	fr := framework.New(framework.WithCustomConfig(privateKey, rpcUrl))

	taStoreContract, err := fr.Suave.BindToExistingContract(common.HexToAddress(taStoreContractAddr), taStoreContractPath)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to existing contract: %v", err)
	}

	client, err := ethclient.Dial(rpcUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to dial RPC: %v", err)
	}

	taStoreContractBind, err := tas.NewContract(taStoreContract.Contract.Address(), client)
	if err != nil {
		return nil, fmt.Errorf("failed to bind to contract: %v", err)
	}

	chainId, err := client.ChainID(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to get chain ID: %v", err)
	}

	priv, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert hex to private key: %v", err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(priv, chainId)
	if err != nil {
		return nil, fmt.Errorf("failed to create transactor: %v", err)
	}

	return &server{fr: fr, taStoreContract: taStoreContract, taStoreContractBind: taStoreContractBind, auth: auth, client: client}, nil
}

func StartServer(wg *sync.WaitGroup) {
	defer wg.Done()

	// Ensure env variables are set
	checkEnvVars(true)
	// Setup framework and contract
	rpcUrl := os.Getenv("RPC_URL")
	privateKeyStr := os.Getenv("PRIVATE_KEY")
	taStoreContractAddr := os.Getenv("TA_STORE_CONTRACT_ADDRESS")

	s, err := NewServer(rpcUrl, privateKeyStr, taStoreContractAddr)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// gRPC server
	gprcs := grpc.NewServer()
	lis, err := net.Listen("tcp", grpcPort)
	if err != nil {
		log.Fatalf("Failed to listen for gRPC server: %v", err)
	}
	pb.RegisterAccountServiceServer(gprcs, s)
	log.Println("gRPC server started on", grpcPort)

	go func() {
		if err := gprcs.Serve(lis); err != nil {
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
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		log.Printf("err: %v", err)
		return nil, err
	}

	tx, err := s.taStoreContractBind.TransferAccount(s.auth, *sig, req.Base.AccountId, common.HexToAddress(req.To))
	if err != nil {
		log.Printf("err: %v", err)
		return nil, err
	}

	// Wait for the transaction to be mined
	receipt, err := bind.WaitMined(ctx, s.client, tx)
	if err != nil {
		log.Printf("error waiting for transaction to be mined: %v", err)
		return nil, err
	}

	// Check if the transaction was successful
	if receipt.Status != types.ReceiptStatusSuccessful {
		return nil, fmt.Errorf("transaction failed")
	}

	return &pb.TransferAccountResponse{TxHash: tx.Hash().Hex()}, nil
}

func (s *server) DeleteAccount(ctx context.Context, req *pb.DeleteAccountRequest) (*pb.DeleteAccountResponse, error) {
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		log.Printf("err: %v", err)
		return nil, err
	}
	tx, err := s.taStoreContractBind.DeleteAccount(s.auth, *sig, req.Base.AccountId)
	if err != nil {
		log.Printf("err: %v", err)
		return nil, err
	}

	return &pb.DeleteAccountResponse{TxHash: tx.Hash().Hex()}, nil
}

func (s *server) UnlockAccount(ctx context.Context, req *pb.UnlockAccountRequest) (*pb.UnlockAccountResponse, error) {
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		log.Printf("err: %v", err)
		return nil, err
	}

	tx, err := s.taStoreContractBind.UnlockAccount(s.auth, *sig, req.Base.AccountId)
	if err != nil {
		log.Printf("err: %v", err)
		return nil, err
	}

	return &pb.UnlockAccountResponse{TxHash: tx.Hash().Hex()}, nil
}

func (s *server) ApproveAddress(ctx context.Context, req *pb.ApproveAddressRequest) (*pb.ApproveAddressResponse, error) {
	sig, err := populateTimedSignature(req.Base.Proof)
	if err != nil {
		return nil, err
	}

	tx, err := s.taStoreContractBind.ApproveAddress(s.auth, *sig, req.Base.AccountId, common.HexToAddress(req.Address))
	if err != nil {
		log.Printf("err: %v", err)
		return nil, err
	}

	return &pb.ApproveAddressResponse{TxHash: tx.Hash().Hex()}, nil
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
		AccountId          [16]uint8      `json:"accountId"`
		Owner              common.Address `json:"owner"`
		PublicKeyX         *big.Int       `json:"publicKeyX"`
		PublicKeyY         *big.Int       `json:"publicKeyY"`
		SignatureAlgorithm uint8          `json:"signatureAlgorithm"`
		IsLocked           bool           `json:"isLocked"`
	})
	if !ok {
		return nil, status.Errorf(codes.InvalidArgument, "account data type is invalid or unexpected")
	}

	// check if the account exists
	if ac.Owner == (common.Address{}) {
		return nil, status.Errorf(codes.NotFound, "account not found")
	}

	pbac := &pb.Account{
		AccountId:          req.AccountId,
		Owner:              ac.Owner.Hex(),
		PublicKeyX:         ac.PublicKeyX.Text(16),
		PublicKeyY:         ac.PublicKeyY.Text(16),
		SignatureAlgorithm: pb.SignatureAlgorithm(ac.SignatureAlgorithm),
		IsLocked:           ac.IsLocked,
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

func populateTimedSignature(sig *pb.TimedSignature) (*tas.SignatureVerifierTimedSignature, error) {
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

	return &tas.SignatureVerifierTimedSignature{
		ValidFor:    sig.ValidFor,
		MessageHash: messageHashBytes,
		Signature:   signature,
		Signer:      common.HexToAddress(sig.Signer),
	}, nil
}
