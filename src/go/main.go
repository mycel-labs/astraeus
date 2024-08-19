package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/suave/sdk"
	framework "github.com/mycel-labs/transferable-account/framework"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/mycel-labs/transferable-account/pb"
)

const (
	grpcPort            = ":50052"
	restPort            = ":8080"
	taStoreContractPath = "TransferableAccountStore.sol/TransferableAccountStore"
)

var (
	privKey             string
	taStoreContractAddr string
)

type server struct {
	pb.UnimplementedAccountServiceServer
	fr              *framework.Framework
	taStoreContract *framework.Contract
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
	return &pb.AccountResponse{Account: &pb.Account{AccountId: s.fr.KettleAddress.Hex()}}, nil
}

// func (s *server) IsApproved(ctx context.Context, req *pb.ApproveAddressRequest) (*pb.BoolResponse, error) {
// 	return &pb.BoolResponse{}, nil
// }

// func (s *server) IsOwner(ctx context.Context, req *pb.ApproveAddressRequest) (*pb.BoolResponse, error) {
// 	return &pb.BoolResponse{}, nil
// }

// func (s *server) IsLocked(ctx context.Context, req *pb.AccountIdRequest) (*pb.BoolResponse, error) {
// 	return &pb.BoolResponse{}, nil
// }

// func (s *server) GetLock(ctx context.Context, req *pb.AccountIdRequest) (*pb.TimeLockResponse, error) {
// 	return &pb.TimeLockResponse{}, nil
// }

func init() {
	taStoreContractAddr = os.Getenv("TA_STORE_CONTRACT_ADDRESS")
	if taStoreContractAddr == "" {
		log.Fatalf("TA_STORE_CONTRACT_ADDRESS is not set")
	}
	privKey = os.Getenv("PRIVATE_KEY")
	if privKey == "" {
		log.Fatalf("PRIVATE_KEY is not set")
	}
}

func main() {
	// setup framework and account
	fr := framework.New()
	fundedAccount := framework.NewPrivKeyFromHex(privKey)

	// read artifact
	artifact, err := framework.ReadArtifact(taStoreContractPath)
	if err != nil {
		log.Fatalf("Failed to read artifact: %v", err)
	}

	// create sdk client
	clt := sdk.NewClient(fr.Suave.RPC().Client(), fundedAccount.Priv, fr.KettleAddress)

	// get contract
	taStoreContractSDK := sdk.GetContract(fr.KettleAddress, artifact.Abi, clt)
	taStoreContract := &framework.Contract{Abi: artifact.Abi, Contract: taStoreContractSDK}

	// gRPC server
	s := grpc.NewServer()
	// Start gRPC server
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
