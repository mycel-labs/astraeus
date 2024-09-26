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
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	framework "github.com/mycel-labs/transferable-account/src/go/framework"
	pb "github.com/mycel-labs/transferable-account/src/go/pb/api/v1"
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

type Transaction1559Request struct {
	To                   common.Address
	Gas                  *big.Int
	MaxFeePerGas         *big.Int
	MaxPriorityFeePerGas *big.Int
	Value                *big.Int
	Nonce                *big.Int
	Data                 []byte
	ChainId              *big.Int
	AccessList           []byte
}

type Transaction155Request struct {
	To       common.Address
	Gas      *big.Int
	GasPrice *big.Int
	Value    *big.Int
	Nonce    *big.Int
	Data     []byte
	ChainId  *big.Int
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
	log.Printf("data: %x", data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %v", err)
	}

	tx1559Request := &Transaction1559Request{
		To:                   common.HexToAddress("0xRecipientAddress"),
		Gas:                  big.NewInt(31000),
		MaxFeePerGas:         big.NewInt(400000000000), // 400 Gwei
		MaxPriorityFeePerGas: big.NewInt(20000000000),  // 20 Gwei
		Value:                big.NewInt(4),
		Nonce:                big.NewInt(0),
		Data:                 []byte("適当な値"),
		ChainId:              big.NewInt(11155111), // Mainnet             // No access list
	}

	rlpEncodedTx1559Request, err := rlp.EncodeToBytes(tx1559Request)
	if err != nil {
		return nil, fmt.Errorf("failed to RLP encode tx1559Request: %v", err) // 修正: エラーメッセージの先頭を小文字に変更
	}
	log.Printf("RLP Encoded tx1559Request: %x", rlpEncodedTx1559Request)

	rlpTxnHash := crypto.Keccak256(rlpEncodedTx1559Request)

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("error occurred during transaction execution: %v", r)
			}
		}()
		result = s.taStoreContract.SendConfidentialRequest("sign1559", []interface{}{sig, req.Base.AccountId, rlpTxnHash}, nil)
	}()

	if err != nil {
		return nil, err
	}

	if result == nil {
		return nil, fmt.Errorf("failed to sign")
	}

	caEvent, err := s.taStoreContract.Abi.Events["Transaction1559"].ParseLog(result.Logs[2])
	if err != nil {
		panic(err)
	}
	// 型アサーションを使用して、適切な型に変換
	signed1559TxStruct, ok := caEvent["signedTx"].(struct {
		To                   common.Address `json:"to"`
		Gas                  *big.Int       `json:"gas"`
		MaxFeePerGas         *big.Int       `json:"maxFeePerGas"`
		MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas"`
		Value                *big.Int       `json:"value"`
		Nonce                *big.Int       `json:"nonce"`
		Data                 []uint8        `json:"data"`
		ChainId              *big.Int       `json:"chainId"`
		AccessList           []uint8        `json:"accessList"`
		R                    [32]uint8      `json:"r"`
		S                    [32]uint8      `json:"s"`
		V                    *big.Int       `json:"v"`
	})
	if !ok {
		log.Fatalf("failed to cast signedTx to expected struct type")
	}

	log.Printf("signedTx R: %x", signed1559TxStruct.R)
	log.Printf("signedTx S: %x", signed1559TxStruct.S)
	log.Printf("signedTx V: %x", signed1559TxStruct.V)

	signature := append(signed1559TxStruct.R[:], append(signed1559TxStruct.S[:], byte(signed1559TxStruct.V.Uint64()))...)
	log.Printf("signature: %x", signature)

	tx := types.NewTx(&types.DynamicFeeTx{
		To:        &tx1559Request.To,
		Gas:       tx1559Request.Gas.Uint64(),
		GasFeeCap: tx1559Request.MaxFeePerGas,
		GasTipCap: tx1559Request.MaxPriorityFeePerGas,
		Value:     tx1559Request.Value,
		Nonce:     tx1559Request.Nonce.Uint64(),
		Data:      tx1559Request.Data,
		ChainID:   tx1559Request.ChainId,
	})

	// 署名データを適用
	signedTx, err := tx.WithSignature(types.NewLondonSigner(tx.ChainId()), []byte(signature))
	if err != nil {
		log.Fatalf("Failed to apply signature to transaction: %v", err)
	}

	log.Printf("signedTx: %v", signedTx)
	log.Printf("signedTx To: %s", signedTx.To().Hex())
	log.Printf("signedTx Gas: %d", signedTx.Gas())
	log.Printf("signedTx GasFeeCap: %s", signedTx.GasFeeCap().String())
	log.Printf("signedTx GasTipCap: %s", signedTx.GasTipCap().String())
	log.Printf("signedTx Value: %s", signedTx.Value().String())
	log.Printf("signedTx Nonce: %d", signedTx.Nonce())
	log.Printf("signedTx Data: %x", signedTx.Data())
	log.Printf("signedTx ChainID: %d", signedTx.ChainId())

	sender, err := types.Sender(types.NewLondonSigner(tx.ChainId()), signedTx)
	if err != nil {
		log.Fatalf("Failed to get sender from signed transaction: %v", err)
	}
	log.Printf("Sender Address: %s", sender)

	// Get RPC URL from environment variables
	rpcURL := "https://eth-sepolia.public.blastapi.io"
	// Create Ethereum client
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	// Broadcast transaction and get TxHash
	txHash := signedTx.Hash()
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}
	log.Printf("Transaction sent successfully. TxHash: %s", txHash.Hex())

	return &pb.SignResponse{
		TxHash:    result.TxHash.Hex(),
		Signature: signedTx.Hash().Hex(),
	}, nil
}

// func (s *server) Sign(ctx context.Context, req *pb.SignRequest) (*pb.SignResponse, error) {
// 	var result *types.Receipt
// 	var err error
// 	sig, err := populateTimedSignature(req.Base.Proof)
// 	if err != nil {
// 		return nil, err
// 	}

// 	data, err := hex.DecodeString(req.Data)
// 	log.Printf("data: %x", data)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to decode data: %v", err)
// 	}

// 	tx1559Request := &Transaction1559Request{
// 		To:                   common.HexToAddress("0xRecipientAddress"),
// 		Gas:                  big.NewInt(21000),
// 		MaxFeePerGas:         big.NewInt(50000000000), // 50 Gwei
// 		MaxPriorityFeePerGas: big.NewInt(2000000000),  // 2 Gwei
// 		Value:                big.NewInt(1),
// 		Nonce:                big.NewInt(0),
// 		Data:                 []byte("適当な値"),
// 		ChainId:              big.NewInt(11155111), // Mainnet             // No access list
// 	}

// 	log.Printf("txRequest.ChainId: %d", tx1559Request.ChainId.Int64())

// 	func() {
// 		defer func() {
// 			if r := recover(); r != nil {
// 				err = fmt.Errorf("error occurred during transaction execution: %v", r)
// 			}
// 		}()
// 		result = s.taStoreContract.SendConfidentialRequest("sign1559", []interface{}{sig, req.Base.AccountId, tx1559Request}, nil)
// 	}()

// 	if err != nil {
// 		return nil, err
// 	}

// 	if result == nil {
// 		return nil, fmt.Errorf("failed to sign")
// 	}

// 	// ---------秘密鍵に問題がないかの検証-----------------

// 	// Parse the second log entry for Privatekey event
// 	privateKeyEvent, err := s.taStoreContract.Abi.Events["Privatekey"].ParseLog(result.Logs[3])
// 	if err != nil {
// 		panic(err)
// 	}

// 	signingKey := privateKeyEvent["signingKey"].([]byte)
// 	log.Printf("Privatekey Event: %s", string(signingKey))

// 	// 秘密鍵から公開鍵を導出
// 	log.Printf("Signing Key Byte Length: %d bytes", len(string(signingKey)))

// 	log.Printf("Signing Key Length: %d bits", len(string(signingKey))*8)

// 	if err != nil {
// 		log.Fatalf("failed to decode signingKey: %v", err)
// 	}

// 	signingKeyBytes, err := hex.DecodeString(string(signingKey))
// 	if err != nil {
// 		log.Fatalf("failed to decode signingKey: %v", err)
// 	}
// 	if len(signingKeyBytes) != 32 {
// 		log.Fatalf("signingKey length is not 32 bytes: %d bytes", len(string(signingKey)))
// 	}
// 	privateKey, err := crypto.ToECDSA(signingKeyBytes)
// 	if err != nil {
// 		log.Fatalf("failed to convert signingKey to ECDSA private key: %v", err)
// 	}
// 	publicKey := privateKey.Public()
// 	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
// 	if !ok {
// 		log.Fatalf("failed to cast publicKey to ECDSA")
// 	}
// 	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
// 	log.Printf("Public Key: %s", hex.EncodeToString(publicKeyBytes))

// 	// 公開鍵からアドレスを導出
// 	address := crypto.PubkeyToAddress(*publicKeyECDSA)
// 	log.Printf("Address: %s", address.Hex())

// 	// ---------秘密鍵に問題がないかの検証-----------------

// 	// ----------------privateKeyStringの検証------------------

// 	signingKeyParse, err := s.taStoreContract.Abi.Events["PrivatekeyString"].ParseLog(result.Logs[4])
// 	if err != nil {
// 		panic(err)
// 	}

// 	signingKeyString := signingKeyParse["signingKey"]
// 	log.Printf("signingKeyString: %s", signingKeyString)

// 	// ----------------privateKeyStringの検証------------------

// 	// ----------signEthTransactionの検証------------
// 	log.Printf("result.Logs: %v", result.Logs)
// 	Transaction1559bytes, err := s.taStoreContract.Abi.Events["Transaction1559bytes"].ParseLog(result.Logs[6])
// 	if err != nil {
// 		panic(err)
// 	}

// 	signedTxBytes := Transaction1559bytes["signedTx"].([]byte)
// 	log.Printf("signedTxBytes: %s", signedTxBytes)

// 	// ----------signEthTransactionの検証------------

// 	// -----------------------API server上で署名を作って、どこが違うかを検証--------------------------------
// 	RLPTransaction, err := s.taStoreContract.Abi.Events["RLPTransaction"].ParseLog(result.Logs[0])
// 	rlptxn := RLPTransaction["rlptxn"].([]byte)
// 	rlptxnHash := crypto.Keccak256(rlptxn)
// 	log.Printf("rlptxnHash: %x", rlptxnHash)

// 	RLPTransactionHashed, err := s.taStoreContract.Abi.Events["RLPTransactionHashed"].ParseLog(result.Logs[1])
// 	rlpTxnHashonSolidity := RLPTransactionHashed["rlpTxnHash"].([]byte)
// 	log.Printf("rlpTxnHashonSolidity: %x", rlpTxnHashonSolidity)

// 	Signature, err := s.taStoreContract.Abi.Events["Signature"].ParseLog(result.Logs[2])
// 	signatureOnSolidity := Signature["signature"].([]byte)
// 	log.Printf("signatureOnSolidity: %x", signatureOnSolidity)

// 	rlpEncodedTx1559Request, err := rlp.EncodeToBytes(tx1559Request)
// 	if err != nil {
// 		log.Fatalf("Failed to RLP encode tx1559Request: %v", err)
// 	}
// 	log.Printf("RLP Encoded tx1559Request: %x", rlpEncodedTx1559Request)

// 	rlpTxnHash := crypto.Keccak256Hash(rlpEncodedTx1559Request)
// 	log.Printf("RLP Transaction Hash: %s", rlpTxnHash.Hex())

// 	// ECDSA秘密鍵を生成
// 	privateKeyECDSA, err := crypto.ToECDSA(signingKeyBytes)
// 	if err != nil {
// 		log.Fatalf("failed to convert signingKeyString to ECDSA private key: %v", err)
// 	}

// 	// 署名を作成
// 	signature, err := crypto.Sign(rlptxnHash, privateKeyECDSA)
// 	if err != nil {
// 		log.Fatalf("failed to sign rlptxnHash: %v", err)
// 	}

// 	// 署名をログに出力
// 	log.Printf("Generated Signature: %x", signature)

// 	// r, s, vを抽出
// 	rr := signature[:32]
// 	ss := signature[32:64]
// 	vv := signature[64]

// 	// r, s, vをログに出力
// 	log.Printf("r: %x", rr)
// 	log.Printf("s: %x", ss)
// 	log.Printf("v: %x", vv)

// 	log.Printf("vv: %x", vv)
// 	// 署名のv値を調整
// 	// if vv < 2 {
// 	// 	vv -= 1
// 	// }

// 	log.Printf("vv: %x", vv)
// 	log.Printf(" append(rr, append(ss, vv)...): %x", append(rr, append(ss, vv)...))

// 	// トランザクションのハッシュを計算
// 	// signer := types.NewLondonSigner(tx1559Request.ChainId)

// 	// txHash := signer.Hash(tx)
// 	publicKeyDerived, err := crypto.SigToPub(rlpTxnHashonSolidity, append(rr, append(ss, vv)...))
// 	if err != nil {
// 		return nil, err
// 	}

// 	// publicKeyDerived2, err := crypto.SigToPub(rlpTxnHashonSolidity, append(rr, append(ss, vv)...))
// 	// if err != nil {
// 	// 	return nil, err
// 	// }

// 	// 署名者のアドレスを導出
// 	signerAddress := crypto.PubkeyToAddress(*publicKeyDerived)
// 	log.Printf("signerAddressDerived: %x", signerAddress)

// 	// -----------------------API server上で署名を作って、どこが違うかを検証--------------------------------

// 	caEvent, err := s.taStoreContract.Abi.Events["Transaction1559"].ParseLog(result.Logs[5])
// 	if err != nil {
// 		panic(err)
// 	}
// 	// 型アサーションを使用して、適切な型に変換
// 	signed1559TxStruct, ok := caEvent["signedTx"].(struct {
// 		To                   common.Address `json:"to"`
// 		Gas                  *big.Int       `json:"gas"`
// 		MaxFeePerGas         *big.Int       `json:"maxFeePerGas"`
// 		MaxPriorityFeePerGas *big.Int       `json:"maxPriorityFeePerGas"`
// 		Value                *big.Int       `json:"value"`
// 		Nonce                *big.Int       `json:"nonce"`
// 		Data                 []uint8        `json:"data"`
// 		ChainId              *big.Int       `json:"chainId"`
// 		AccessList           []uint8        `json:"accessList"`
// 		R                    [32]uint8      `json:"r"`
// 		S                    [32]uint8      `json:"s"`
// 		V                    *big.Int       `json:"v"`
// 	})
// 	if !ok {
// 		log.Fatalf("failed to cast signedTx to expected struct type")
// 	}

// 	if tx1559Request.To != signed1559TxStruct.To {
// 		log.Fatalf("To address mismatch: expected %s but got %s", tx1559Request.To.Hex(), signed1559TxStruct.To.Hex())
// 	} else {
// 		log.Printf("To address match: %s", tx1559Request.To.Hex())
// 	}
// 	if tx1559Request.Gas.Cmp(signed1559TxStruct.Gas) != 0 {
// 		log.Fatalf("Gas mismatch: expected %s but got %s", tx1559Request.Gas.String(), signed1559TxStruct.Gas.String())
// 	} else {
// 		log.Printf("Gas match: %s", tx1559Request.Gas.String())
// 	}
// 	if tx1559Request.MaxFeePerGas.Cmp(signed1559TxStruct.MaxFeePerGas) != 0 {
// 		log.Fatalf("MaxFeePerGas mismatch: expected %s but got %s", tx1559Request.MaxFeePerGas.String(), signed1559TxStruct.MaxFeePerGas.String())
// 	} else {
// 		log.Printf("MaxFeePerGas match: %s", tx1559Request.MaxFeePerGas.String())
// 	}
// 	if tx1559Request.MaxPriorityFeePerGas.Cmp(signed1559TxStruct.MaxPriorityFeePerGas) != 0 {
// 		log.Fatalf("MaxPriorityFeePerGas mismatch: expected %s but got %s", tx1559Request.MaxPriorityFeePerGas.String(), signed1559TxStruct.MaxPriorityFeePerGas.String())
// 	} else {
// 		log.Printf("MaxPriorityFeePerGas match: %s", tx1559Request.MaxPriorityFeePerGas.String())
// 	}
// 	if tx1559Request.Value.Cmp(signed1559TxStruct.Value) != 0 {
// 		log.Fatalf("Value mismatch: expected %s but got %s", tx1559Request.Value.String(), signed1559TxStruct.Value.String())
// 	} else {
// 		log.Printf("Value match: %s", tx1559Request.Value.String())
// 	}
// 	if tx1559Request.Nonce.Cmp(signed1559TxStruct.Nonce) != 0 {
// 		log.Fatalf("Nonce mismatch: expected %s but got %s", tx1559Request.Nonce.String(), signed1559TxStruct.Nonce.String())
// 	} else {
// 		log.Printf("Nonce match: %s", tx1559Request.Nonce.String())
// 	}
// 	if !bytes.Equal(tx1559Request.Data, signed1559TxStruct.Data) {
// 		log.Fatalf("Data mismatch: expected %x but got %x", tx1559Request.Data, signed1559TxStruct.Data)
// 	} else {
// 		log.Printf("Data match: %x", tx1559Request.Data)
// 	}
// 	if tx1559Request.ChainId.Cmp(signed1559TxStruct.ChainId) != 0 {
// 		log.Fatalf("ChainId mismatch: expected %s but got %s", tx1559Request.ChainId.String(), signed1559TxStruct.ChainId.String())
// 	} else {
// 		log.Printf("ChainId match: %s", tx1559Request.ChainId.String())
// 	}
// 	if !bytes.Equal(tx1559Request.AccessList, signed1559TxStruct.AccessList) {
// 		log.Fatalf("AccessList mismatch: expected %x but got %x", tx1559Request.AccessList, signed1559TxStruct.AccessList)
// 	} else {
// 		log.Printf("AccessList match: %x", tx1559Request.AccessList)
// 	}

// 	log.Printf("signedTx R: %x", signed1559TxStruct.R)
// 	log.Printf("signedTx S: %x", signed1559TxStruct.S)
// 	log.Printf("signedTx V: %x", signed1559TxStruct.V)

// 	// if err != nil {
// 	// 	log.Fatalf("Failed to encode RLP: %v", err)
// 	// }

// 	// rlpHash := crypto.Keccak256Hash(
// 	// 	append([]byte{txType}, rlpEncoded...),
// 	// )

// 	// -----------------RSVの署名データが正しく署名されているものかどうかの検証-------------------
// 	// signerDerived := types.NewLondonSigner(signed1559TxStruct.ChainId)
// 	// ethSignedMessageHash := signer.Hash(tx)
// 	recoveredPubkey, err := crypto.SigToPub(rlpTxnHashonSolidity, signature)
// 	if err != nil {
// 		log.Fatalf("Failed to recover signer from signature: %v", err)
// 	}
// 	log.Printf("recoveredSigner: %s", recoveredPubkey)
// 	recoveredAddress := crypto.PubkeyToAddress(*recoveredPubkey)
// 	// if recoveredAddress != sender {
// 	// 	log.Fatalf("Signature verification failed: expected %s but got %s", sender.Hex(), recoveredAddress.Hex())
// 	// }
// 	log.Printf("Signature verification succeeded Sender: %s", recoveredAddress.Hex())
// 	// -----------------RSVの署名データが正しく署名されているものかどうかの検証-------------------

// 	tx := types.NewTx(&types.DynamicFeeTx{
// 		To:        &signed1559TxStruct.To,
// 		Gas:       signed1559TxStruct.Gas.Uint64(),
// 		GasFeeCap: signed1559TxStruct.MaxFeePerGas,
// 		GasTipCap: signed1559TxStruct.MaxPriorityFeePerGas,
// 		Value:     signed1559TxStruct.Value,
// 		Nonce:     signed1559TxStruct.Nonce.Uint64(),
// 		Data:      signed1559TxStruct.Data,
// 		ChainID:   signed1559TxStruct.ChainId,
// 	})

// 	tx1559RequestReturned := &Transaction1559Request{
// 		To:                   signed1559TxStruct.To,
// 		Gas:                  signed1559TxStruct.Gas,
// 		MaxFeePerGas:         signed1559TxStruct.MaxFeePerGas,         // 50 Gwei
// 		MaxPriorityFeePerGas: signed1559TxStruct.MaxPriorityFeePerGas, // 2 Gwei
// 		Value:                signed1559TxStruct.Value,
// 		Nonce:                signed1559TxStruct.Nonce,
// 		Data:                 signed1559TxStruct.Data,
// 		ChainId:              signed1559TxStruct.ChainId, // Mainnet             // No access list
// 	}

// 	if tx1559Request.To != tx1559RequestReturned.To ||
// 		tx1559Request.Gas.Cmp(tx1559RequestReturned.Gas) != 0 ||
// 		tx1559Request.MaxFeePerGas.Cmp(tx1559RequestReturned.MaxFeePerGas) != 0 ||
// 		tx1559Request.MaxPriorityFeePerGas.Cmp(tx1559RequestReturned.MaxPriorityFeePerGas) != 0 ||
// 		tx1559Request.Value.Cmp(tx1559RequestReturned.Value) != 0 ||
// 		tx1559Request.Nonce.Cmp(tx1559RequestReturned.Nonce) != 0 ||
// 		!bytes.Equal(tx1559Request.Data, tx1559RequestReturned.Data) ||
// 		tx1559Request.ChainId.Cmp(tx1559RequestReturned.ChainId) != 0 {
// 		log.Fatalf("tx1559Request and tx1559RequestReturned do not match")
// 	} else {
// 		log.Printf("tx1559Request and tx1559RequestReturned match")
// 	}

// 	// rlpEncodedTx1559RequestReturned, err := rlp.EncodeToBytes(tx1559RequestReturned)
// 	// if err != nil {
// 	// 	log.Fatalf("Failed to RLP encode tx1559RequestReturned: %v", err)
// 	// }
// 	// log.Printf("RLP Encoded tx1559RequestReturned: %x", rlpEncodedTx1559RequestReturned)

// 	// if bytes.Equal(rlpEncodedTx1559RequestReturned, rlptxnHash) {
// 	// 	log.Printf("rlpEncodedTx1559RequestReturned is equal to rlptxnHash")
// 	// } else {
// 	// 	log.Printf("rlpEncodedTx1559RequestReturned is not equal to rlptxnHash")
// 	// }
// 	// // 署名データを適用
// 	// rrr := signed1559TxStruct.R[:]
// 	// sss := signed1559TxStruct.S[:]
// 	// vBytes := signed1559TxStruct.V.Bytes()

// 	log.Printf("tx: %+v", tx)
// 	log.Printf("tx Type: %d", tx.Type())
// 	log.Printf("tx ChainId: %d", tx.ChainId())
// 	log.Printf("tx Data: %x", tx.Data())
// 	log.Printf("tx Gas: %d", tx.Gas())
// 	log.Printf("tx GasTipCap: %s", tx.GasTipCap().String())
// 	log.Printf("tx GasFeeCap: %s", tx.GasFeeCap().String())
// 	log.Printf("tx Value: %s", tx.Value().String())
// 	log.Printf("tx Nonce: %d", tx.Nonce())
// 	log.Printf("tx To: %s", tx.To().Hex())

// 	// 署名データを適用
// 	// signedTx, err := tx.WithSignature(types.NewLondonSigner(tx.ChainId()), append(rrr, append(sss, vBytes[0])...))
// 	signedTx, err := tx.WithSignature(types.NewLondonSigner(tx.ChainId()), signature)

// 	if err != nil {
// 		log.Fatalf("Failed to apply signature to transaction: %v", err)
// 	}

// 	sender, err := types.Sender(types.NewLondonSigner(tx.ChainId()), signedTx)
// 	if err != nil {
// 		log.Fatalf("Failed to get sender from signed transaction: %v", err)
// 	}
// 	log.Printf("Sender Address: %s", sender.Hex())
// 	if err != nil {
// 		log.Fatalf("Failed to apply signature to transaction: %v", err)
// 	}

// 	log.Printf("signedTx: %v", signedTx)

// 	// Get RPC URL from environment variables
// 	rpcURL := "https://eth-sepolia.public.blastapi.io"
// 	// Create Ethereum client
// 	client, err := ethclient.Dial(rpcURL)
// 	if err != nil {
// 		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
// 	}

// 	// Broadcast transaction and get TxHash
// 	txHash := signedTx.Hash()
// 	err = client.SendTransaction(context.Background(), signedTx)
// 	if err != nil {
// 		log.Fatalf("Failed to send transaction: %v", err)
// 	}
// 	log.Printf("Transaction sent successfully. TxHash: %s", txHash.Hex())

// 	return &pb.SignResponse{
// 		TxHash:    result.TxHash.Hex(),
// 		Signature: signedTx.Hash().Hex(),
// 	}, nil
// }

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
