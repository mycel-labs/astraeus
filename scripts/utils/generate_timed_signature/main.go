package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"

	"github.com/joho/godotenv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
	impl "github.com/mycel-labs/astraeus/src/go/server"
	testutil "github.com/mycel-labs/astraeus/test/utils"
)

func generateTimedSignature(validFor int64, privateKey *ecdsa.PrivateKey, nonce uint64, targetFunctionHash [32]byte) (messageHash [32]byte, signature []byte, err error) {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Step 1: Create the message hash
	// Combine validFor timestamp, signer's address, nonce, and targetFunctionHash, then hash with Keccak256
	messageHash = crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(validFor).Bytes(), 8),
		common.LeftPadBytes(address.Bytes(), 20),
		common.LeftPadBytes(big.NewInt(int64(nonce)).Bytes(), 8),
		targetFunctionHash[:],
	)

	// Step 2: Apply Mycel-specific prefix
	// Prepend "\x19Mycel Signed Message:\n32" and hash again
	prefixedMessage := fmt.Sprintf("\x19Mycel Signed Message:\n32%s", messageHash)
	prefixedMessageHash := crypto.Keccak256Hash([]byte(prefixedMessage))

	// Step 3: Generate the signature
	// Sign the prefixed message hash with the private key
	signature, err = crypto.Sign(prefixedMessageHash.Bytes(), privateKey)
	if err != nil {
		return [32]byte{}, nil, err
	}

	// Adjust the v value of the signature (add 27)
	// This ensures compatibility with Mycel's signature standard
	signature[64] += 27

	return messageHash, signature, nil
}

func getNonce(address string) (*pb.GetNonceResponse, *http.Response, error) {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	apiRpcUrl := os.Getenv("API_RPC_URL")
	log.Printf("RPC URL: %s", apiRpcUrl)
	if apiRpcUrl == "" {
		log.Fatal("Failed to retrieve RPC_URL correctly")
	}

	url := fmt.Sprintf("%s/v1/nonce/%s", apiRpcUrl, address)
	getNonceResponse := &pb.GetNonceResponse{}
	resp := testutil.GetServer(url, getNonceResponse)
	return getNonceResponse, resp, nil
}

func main() {

	if len(os.Args) != 4 {
		log.Fatalf("Usage: %s <validFor> <privateKey> <targetFunction>", os.Args[0])
	}

	validFor, err := strconv.ParseInt(os.Args[1], 10, 64)
	if err != nil {
		log.Fatalf("Invalid validFor value: %v", err)
	}

	privateKeyHex := os.Args[2]
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}

	targetFunction := os.Args[3]

	var targetFunctionHash [32]byte

	switch targetFunction {
	case "CreateAccount":
		targetFunctionHash = common.HexToHash(impl.CREATE_ACCOUNT_FUNCTION_HASH)
	case "ApproveAddress":
		targetFunctionHash = common.HexToHash(impl.APPROVE_ADDRESS_FUNCTION_HASH)
	case "RevokeApproval":
		targetFunctionHash = common.HexToHash(impl.REVOKE_APPROVAL_FUNCTION_HASH)
	case "TransferAccount":
		targetFunctionHash = common.HexToHash(impl.TRANSFER_ACCOUNT_FUNCTION_HASH)
	case "DeleteAccount":
		targetFunctionHash = common.HexToHash(impl.DELETE_ACCOUNT_FUNCTION_HASH)
	case "UnlockAccount":
		targetFunctionHash = common.HexToHash(impl.UNLOCK_ACCOUNT_FUNCTION_HASH)
	case "Sign":
		targetFunctionHash = common.HexToHash(impl.SIGN_FUNCTION_HASH)
	default:
		log.Fatalf("Unknown target function: %s", targetFunction)
	}

	log.Printf("Target Function Hash: %x", targetFunctionHash)

	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	log.Printf("Address: %s", address.Hex())
	getNonceResponse, _, err := getNonce(address.String())
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}
	nonce := getNonceResponse.Nonce
	log.Printf("Nonce: %d", nonce)

	messageHash, signature, err := generateTimedSignature(validFor, privateKey, nonce, targetFunctionHash)
	if err != nil {
		log.Fatalf("Failed to generate timed signature: %v", err)
	}

	fmt.Printf("Message Hash: %x\n", messageHash)
	fmt.Printf("Signature: %x\n", signature)
}
