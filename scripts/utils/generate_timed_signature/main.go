package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/mycel-labs/astraeus/src/go/framework"
	impl "github.com/mycel-labs/astraeus/src/go/server"
	testutil "github.com/mycel-labs/astraeus/test/utils"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <targetFunction>", os.Args[0])
	}

	targetFunction := os.Args[1]

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

	privateKeyBytes, err := hex.DecodeString(os.Getenv("PRIVATE_KEY"))

	if err != nil {
		log.Fatalf("failed to decode hex string: %v", err)
	}
	privKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}

	fr := framework.New(framework.WithCustomConfig(os.Getenv("PRIVATE_KEY"), os.Getenv("RPC_URL")))

	log.Printf("Using TA_STORE_CONTRACT_ADDRESS: %s", os.Getenv("TA_STORE_CONTRACT_ADDRESS"))
	taStoreContract, err := fr.Suave.BindToExistingContract(common.HexToAddress(os.Getenv("TA_STORE_CONTRACT_ADDRESS")), testutil.TAStoreContractPath)
	if err != nil {
		log.Fatalf("Failed to bind to existing contract: %v", err)
	}

	valdFor := uint64(time.Now().Unix() + 86400)

	timedSignature, err := testutil.NewPbTimedSignature(taStoreContract, privKey, valdFor, targetFunctionHash)

	if err != nil {
		log.Fatalf("Failed to generate timed signature: %v", err)
	}

	fmt.Printf("\"proof\": {\n")
	fmt.Printf("  \"validFor\": %d,\n", valdFor)
	fmt.Printf("  \"messageHash\": \"%s\",\n", timedSignature.MessageHash)
	fmt.Printf("  \"signature\": \"%s\",\n", timedSignature.Signature)
	fmt.Printf("  \"signer\": \"%s\",\n", timedSignature.Signer)
	fmt.Printf("  \"nonce\": %d,\n", timedSignature.Nonce)
	fmt.Printf("  \"target_function_hash\": \"%s\"\n", timedSignature.TargetFunctionHash)
	fmt.Printf("}\n")
}
