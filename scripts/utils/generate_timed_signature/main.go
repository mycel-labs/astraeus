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
		targetFunctionHash = common.HexToHash("0x030bb6482ea73e1a5ab7ed4810436dc5d10770855cdbbba0acb9a90b04852e4f")
	case "ApproveAddress":
		targetFunctionHash = common.HexToHash("0x16d1dabab53b460506870428d7a255f9bff53294080a73797c114f4e25b5e76f")
	case "RevokeApproval":
		targetFunctionHash = common.HexToHash("0xdb4c3d2d6140b1cf852cff55c9c9a3d0c16d15c9da5e35f87fdc664b1bbf1c32")
	case "TransferAccount":
		targetFunctionHash = common.HexToHash("0x29535a955f68dc291a88a89b6112c958d2edce1684117ccd6b54ca173656f65f")
	case "DeleteAccount":
		targetFunctionHash = common.HexToHash("0x31819315e31d5175ae85114dd27816114c585abc7f9d53ef5ca9bf3c4f2db038")
	case "UnlockAccount":
		targetFunctionHash = common.HexToHash("0x062e71868bb32b076e90fa8fa0fa661f47d2f38ee0e9db39a5ab5569589f6332")
	case "Sign":
		targetFunctionHash = common.HexToHash("0xd34780a58dd276dd414ea2abde077f3492ca5422926cdcadf8def7a93f12e993")
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
