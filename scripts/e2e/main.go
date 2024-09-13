package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mycel-labs/transferable-account/src/go/server"
)

const (
	hostURL = "http://localhost:8080"
)

/*
This script demonstrates the process of setting up a SUAVE server, deploying a contract,
and interacting with it through a Go server. Here's an overview of the steps:

1. Start the SUAVE server (external command: make devnet-up)
2. Deploy the contract to the SUAVE server (external command: forge create ...)
3. Set environment variables for the contract address and private key
4. Start the Go server
5. Generate a timed signature
6. Create an account using the API
7. Transfer the account using the API

Before running this script:
- Ensure you have the SUAVE server and Forge installed
- Run `make devnet-up` to start the SUAVE server
- Deploy the contract using Forge and set the TA_STORE_CONTRACT_ADDRESS environment variable
- Set the PRIVATE_KEY environment variable

After these steps, you can run this script to interact with the deployed contract via the API.
*/


func main() {
	// Check if required environment variables are set
	contractAddress := os.Getenv("TA_STORE_CONTRACT_ADDRESS")
	privateKey := os.Getenv("PRIVATE_KEY")
	if contractAddress == "" || privateKey == "" {
		log.Fatal("TA_STORE_CONTRACT_ADDRESS and PRIVATE_KEY must be set")
	}

	// Generate timed signature
	privKey, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		log.Fatal("Failed to convert private key to ECDSA:", err)
	}
	timedSignature, err := populateTimedSignature(privKey)
	if err != nil {
		log.Fatal("Failed to generate timed signature:", err)
	}

	// Create account
	createAccount(timedSignature)
}

func populateTimedSignature(privateKey *ecdsa.PrivateKey) (server.TimedSignature, error) {
	validFor := time.Now().Unix() + 1000000
	address, messageHash, signature, err := generateTimedSignature(validFor, privateKey)
	if err != nil {
		return server.TimedSignature{}, err
	}
	return server.TimedSignature{
		ValidFor:    uint64(validFor),
		MessageHash: messageHash,
		Signature:   signature,
		Signer:      address,
	}, nil
}

func generateTimedSignature(validFor int64, privateKey *ecdsa.PrivateKey) (address common.Address, messageHash [32]byte, signature []byte, err error) {
	address = crypto.PubkeyToAddress(privateKey.PublicKey)

	// Step 1: Create the message hash
	// Combine validFor timestamp and signer's address, then hash with Keccak256
	messageHash = crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(validFor).Bytes(), 8),
		common.LeftPadBytes(address.Bytes(), 20),
	)

	// Step 2: Apply Mycel-specific prefix
	// Prepend "\x19Mycel Signed Message:\n32" and hash again
	prefixedMessage := fmt.Sprintf("\x19Mycel Signed Message:\n32%s", messageHash)
	prefixedMessageHash := crypto.Keccak256Hash([]byte(prefixedMessage))

	// Step 3: Generate the signature
	// Sign the prefixed message hash with the private key
	signature, err = crypto.Sign(prefixedMessageHash.Bytes(), privateKey)
	if err != nil {
		return common.Address{}, [32]byte{}, nil, err
	}

	// Adjust the v value of the signature (add 27)
	// This ensures compatibility with Mycel's signature standard
	signature[64] += 27

	return address, messageHash, signature, nil
}

func createAccount(timedSignature server.TimedSignature) {
	url := fmt.Sprintf("%s/v1/accounts", hostURL)
	data := map[string]interface{}{
		"proof": map[string]interface{}{
			"validFor":    timedSignature.ValidFor,
			"messageHash": fmt.Sprintf("%x", timedSignature.MessageHash), // Convert to hex string
			"signature":   fmt.Sprintf("%x", timedSignature.Signature),   // Convert to hex string
			"signer":      timedSignature.Signer.Hex(),
		},
	}
	log.Printf("Creating account with: %v", data)
	sendRequest(url, data)
}

func sendRequest(url string, data map[string]interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal("Failed to marshal JSON:", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal("Failed to send request:", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response:", err)
	}

	fmt.Printf("Status Code: %d\n", resp.StatusCode)
	fmt.Printf("Response Headers: %v\n", resp.Header)
	fmt.Printf("Response Body: %s\n", string(body))
}
