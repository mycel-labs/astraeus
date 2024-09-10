package main

import (
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

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

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <validFor> <privateKey>", os.Args[0])
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

	address, messageHash, signature, err := generateTimedSignature(validFor, privateKey)
	if err != nil {
		log.Fatalf("Failed to generate timed signature: %v", err)
	}

	fmt.Printf("Address: %x\n", address)
	fmt.Printf("Message Hash: %x\n", messageHash)
	fmt.Printf("Signature: %x\n", signature)
}
