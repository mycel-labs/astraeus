package main

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func generateRandomPrivKey() *ecdsa.PrivateKey {
	// Generate a random private key
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		fmt.Println("Failed to generate private key:", err)
		return nil
	}

	// Display the generated private key as a hexadecimal string
	privateKeyHex := fmt.Sprintf("%x", crypto.FromECDSA(privateKey))
	fmt.Println("Generated private key:", privateKeyHex)

	return privateKey
}

func generateTimedSignature(validFor int64, privateKey *ecdsa.PrivateKey) (messageHash [32]byte, signature []byte, err error) {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

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
		return [32]byte{}, nil, err
	}

	// Adjust the v value of the signature (add 27)
	// This ensures compatibility with Mycel's signature standard
	signature[64] += 27

	return messageHash, signature, nil
}

func main() {
	validFor := time.Now().Unix() + 86400 // 1 day later
	privKey := generateRandomPrivKey()
	messageHash, signature, err := generateTimedSignature(validFor, privKey)
	if err != nil {
		fmt.Println("Failed to generate timed signature:", err)
		return
	}

	fmt.Printf("Message Hash: %x\n", messageHash)
	fmt.Printf("Signature: %x\n", signature)
}
