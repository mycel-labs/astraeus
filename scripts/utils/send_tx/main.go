package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Get RPC URL and private key from environment variables
	rpcURL := os.Getenv("SEPOLIA_TESTNET_RPC")
	privateKeyHex := os.Getenv("SEPOLIA_TESTNET_PRIVATE_KEY")

	// Create Ethereum client
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	// Create private key
	privateKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}

	// Get sender address
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey) // Correction: *crypto.PublicKey -> *ecdsa.PublicKey
	if !ok {
		log.Fatalf("Failed to get public key")
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

	// Get recipient address
	if len(os.Args) != 2 {
		log.Fatalf("Usage: %s <recipient address>", os.Args[0])
	}
	toAddress := common.HexToAddress(os.Args[1])

	// Get nonce
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}

	// Get gas price
	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}

	// Create transaction
	value := big.NewInt(10000000000000000) // 0.01 ETH
	gasLimit := uint64(21000)              // Standard transaction gas limit
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, nil)

	// Sign transaction
	chainID, err := client.NetworkID(context.Background())
	if err != nil {
		log.Fatalf("Failed to get network ID: %v", err)
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	// Send transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction sent successfully: %s\n", signedTx.Hash().Hex())
}
