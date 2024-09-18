package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/joho/godotenv"
)

func main() {
	// Load .env file
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	// Get RPC URL from environment variables
	rpcURL := os.Getenv("SEPOLIA_TESTNET_RPC")
	// Create Ethereum client
	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	// Unsigned transaction data
	unsignedTx := os.Args[1]
	unsignedTxBytes, err := hex.DecodeString(unsignedTx)
	if err != nil {
		log.Fatalf("Failed to decode unsigned transaction: %v", err)
	}

	// Decode unsigned transaction
	var tx types.Transaction
	err = rlp.DecodeBytes(unsignedTxBytes, &tx)
	if err != nil {
		log.Fatalf("Failed to decode unsigned transaction: %v", err)
	}

	// Signature data
	signature := os.Args[2]
	// Convert signature data to byte array
	signatureBytes, err := hex.DecodeString(signature)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}

	signedTx, err := tx.WithSignature(types.NewEIP155Signer(big.NewInt(11155111)), signatureBytes)
	if err != nil {
		log.Fatalf("Failed to apply signature to transaction: %v", err)
	}

	address := common.HexToAddress("0x14b1D4B4e3D822262ef16Ef3eFb6B9f137Fb3964")
	balance, err := client.BalanceAt(context.Background(), address, nil)
	if err != nil {
		log.Fatalf("Failed to get balance: %v", err)
	}

	fmt.Printf("Address: %s\n", address.Hex())
	fmt.Printf("Balance: %s\n", balance.String())

	if balance.Cmp(big.NewInt(0)) <= 0 {
		log.Fatalf("Insufficient balance to pay for gas")
	}

	sender, err := types.Sender(types.NewEIP155Signer(big.NewInt(11155111)), signedTx)
	if err != nil {
		log.Fatalf("Failed to get sender from signed transaction: %v", err)
	}
	fmt.Printf("Signed Transaction: %v\n", signedTx)
	fmt.Printf("Gas Price: %s\n", signedTx.GasPrice().String())
	fmt.Printf("Gas Limit: %d\n", signedTx.Gas())
	fmt.Printf("Sender: %s\n", sender.Hex())

	// Broadcast transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	fmt.Printf("Transaction sent: %s\n", signedTx.Hash().Hex())
}
