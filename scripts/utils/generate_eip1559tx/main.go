package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/joho/godotenv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <Alice's address> <Bob's address>", os.Args[0])
	}
	aliceAddress := common.HexToAddress(os.Args[1])
	bobAddress := common.HexToAddress(os.Args[2])

	client, err := ethclient.Dial(os.Getenv("SEPOLIA_TESTNET_RPC"))
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), aliceAddress)
	if err != nil {
		log.Fatalf("Failed to get nonce: %v", err)
	}
	fmt.Printf("Nonce: %d\n", nonce)

	gasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get gas price: %v", err)
	}
	fmt.Printf("Gas Price: %s\n", gasPrice.String())

	value := big.NewInt(100000000000000) // 0.0001 ETH
	gasLimit := uint64(21000)            // Gas limit for a standard transaction
	chainID := big.NewInt(11155111)      // Sepolia Testnet Chain ID

	eip1559Request := Transactions.EIP1559Request{
		To:                   bobAddress,
		Gas:                  gasLimit,
		MaxFeePerGas:         gasPrice,
		MaxPriorityFeePerGas: big.NewInt(2000000000), // 2 Gwei
		Value:                value,
		Nonce:                nonce,
		Data:                 nil,
		ChainId:              chainID,
		AccessList:           nil,
	}

	fmt.Printf("EIP1559Request: %+v\n", eip1559Request)
}
