package main

import (
	"context"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/joho/godotenv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
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

	tx := types.NewTransaction(nonce, bobAddress, value, gasLimit, gasPrice, nil)

	JsonTx, err := tx.MarshalJSON()
	if err != nil {
		log.Fatalf("Failed to marshal transaction: %v", err)
	}

	fmt.Printf("Unsigned Transaction (JSON): %x\n", JsonTx)
	rlpEncodedTx, err := rlp.EncodeToBytes(tx)
	if err != nil {
		log.Fatalf("Failed to RLP encode transaction: %v", err)
	}
	fmt.Printf("Unsigned Transaction (RLP): %x\n", rlpEncodedTx)
	hashedTx := crypto.Keccak256([]byte(rlpEncodedTx))
	fmt.Printf("Unsigned Hashed Transaction: %x\n", hashedTx)
}
