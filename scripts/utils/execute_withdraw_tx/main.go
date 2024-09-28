package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"crypto/ecdsa"
	"encoding/hex"
	"math/big"

	"github.com/joho/godotenv"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	pb "github.com/mycel-labs/transferable-account/src/go/pb/api/v1"
	testutil "github.com/mycel-labs/transferable-account/test/utils"
)

func calculateEthereumAddress(publicKeyX, publicKeyY string) (common.Address, error) {
	// Decode the hex-encoded X and Y coordinates
	xBytes, err := hex.DecodeString(publicKeyX)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to decode public key X: %v", err)
	}

	yBytes, err := hex.DecodeString(publicKeyY)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to decode public key Y: %v", err)
	}

	// Convert bytes to big.Int
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Create an ECDSA public key using the X and Y coordinates
	publicKey := ecdsa.PublicKey{
		Curve: crypto.S256(), // Use the secp256k1 curve, standard for Ethereum
		X:     x,
		Y:     y,
	}

	// Get the public key bytes (uncompressed form)
	publicKeyBytes := crypto.FromECDSAPub(&publicKey)

	// Hash the public key bytes using Keccak256 and take the last 20 bytes to get the address
	address := crypto.Keccak256Hash(publicKeyBytes[1:]).Hex()
	return common.HexToAddress(address), nil
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}

	if len(os.Args) != 5 {
		log.Fatalf("Usage: <TA's accountID> <TargetChainID> <ToAddress> <SendValue>")
	}

	accountId := os.Args[1]
	if common.HexToAddress(accountId) == (common.Address{}) {
		log.Fatalf("Invalid accountId: %s", os.Args[1])
	}

	chainId, ok := new(big.Int).SetString(os.Args[2], 10)
	if !ok {
		log.Fatalf("Invalid chain ID: %s", chainId)
	}
	bobAddress := common.HexToAddress(os.Args[3])
	if bobAddress == (common.Address{}) {
		log.Fatalf("Invalid address: %s", os.Args[3])
	}
	value, err := strconv.ParseFloat(os.Args[4], 64)
	if err != nil {
		log.Fatalf("Invalid value: %v", err)
	}
	valueInWei := big.NewInt(int64(value * 1e18))

	privateKeyBytes, err := hex.DecodeString(os.Getenv("PRIVATE_KEY"))
	if err != nil {
		log.Fatalf("failed to decode hex string: %v", err)
	}
	privKey, err := crypto.ToECDSA(privateKeyBytes)
	if err != nil {
		log.Fatalf("Failed to create private key: %v", err)
	}

	timedSignature, err := testutil.GenerateTimedSignature(time.Now().Unix()+86400, privKey)
	if err != nil {
		log.Fatalf("Failed to generate timed signature: %v", err)
	}

	getAccountRequest := &pb.GetAccountRequest{
		AccountId: accountId,
	}

	getAccountResponse, _, err := testutil.GetAccount(getAccountRequest)
	if err != nil {
		log.Fatalf("Failed to get account: %v", err)
	}
	log.Println("Get Account Response: ", getAccountResponse)

	x := getAccountResponse.Account.PublicKeyX
	y := getAccountResponse.Account.PublicKeyY

	accountAddress, err := calculateEthereumAddress(x, y)
	if err != nil {
		log.Fatalf("Failed to calculate Ethereum address: %v", err)
	}
	log.Println("Account Address: ", accountAddress)

	IsAccountLockedRequest := &pb.IsAccountLockedRequest{
		AccountId: accountId,
	}
	IsAccountLockedResponse, _, err := testutil.IsAccountLocked(IsAccountLockedRequest)
	if err != nil {
		log.Fatalf("Failed to IsAccountLockedRequest: %v", err)
	}
	isLocked := IsAccountLockedResponse.Result

	if isLocked {
		unlockAccountRequest := &pb.UnlockAccountRequest{
			Base: &pb.AccountOperationRequest{
				AccountId: accountId,
				Proof:     timedSignature,
			},
		}
		unlockAccountResponse, _, err := testutil.UnlockAccount(unlockAccountRequest)
		if err != nil {
			log.Fatalf("Failed to unlock account: %v", err)
		}
		log.Println("Unlock Account Response: ", unlockAccountResponse)
	}

	client, err := ethclient.Dial(os.Getenv("WITHDRAW_TESTNET_RPC"))
	if err != nil {
		log.Fatalf("Failed to connect to Ethereum client: %v", err)
	}

	nonce, err := client.PendingNonceAt(context.Background(), accountAddress)
	if err != nil {
		log.Fatalf("Failed to get next Tx nonce: %v", err)
	}

	suggestedGasPrice, err := client.SuggestGasPrice(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggested gas price: %v", err)
	}

	suggestedTipCap, err := client.SuggestGasTipCap(context.Background())
	if err != nil {
		log.Fatalf("Failed to get suggested gas tip cap: %v", err)
	}

	log.Printf("Suggested Gas Price: %v", suggestedGasPrice)
	log.Printf("Suggested Gas Tip Cap: %v", suggestedTipCap)

	// Create an Ethereum transaction (EIP-1559)
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   chainId,
		Nonce:     nonce,
		GasFeeCap: suggestedGasPrice,
		GasTipCap: suggestedTipCap,
		Gas:       21000, // Standard gas limit for a simple transfer
		To:        &bobAddress,
		Value:     valueInWei,
		Data:      []byte{},
	})

	signer := types.LatestSignerForChainID(tx.ChainId())
	txHash := signer.Hash(tx).Bytes()

	signRequest := &pb.SignRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: accountId,
			Proof:     timedSignature,
		},
		Data: hex.EncodeToString(txHash),
	}

	signResponse, _, err := testutil.Sign(signRequest)
	if err != nil {
		log.Fatalf("Failed to sign data: %v", err)
	}
	log.Println("Sign Response: ", signResponse)

	// Decode the signature from signResponse
	signature, err := hex.DecodeString(signResponse.Signature)
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}

	// Apply the signature to the transaction
	signedTx, err := tx.WithSignature(signer, signature)
	if err != nil {
		log.Fatalf("Failed to apply signature to transaction: %v", err)
	}

	sender, err := types.Sender(types.NewLondonSigner(tx.ChainId()), signedTx)
	if err != nil {
		log.Fatalf("Failed to get sender from signed transaction: %v", err)
	}
	log.Println("Sender Address: ", sender)

	// Deposit ETH to the account
	reader := bufio.NewReader(os.Stdin)
	fmt.Printf("You need to depoist send value & gas ETH to %s (y/n): ", accountAddress.Hex())
	confirmation, _ := reader.ReadString('\n')
	confirmation = strings.TrimSpace(strings.ToLower(confirmation))
	if confirmation != "y" {
		fmt.Println("Transaction canceled.")
		return
	}

	// Send the transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	log.Println("Transaction sent successfully! Tx Hash: ", signedTx.Hash().Hex())
}
