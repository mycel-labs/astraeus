package main

import (
	"encoding/hex"
	"log"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <hashedMessage> <signature>", os.Args[0])
	}

	hashedMessage, err := hex.DecodeString(os.Args[1])
	if err != nil {
		log.Fatalf("Failed to decode hashedMessage: %v", err)
	}

	signature, err := hex.DecodeString(os.Args[2])
	if err != nil {
		log.Fatalf("Failed to decode signature: %v", err)
	}

	sigPublicKey, err := crypto.SigToPub(hashedMessage, signature)
	if err != nil {
		panic(err)
	}
	println("Signature Public Key X: ", sigPublicKey.X.String())
	println("Signature Public Key Y: ", sigPublicKey.Y.String())
	sigAddress := crypto.PubkeyToAddress(*sigPublicKey)
	println("Signature Address: ", sigAddress.String())
}
