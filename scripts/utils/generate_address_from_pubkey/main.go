package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"

	"golang.org/x/crypto/sha3"
)

// hexStringToBigInt converts a hex string to a big.Int
func hexStringToBigInt(hexStr string) (*big.Int, error) {
	bigInt := new(big.Int)
	_, success := bigInt.SetString(hexStr, 16)
	if !success {
		return nil, fmt.Errorf("invalid hex string: %s", hexStr)
	}
	return bigInt, nil
}

// generateAddress generates an Ethereum address from the given x and y coordinates of the public key
func generateAddress(x, y *big.Int) (string, error) {
	// Concatenate x and y coordinates
	publicKey := append(x.Bytes(), y.Bytes()...)

	// Compute Keccak-256 hash
	hash := sha3.NewLegacyKeccak256()
	hash.Write(publicKey)
	hashBytes := hash.Sum(nil)

	// Take the last 20 bytes of the hash
	address := hashBytes[len(hashBytes)-20:]

	return hex.EncodeToString(address), nil
}

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s <x-coordinate> <y-coordinate>", os.Args[0])
	}

	xHex := os.Args[1]
	yHex := os.Args[2]

	x, err := hexStringToBigInt(xHex)
	if err != nil {
		log.Fatalf("Invalid x-coordinate: %v", err)
	}

	y, err := hexStringToBigInt(yHex)
	if err != nil {
		log.Fatalf("Invalid y-coordinate: %v", err)
	}

	address, err := generateAddress(x, y)
	if err != nil {
		log.Fatalf("Failed to generate address: %v", err)
	}

	println("Signature Public Key X (Hex): ", xHex)
	println("Signature Public Key Y (Hex): ", yHex)
	println("Signature Public Key X (Decimal): ", new(big.Int).SetBytes(x.Bytes()).String())
	println("Signature Public Key Y (Decimal): ", new(big.Int).SetBytes(y.Bytes()).String())
	fmt.Printf("Ethereum Address: 0x%s\n", address)
}
