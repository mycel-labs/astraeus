package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <argument>")
		os.Exit(1)
	}

	argument := os.Args[1]

	hash := keccak256(argument)
	fmt.Printf("0x%s\n", hash)
}

func keccak256(input string) string {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}
