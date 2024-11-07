package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"golang.org/x/crypto/sha3"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run main.go <function_signature>")
		fmt.Fprintln(os.Stderr, "Example: go run main.go \"transfer(address,uint256)\"")
		os.Exit(1)
	}

	argument := os.Args[1]
	if len(argument) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Empty input string")
		os.Exit(1)
	}

	hash := keccak256(argument)
	fmt.Printf("0x%s\n", hash)
}

func keccak256(input string) string {
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}
