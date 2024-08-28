package integration_test

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/mycel-labs/transferable-account/src/go/framework"
	"github.com/stretchr/testify/assert"
)

const (
	taStoreContractPath = "TransferableAccountStore.sol/TransferableAccountStore.json"
	fundedAddress       = "0xBE69d72ca5f88aCba033a063dF5DBe43a4148De0"
)

var (
	fr              *framework.Framework
	taStoreContract *framework.Contract
)

type TimedSignature struct {
	ValidFor    uint64
	MessageHash [32]byte
	Signature   []byte
	Signer      common.Address
}

func TestMain(m *testing.M) {
	// Setup
	t := &testing.T{}
	setup(t)

	// Run tests
	code := m.Run()

	// Exit with the test result code
	os.Exit(code)
}

func setup(_ *testing.T) {
	fr = framework.New()

	// Deploy contract
	taStoreContract = fr.Suave.DeployContract(taStoreContractPath)
}

func TestAuth(t *testing.T) {
	// Setup
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Test cases
	testCases := []struct {
		name        string
		validFor    int64
		modifySig   func([]byte) []byte
		expectValid bool
	}{
		{
			name:        "Valid signature",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			modifySig:   func(sig []byte) []byte { return sig },
			expectValid: true,
		},
		{
			name:        "Expired signature",
			validFor:    time.Now().Unix() - 86400, // 1 day ago
			modifySig:   func(sig []byte) []byte { return sig },
			expectValid: false,
		},
		{
			name:     "Invalid signature",
			validFor: time.Now().Unix() + 86400,
			modifySig: func(sig []byte) []byte {
				sig[0] ^= 0xFF // Flip all bits in the first byte
				return sig
			},
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			messageHash, signature, err := generateTimedSignature(tc.validFor, privKey)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			modifiedSignature := tc.modifySig(signature)

			sig := &TimedSignature{
				ValidFor:    uint64(tc.validFor),
				MessageHash: messageHash,
				Signature:   modifiedSignature,
				Signer:      crypto.PubkeyToAddress(privKey.PublicKey),
			}

			result := taStoreContract.Call("verifyTimedSignature", []interface{}{sig})
			if len(result) == 0 || result[0] == nil {
				t.Fatalf("empty result")
			}

			valid, ok := result[0].(bool)
			if !ok {
				t.Fatalf("valid data type is unexpected")
			}

			// Assert
			assert.Equal(t, tc.expectValid, valid, "Unexpected validation result")
		})
	}
}

/*
** Helper functions
 */

func generateTimedSignature(validFor int64, privateKey *ecdsa.PrivateKey) (messageHash [32]byte, signature []byte, err error) {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Step 1: Create the message hash
	// Combine validFor timestamp and signer's address, then hash with Keccak256
	messageHash = crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(validFor).Bytes(), 8),
		common.LeftPadBytes(address.Bytes(), 20),
	)

	// Step 2: Apply Ethereum-specific prefix
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
	// This ensures compatibility with Ethereum's signature standard
	signature[64] += 27

	return messageHash, signature, nil
}
