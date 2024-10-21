package integration_test

import (
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	ct "github.com/mycel-labs/astraeus/src/go/contract"
	"github.com/mycel-labs/astraeus/src/go/framework"
	impl "github.com/mycel-labs/astraeus/src/go/server"
	testutil "github.com/mycel-labs/astraeus/test/utils"
	"github.com/stretchr/testify/assert"
)

var (
	fr              *framework.Framework
	taStoreContract *framework.Contract
	signTestUtil    *testutil.SignTestUtil
)

func TestMain(m *testing.M) {
	// Setup
	t := &testing.T{}
	setup(t)

	// Run tests
	code := m.Run()

	// Exit with the test result code
	os.Exit(code)
}

func setup(t *testing.T) {
	fr = framework.New()

	// Deploy contract
	taStoreContract = fr.Suave.DeployContract(testutil.TAStoreContractPath)
	signTestUtil = &testutil.SignTestUtil{
		T:               t,
		TaStoreContract: taStoreContract,
	}
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
		// {
		// 	name:        "Expired signature",
		// 	validFor:    time.Now().Unix() - 86400, // 1 day ago
		// 	modifySig:   func(sig []byte) []byte { return sig },
		// 	expectValid: false,
		// },
		// {
		// 	name:     "Invalid signature",
		// 	validFor: time.Now().Unix() + 86400,
		// 	modifySig: func(sig []byte) []byte {
		// 		sig[0] ^= 0xFF // Flip all bits in the first byte
		// 		return sig
		// 	},
		// 	expectValid: false,
		// },
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			functionHash := common.HexToHash(impl.CREATE_ACCOUNT_FUNCTION_HASH)
			timedSignature := signTestUtil.NewTimedSignature(privKey, functionHash)

			modifiedSignature := tc.modifySig([]byte(timedSignature.Signature))

			sig := &ct.SignatureVerifierTimedSignature{
				ValidFor:           timedSignature.ValidFor,
				MessageHash:        timedSignature.MessageHash,
				Signature:          modifiedSignature,
				Signer:             timedSignature.Signer,
				Nonce:              timedSignature.Nonce,
				TargetFunctionHash: timedSignature.TargetFunctionHash,
			}

			result := taStoreContract.Call("verifyTimedSignature", []interface{}{sig, timedSignature.TargetFunctionHash})
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
