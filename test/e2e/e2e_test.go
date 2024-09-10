package e2e_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/mycel-labs/transferable-account/src/go/framework"
	"github.com/mycel-labs/transferable-account/testutil"
)

var (
	fr              *framework.Framework
	taStoreContract *framework.Contract
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
	// Start SUAVE server
	if err := testutil.StartSUAVEServer(); err != nil {
		t.Fatalf("Failed to start SUAVE server: %v", err)
	}
	// Deploy contract
	fr = framework.New()
	taStoreContract = fr.Suave.DeployContract(testutil.TAStoreContractPath)
	contractAddress := taStoreContract.Contract.Address().String()
	err := os.Setenv("TA_STORE_CONTRACT_ADDRESS", contractAddress)
	if err != nil {
		fmt.Println("Error setting environment variable:", err)
	}

	// Generate private key
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	err = os.Setenv("PRIVATE_KEY", privKey.X.String())
	if err != nil {
		fmt.Println("Error setting environment variable:", err)
	}

  // Start Astraeus server
	testutil.StartAstraeusServer()
}

func TestCreateAccountE2E(t *testing.T) {
	// Setup
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	testCases := []struct {
		name        string
		validFor    int64
		expectValid bool
	}{
		{
			name:        "Valid signature",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			expectValid: true,
		},
		{
			name:        "Expired signature",
			validFor:    time.Now().Unix() - 86400, // 1 day ago
			expectValid: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			messageHash, signature, err := testutil.GenerateTimedSignature(tc.validFor, privKey)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			timedSignature := testutil.TimedSignature{
				ValidFor:    uint64(tc.validFor),
				MessageHash: messageHash,
				Signature:   signature,
				Signer:      crypto.PubkeyToAddress(privKey.PublicKey),
			}

			response := testutil.CreateAccount(timedSignature)
			valid := response.StatusCode == 200

			assert.Equal(t, tc.expectValid, valid)
		})
	}

}
