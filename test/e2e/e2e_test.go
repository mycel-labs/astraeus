package e2e_test

import (
	"crypto/ecdsa"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/mycel-labs/transferable-account/src/go/framework"
	"github.com/mycel-labs/transferable-account/src/go/pb/api/v1"
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
			timedSignature, err := testutil.GenerateTimedSignature(tc.validFor, privKey)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			request := &pb.CreateAccountRequest{
				Proof: timedSignature,
			}
			createAccountResponse, StatusCode, err := testutil.CreateAccount(request)
			fmt.Println("createAccountResponse", createAccountResponse)
			valid := StatusCode == 200

			assert.Equal(t, tc.expectValid, valid)
		})
	}
}
func TestTransferAccountE2E(t *testing.T) {
	// setup
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	bobPrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	testCases := []struct {
		name        string
		validFor    int64
		creator     *ecdsa.PrivateKey
		sender      *ecdsa.PrivateKey
		to          string
		expectValid bool
	}{
		{
			name:        "Valid transfer",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			creator:     alicePrivKey,
			sender:      alicePrivKey,
			to:          bobPrivKey.PublicKey.X.String(),
			expectValid: true,
		},
		{
			name:        "Invalid sender",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			creator:     alicePrivKey,
			sender:      bobPrivKey,
			to:          bobPrivKey.PublicKey.X.String(),
      expectValid: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create account
			createSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}
			createAccountRequest := &pb.CreateAccountRequest{
				Proof: createSig,
			}
			createAccountResponse, statusCode, err := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, statusCode)

      // Transfer account
      transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			request := &pb.TransferAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     transferSig,
        },
				To: tc.to,
			}
			_, statusCode, err = testutil.TransferAccount(request)
			valid := statusCode == 200
			assert.Equal(t, tc.expectValid, valid)
		})
	}
}
