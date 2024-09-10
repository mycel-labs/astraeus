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
			_, resp, err := testutil.CreateAccount(request)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)
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
			createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Transfer account
			transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			request := &pb.TransferAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     transferSig,
				},
				To: tc.to,
			}
			_, resp, err = testutil.TransferAccount(request)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)
		})
	}
}

func TestDeleteAccountE2E(t *testing.T) {
	// Setup keys for Alice (account creator)
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	bobPrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	// Define test cases for deletion
	testCases := []struct {
		name        string
		validFor    int64
		creator     *ecdsa.PrivateKey
		sender      *ecdsa.PrivateKey
		expectValid bool
	}{
		{
			name:        "Valid deletion",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			creator:     alicePrivKey,
			sender:      alicePrivKey,
			expectValid: true,
		},
		{
			name:        "Invalid sender",
			validFor:    time.Now().Unix() + 86400,
			creator:     alicePrivKey,
			sender:      bobPrivKey,
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Create account
			createSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			createAccountRequest := &pb.CreateAccountRequest{
				Proof: createSig,
			}
			createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Step 2: Unlock the account
			unlockSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			unlockAccountRequest := &pb.UnlockAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     unlockSig,
				},
			}
			_, resp, err = testutil.UnlockAccount(unlockAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Step 3: Delete the account
			deleteSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)

			deleteAccountRequest := &pb.DeleteAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     deleteSig,
				},
			}

			_, resp, err = testutil.DeleteAccount(deleteAccountRequest)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)
		})
	}
}

func TestUnlockAccountE2E(t *testing.T) {
	// Setup keys for Alice (account creator)
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	bobPrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	// Define test cases for deletion
	testCases := []struct {
		name        string
		validFor    int64
		creator     *ecdsa.PrivateKey
		sender      *ecdsa.PrivateKey
		expectValid bool
	}{
		{
			name:        "Valid unlocking",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			creator:     alicePrivKey,
			sender:      alicePrivKey,
			expectValid: true,
		},
		{
			name:        "Invalid sender",
			validFor:    time.Now().Unix() + 86400,
			creator:     alicePrivKey,
			sender:      bobPrivKey,
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Create account
			createSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			createAccountRequest := &pb.CreateAccountRequest{
				Proof: createSig,
			}
			createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Step 2: Unlock the account
			unlockSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			unlockAccountRequest := &pb.UnlockAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     unlockSig,
				},
			}
			_, resp, err = testutil.UnlockAccount(unlockAccountRequest)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)
		})
	}
}

func TestApproveAddressE2E(t *testing.T) {
	// Setup keys for Alice (account creator)
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	bobPrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	// Define test cases for deletion
	testCases := []struct {
		name        string
		validFor    int64
		creator     *ecdsa.PrivateKey
		sender      *ecdsa.PrivateKey
		to          *ecdsa.PrivateKey
		expectValid bool
	}{
		{
			name:        "Valid approval",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			creator:     alicePrivKey,
			sender:      alicePrivKey,
			to:          bobPrivKey,
			expectValid: true,
		},
		{
			name:        "Invalid sender",
			validFor:    time.Now().Unix() + 86400,
			creator:     alicePrivKey,
			sender:      bobPrivKey,
			to:          bobPrivKey,
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Create account
			createSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			createAccountRequest := &pb.CreateAccountRequest{
				Proof: createSig,
			}
			createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Step 2: Approve the account
			approveSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			approveAddressRequest := &pb.ApproveAddressRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     approveSig,
				},
				Address: tc.to.PublicKey.X.String(),
			}
			_, resp, err = testutil.ApproveAddress(approveAddressRequest)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)

			// Step 3: Check if the address is approved
			if tc.expectValid {
				transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				transferRequest := &pb.TransferAccountRequest{
					Base: &pb.AccountOperationRequest{
						AccountId: createAccountResponse.AccountId,
						Proof:     transferSig,
					},
					To: tc.to.PublicKey.X.String(),
				}
				_, resp, err = testutil.TransferAccount(transferRequest)
				assert.Equal(t, true, resp.StatusCode == 200)
			}
		})
	}
}

func TestRevokeApprovalE2E(t *testing.T) {
	// Setup keys for Alice (account creator)
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	bobPrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	// Define test cases for deletion
	testCases := []struct {
		name        string
		validFor    int64
		creator     *ecdsa.PrivateKey
		sender      *ecdsa.PrivateKey
		to          *ecdsa.PrivateKey
		expectValid bool
	}{
		{
			name:        "Valid revocation",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			creator:     alicePrivKey,
			sender:      alicePrivKey,
			to:          bobPrivKey,
			expectValid: true,
		},
		{
			name:        "Invalid sender",
			validFor:    time.Now().Unix() + 86400,
			creator:     alicePrivKey,
			sender:      bobPrivKey,
			to:          bobPrivKey,
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Create account
			createSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			createAccountRequest := &pb.CreateAccountRequest{
				Proof: createSig,
			}
			createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Step 2: Approve the account
			approveSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			approveAddressRequest := &pb.ApproveAddressRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     approveSig,
				},
				Address: tc.to.PublicKey.X.String(),
			}
			_, resp, err = testutil.ApproveAddress(approveAddressRequest)
			assert.Equal(t, true, resp.StatusCode == 200)

			// Step 3: Revoke the approval
			revokeSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}
			revokeApprovalRequest := &pb.RevokeApprovalRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     revokeSig,
				},
				Address: tc.to.PublicKey.X.String(),
			}
			_, resp, err = testutil.RevokeApproval(revokeApprovalRequest)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)

			// Step 4: Check if the address is revoked
			if tc.expectValid {
				transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.to)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				transferRequest := &pb.TransferAccountRequest{
					Base: &pb.AccountOperationRequest{
						AccountId: createAccountResponse.AccountId,
						Proof:     transferSig,
					},
					To: tc.to.PublicKey.X.String(),
				}
				_, resp, err = testutil.TransferAccount(transferRequest)
				assert.Equal(t, false, resp.StatusCode == 200)
			}
		})
	}
}

func TestSignE2E(t *testing.T) {
	// Setup keys for Alice (account creator)
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	bobPrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	// Define test cases for deletion
	testCases := []struct {
		name        string
		validFor    int64
		creator     *ecdsa.PrivateKey
		sender      *ecdsa.PrivateKey
		fn          func()
		expectValid bool
	}{
		{
			name:        "Valid signing",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			creator:     alicePrivKey,
			sender:      alicePrivKey,
			expectValid: true,
		},
		{
			name:        "Invalid sender",
			validFor:    time.Now().Unix() + 86400,
			creator:     alicePrivKey,
			sender:      bobPrivKey,
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Step 1: Create account
			createSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			createAccountRequest := &pb.CreateAccountRequest{
				Proof: createSig,
			}
			createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Step 2: Unlock the account
			unlockSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.creator)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			unlockAccountRequest := &pb.UnlockAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     unlockSig,
				},
			}
			_, resp, err = testutil.UnlockAccount(unlockAccountRequest)
			assert.Equal(t, true, resp.StatusCode == 200)

			// Step 3: Sign the message
			signSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			signRequest := &pb.SignRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     signSig,
				},
				Data: "Hello, World!",
			}
			_, resp, err = testutil.Sign(signRequest)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)
		})
	}
}
