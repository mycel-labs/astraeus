package e2e_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/mycel-labs/transferable-account/src/go/framework"
	pb "github.com/mycel-labs/transferable-account/src/go/pb/api/v1"
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
			_, resp, _ := testutil.CreateAccount(request)
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
			createAccountResponse, resp, _ := testutil.CreateAccount(createAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Transfer account
			transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}
			request := &pb.TransferAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     transferSig,
				},
				To: tc.to,
			}
			_, resp, _ = testutil.TransferAccount(request)
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
			createAccountResponse, resp, _ := testutil.CreateAccount(createAccountRequest)
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
			_, resp, _ = testutil.UnlockAccount(unlockAccountRequest)
			assert.Equal(t, 200, resp.StatusCode)

			// Step 3: Delete the account
			deleteSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}
			deleteAccountRequest := &pb.DeleteAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     deleteSig,
				},
			}

			_, resp, _ = testutil.DeleteAccount(deleteAccountRequest)
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
			createAccountResponse, resp, _ := testutil.CreateAccount(createAccountRequest)
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
			_, resp, _ = testutil.UnlockAccount(unlockAccountRequest)
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
			createAccountResponse, resp, _ := testutil.CreateAccount(createAccountRequest)
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
			_, resp, _ = testutil.ApproveAddress(approveAddressRequest)
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
				_, resp, _ = testutil.TransferAccount(transferRequest)
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
			createAccountResponse, resp, _ := testutil.CreateAccount(createAccountRequest)
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
			_, resp, _ = testutil.ApproveAddress(approveAddressRequest)
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
			_, resp, _ = testutil.RevokeApproval(revokeApprovalRequest)
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
				_, resp, _ = testutil.TransferAccount(transferRequest)
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
			createAccountResponse, resp, _ := testutil.CreateAccount(createAccountRequest)
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
			_, resp, _ = testutil.UnlockAccount(unlockAccountRequest)
			assert.Equal(t, true, resp.StatusCode == 200)

			// Step 3: Sign the message
			signSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			message := []byte("Hello, World!")
			messageHash := crypto.Keccak256(message)

			signRequest := &pb.SignRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: createAccountResponse.AccountId,
					Proof:     signSig,
				},
				Data: hex.EncodeToString(messageHash),
			}
			_, resp, _ = testutil.Sign(signRequest)
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)
		})
	}
}

func TestGetAccountE2E(t *testing.T) {
	// Setup
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	testCases := []struct {
		name        string
		setupFunc   func() string
		expectValid bool
	}{
		{
			name: "Valid account retrieval",
			setupFunc: func() string {
				// Create an account
				createSig, err := testutil.GenerateTimedSignature(time.Now().Unix()+86400, alicePrivKey)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				createAccountRequest := &pb.CreateAccountRequest{
					Proof: createSig,
				}
				createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
				if err != nil {
					t.Fatalf("Failed to create account: %v", err)
				}
				assert.Equal(t, 200, resp.StatusCode)
				return createAccountResponse.AccountId
			},
			expectValid: true,
		},
		{
			name: "Invalid account ID",
			setupFunc: func() string {
				return "non_existent_account_id"
			},
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			accountId := tc.setupFunc()

			// Execute GetAccount request
			getAccountRequest := &pb.GetAccountRequest{
				AccountId: accountId,
			}
			getAccountResponse, resp, err := testutil.GetAccount(getAccountRequest)
			if err != nil {
				t.Fatalf("Failed to get account: %v", err)
			}

			// Verify the response
			if tc.expectValid {
				assert.Equal(t, 200, resp.StatusCode, "Expected successful account retrieval")

				// Verify the account details
				assert.Equal(t, accountId, getAccountResponse.Account.AccountId, "Account ID mismatch")
				assert.NotEmpty(t, getAccountResponse.Account.Owner, "Owner should not be empty")
				assert.True(t, getAccountResponse.Account.IsLocked, "Account should  be locked")
			} else {
				assert.Equal(t, 404, resp.StatusCode, "Expected not found status for invalid account ID")
			}
		})
	}
}

func TestIsApprovedE2E(t *testing.T) {
	// Setup
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key for Alice: %v", err)
	}
	bobPrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key for Bob: %v", err)
	}

	testCases := []struct {
		name        string
		setupFunc   func() (string, string)
		expectValid bool
	}{
		{
			name: "Approved address",
			setupFunc: func() (string, string) {
				// Create an account
				createSig, err := testutil.GenerateTimedSignature(time.Now().Unix()+86400, alicePrivKey)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				createAccountRequest := &pb.CreateAccountRequest{
					Proof: createSig,
				}
				createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
				if err != nil {
					t.Fatalf("Failed to create account: %v", err)
				}
				assert.Equal(t, 200, resp.StatusCode)

				// Approve Bob's address
				approveSig, err := testutil.GenerateTimedSignature(time.Now().Unix()+86400, alicePrivKey)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				approveAddressRequest := &pb.ApproveAddressRequest{
					Base: &pb.AccountOperationRequest{
						AccountId: createAccountResponse.AccountId,
						Proof:     approveSig,
					},
					Address: bobPrivKey.PublicKey.X.String(),
				}
				_, resp, err = testutil.ApproveAddress(approveAddressRequest)
				assert.NoError(t, err, "setup: failed to approve address")
				assert.Equal(t, 200, resp.StatusCode)

				return createAccountResponse.AccountId, bobPrivKey.PublicKey.X.String()
			},
			expectValid: true,
		},
		{
			name: "Non-approved address",
			setupFunc: func() (string, string) {
				// Create an account
				createSig, err := testutil.GenerateTimedSignature(time.Now().Unix()+86400, alicePrivKey)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				createAccountRequest := &pb.CreateAccountRequest{
					Proof: createSig,
				}
				createAccountResponse, resp, err := testutil.CreateAccount(createAccountRequest)
				if err != nil {
					t.Fatalf("Failed to create account: %v", err)
				}
				assert.Equal(t, 200, resp.StatusCode)

				return createAccountResponse.AccountId, bobPrivKey.PublicKey.X.String()
			},
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			accountId, address := tc.setupFunc()

			// Execute IsApproved request
			isApprovedRequest := &pb.IsApprovedRequest{
				AccountId: accountId,
				Address:   address,
			}
			isApprovedResponse, resp, err := testutil.IsApproved(isApprovedRequest)
			assert.NoError(t, err, "Failed to get IsApproved response")

			// Verify the response
			if tc.expectValid {
				assert.Equal(t, 200, resp.StatusCode, "Expected successful IsApproved check")
				assert.True(t, isApprovedResponse.Result, "Expected address to be approved")
			} else {
				assert.Equal(t, 200, resp.StatusCode, "Expected successful IsApproved check")
				assert.False(t, isApprovedResponse.Result, "Expected address to not be approved")
			}
		})
	}
}
