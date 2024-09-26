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
	testutil "github.com/mycel-labs/transferable-account/test/utils"
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


  // Set PRIVATE_KEY environment variable for testing
	err = os.Setenv("PRIVATE_KEY", "91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12")
	if err != nil {
		fmt.Println("Error setting environment variable:", err)
	}

  // Set RPC URL
  err = os.Setenv("RPC_URL", "http://localhost:8545")
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
			if tc.expectValid && err != nil {
				t.Fatalf("Failed to create account: %v", err)
			}
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
			accountId := testutil.CreateAccountHelper(t, tc.creator)

			// Transfer account
			transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}
			request := &pb.TransferAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: accountId,
					Proof:     transferSig,
				},
				To: tc.to,
			}
			_, resp, err := testutil.TransferAccount(request)
			if tc.expectValid && err != nil {
				t.Fatalf("Failed to transfer account: %v", err)
			}
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
			accountId := testutil.CreateAccountHelper(t, tc.creator)

			// Step 2: Unlock the account
			testutil.UnlockAccountHelper(t, accountId, tc.creator)

			// Step 3: Delete the account
			deleteSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}
			deleteAccountRequest := &pb.DeleteAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: accountId,
					Proof:     deleteSig,
				},
			}

			_, resp, err := testutil.DeleteAccount(deleteAccountRequest)
			if tc.expectValid && err != nil {
				t.Fatalf("Failed to delete account: %v", err)
			}
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
			accountId := testutil.CreateAccountHelper(t, tc.creator)

			// Step 2: Unlock the account
			unlockSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			unlockAccountRequest := &pb.UnlockAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: accountId,
					Proof:     unlockSig,
				},
			}
			_, resp, err := testutil.UnlockAccount(unlockAccountRequest)
			if tc.expectValid && err != nil {
				t.Fatalf("Failed to unlock account: %v", err)
			}
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
			accountId := testutil.CreateAccountHelper(t, tc.creator)

			// Step 2: Approve the account
			approveSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			approveAddressRequest := &pb.ApproveAddressRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: accountId,
					Proof:     approveSig,
				},
				Address: tc.to.PublicKey.X.String(),
			}
			_, resp, err := testutil.ApproveAddress(approveAddressRequest)
			if tc.expectValid && err != nil {
				t.Fatalf("Failed to approve address: %v", err)
			}
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)

			// Step 3: Check if the address is approved
			if tc.expectValid {
				transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				transferRequest := &pb.TransferAccountRequest{
					Base: &pb.AccountOperationRequest{
						AccountId: accountId,
						Proof:     transferSig,
					},
					To: tc.to.PublicKey.X.String(),
				}
				_, resp, err = testutil.TransferAccount(transferRequest)
				if err != nil {
					t.Fatalf("Failed to transfer account: %v", err)
				}
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
			accountId := testutil.CreateAccountHelper(t, tc.creator)

			// Step 2: Approve the account
			testutil.ApproveAddressHelper(t, accountId, tc.creator, tc.to.PublicKey.X.String())

			// Step 3: Revoke the approval
			revokeSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}
			revokeApprovalRequest := &pb.RevokeApprovalRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: accountId,
					Proof:     revokeSig,
				},
				Address: tc.to.PublicKey.X.String(),
			}
			_, resp, err := testutil.RevokeApproval(revokeApprovalRequest)
			if tc.expectValid && err != nil {
				t.Fatalf("Failed to revoke approval: %v", err)
			}
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)

			// Step 4: Check if the address is revoked
			if tc.expectValid {
				transferSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.to)
				if err != nil {
					t.Fatalf("Failed to generate timed signature: %v", err)
				}
				transferRequest := &pb.TransferAccountRequest{
					Base: &pb.AccountOperationRequest{
						AccountId: accountId,
						Proof:     transferSig,
					},
					To: tc.to.PublicKey.X.String(),
				}
				_, resp, err = testutil.TransferAccount(transferRequest)
				assert.Error(t, err)
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
			accountId := testutil.CreateAccountHelper(t, tc.creator)

			// Step 2: Unlock the account
			testutil.UnlockAccountHelper(t, accountId, tc.creator)

			// Step 3: Sign the message
			signSig, err := testutil.GenerateTimedSignature(tc.validFor, tc.sender)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			message := []byte("Hello, World!")
			messageHash := crypto.Keccak256(message)

			signRequest := &pb.SignRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: accountId,
					Proof:     signSig,
				},
				Data: hex.EncodeToString(messageHash),
			}
			_, resp, err := testutil.Sign(signRequest)
			if tc.expectValid && err != nil {
				t.Fatalf("Failed to sign: %v", err)
			}
			assert.Equal(t, tc.expectValid, resp.StatusCode == 200)
		})
	}
}

func TestGetAccountE2E(t *testing.T) {
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
				return testutil.CreateAccountHelper(t, alicePrivKey)
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
			accountId := tc.setupFunc()

			getAccountRequest := &pb.GetAccountRequest{
				AccountId: accountId,
			}
			getAccountResponse, resp, err := testutil.GetAccount(getAccountRequest)
			if err != nil {
				t.Fatalf("Failed to get account: %v", err)
			}

			if tc.expectValid {
				assert.Equal(t, 200, resp.StatusCode, "Expected successful account retrieval")
				assert.Equal(t, accountId, getAccountResponse.Account.AccountId, "Account ID mismatch")
				assert.NotEmpty(t, getAccountResponse.Account.Owner, "Owner should not be empty")
				assert.True(t, getAccountResponse.Account.IsLocked, "Account should be locked")
			} else {
				assert.Equal(t, 404, resp.StatusCode, "Expected not found status for invalid account ID")
			}
		})
	}
}

func TestIsApprovedE2E(t *testing.T) {
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
				accountId := testutil.CreateAccountHelper(t, alicePrivKey)
				bobAddress := bobPrivKey.PublicKey.X.String()
				testutil.ApproveAddressHelper(t, accountId, alicePrivKey, bobAddress)
				return accountId, bobAddress
			},
			expectValid: true,
		},
		{
			name: "Non-approved address",
			setupFunc: func() (string, string) {
				accountId := testutil.CreateAccountHelper(t, alicePrivKey)
				return accountId, bobPrivKey.PublicKey.X.String()
			},
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accountId, address := tc.setupFunc()

			isApprovedRequest := &pb.IsApprovedRequest{
				AccountId: accountId,
				Address:   address,
			}
			isApprovedResponse, resp, err := testutil.IsApproved(isApprovedRequest)
			assert.NoError(t, err, "Failed to get IsApproved response")

			assert.Equal(t, 200, resp.StatusCode, "Expected successful IsApproved check")
			assert.Equal(t, tc.expectValid, isApprovedResponse.Result, "Unexpected IsApproved result")
		})
	}
}

func TestIsOwnerE2E(t *testing.T) {
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
		expectOwner bool
	}{
		{
			name: "Account owner",
			setupFunc: func() (string, string) {
				accountId := testutil.CreateAccountHelper(t, alicePrivKey)
				return accountId, crypto.PubkeyToAddress(alicePrivKey.PublicKey).Hex()
			},
			expectOwner: true,
		},
		{
			name: "Non-owner address",
			setupFunc: func() (string, string) {
				accountId := testutil.CreateAccountHelper(t, alicePrivKey)
				return accountId, crypto.PubkeyToAddress(bobPrivKey.PublicKey).Hex()
			},
			expectOwner: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accountId, address := tc.setupFunc()

			isOwnerRequest := &pb.IsOwnerRequest{
				AccountId: accountId,
				Address:   address,
			}
			isOwnerResponse, resp, err := testutil.IsOwner(isOwnerRequest)
			assert.NoError(t, err, "Failed to get IsOwner response")

			assert.Equal(t, 200, resp.StatusCode, "Expected successful IsOwner check")
			assert.Equal(t, tc.expectOwner, isOwnerResponse.Result, "Unexpected IsOwner result")
		})
	}
}

func TestIsAccountLockedE2E(t *testing.T) {
	alicePrivKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key for Alice: %v", err)
	}

	testCases := []struct {
		name         string
		setupFunc    func() string
		expectLocked bool
	}{
		{
			name: "Newly created account (locked)",
			setupFunc: func() string {
				return testutil.CreateAccountHelper(t, alicePrivKey)
			},
			expectLocked: true,
		},
		{
			name: "Unlocked account",
			setupFunc: func() string {
				accountId := testutil.CreateAccountHelper(t, alicePrivKey)
				testutil.UnlockAccountHelper(t, accountId, alicePrivKey)
				return accountId
			},
			expectLocked: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			accountId := tc.setupFunc()

			isAccountLockedRequest := &pb.IsAccountLockedRequest{
				AccountId: accountId,
			}
			isAccountLockedResponse, resp, err := testutil.IsAccountLocked(isAccountLockedRequest)
			assert.NoError(t, err, "Failed to get IsAccountLocked response")

			assert.Equal(t, 200, resp.StatusCode, "Expected successful IsAccountLocked check")
			assert.Equal(t, tc.expectLocked, isAccountLockedResponse.Result, "Unexpected IsAccountLocked result")
		})
	}
}
