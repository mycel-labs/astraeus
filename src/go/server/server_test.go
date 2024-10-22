package server

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"

	ct "github.com/mycel-labs/astraeus/src/go/contract"
	framework "github.com/mycel-labs/astraeus/src/go/framework"
	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
)

var (
	fr         *framework.Framework
	accountId  string
	privateKey *ecdsa.PrivateKey
	s          *server
)

const fundedAddress = "0xBE69d72ca5f88aCba033a063dF5DBe43a4148De0"

// TestMain is used for test setup and teardown
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
	taStoreContract := fr.Suave.DeployContract(taStoreContractPath)
	os.Setenv("TA_STORE_CONTRACT_ADDRESS", taStoreContract.Contract.Address().Hex())

	// Initialize test data
	var err error
	privateKey, err = crypto.HexToECDSA("91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12")
	if err != nil {
		t.Fatalf("failed to convert hex to private key: %v", err)
	}
	rpcUrl := "http://localhost:8545"

	s, err = NewServer(rpcUrl, hex.EncodeToString(crypto.FromECDSA(privateKey)), taStoreContract.Contract.Address().Hex())
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
}

func TestCreateAccount(t *testing.T) {
	// Setup
	targetFunctionHash := common.HexToHash(CREATE_ACCOUNT_FUNCTION_HASH)
	sig := newPbTimedSignature(t, privateKey, targetFunctionHash)

	// Execute
	req := &pb.CreateAccountRequest{
		Proof: sig,
	}
	resp, err := s.CreateAccount(context.Background(), req)

	// Assert
	assert.NoError(t, err, "CreateAccount call should not return an error")
	assert.NotNil(t, resp, "Response should not be nil")
	assert.IsType(t, &pb.CreateAccountResponse{}, resp, "Response type is incorrect")
	assert.NotEmpty(t, resp.TxHash, "TxHash should not be empty")
	assert.NotEmpty(t, resp.AccountId, "Account ID should not be empty")

	// Verify the account was created
	accountReq := &pb.GetAccountRequest{AccountId: resp.AccountId}
	accountResp, err := s.GetAccount(context.Background(), accountReq)
	assert.NoError(t, err, "GetAccount call should not return an error")
	assert.NotNil(t, accountResp, "Account response should not be nil")
	assert.Equal(t, resp.AccountId, accountResp.Account.AccountId, "Account ID should match")
}

func TestGetAccount(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		expectErr bool
	}{
		{"Valid account", account.AccountId, false},
		{"Non-existent account", "non_existent_account_id", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.GetAccountRequest{AccountId: tc.accountID}
			resp, err := s.GetAccount(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
				assert.Contains(t, err.Error(), "account not found")
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
			}
		})
	}
}

func TestIsApproved(t *testing.T) {
	// Setup
	testAddress := common.HexToAddress("0x123456789012345678901234568901234567890")
	account := newAccount(t, privateKey)
	targetFunctionHash := common.HexToHash(APPROVE_ADDRESS_FUNCTION_HASH)
	sig := newTimedSignature(t, privateKey, targetFunctionHash)
	tx, err := s.taStoreContractBind.ApproveAddress(s.auth, *sig, account.AccountId, testAddress)
	if err != nil {
		t.Fatalf("failed to approve address: %v", err)
	}
	log.Printf("tx: %v", tx)

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		address   string
		expected  bool
	}{
		{"Owner", account.AccountId, account.Owner, true},
		{"Approved address", account.AccountId, testAddress.String(), true},
		{"Not approved address", account.AccountId, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"Non-existent account ID", "non_existent_account_id", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.IsApprovedRequest{
				AccountId: tc.accountID,
				Address:   tc.address,
			}
			resp, err := s.IsApproved(context.Background(), req)

			// Assert
			assert.NoError(t, err, "IsApproved call should not return an error")
			assert.NotNil(t, resp, "Response should not be nil")
			assert.IsType(t, &pb.IsApprovedResponse{}, resp, "Response type is incorrect")
			assert.Equal(t, tc.expected, resp.Result, "Unexpected result for IsApproved")
		})
	}
}

func TestIsOwner(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		address   string
		expected  bool
	}{
		{"Is owner", account.AccountId, account.Owner, true},
		{"Not owner", account.AccountId, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"Non-existent account ID", "non_existent_account_id", fundedAddress, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.IsOwnerRequest{
				AccountId: tc.accountID,
				Address:   tc.address,
			}
			resp, err := s.IsOwner(context.Background(), req)

			// Assert
			assert.NoError(t, err, "IsOwner call should not return an error")
			assert.NotNil(t, resp, "Response should not be nil")
			assert.IsType(t, &pb.IsOwnerResponse{}, resp, "Response type is incorrect")
			assert.Equal(t, tc.expected, resp.Result, "Unexpected result for IsOwner")
		})
	}
}

func TestTransferAccount(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)
	newOwner := "0x1234567890123456789012345678901234567890"

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		to        string
		expectErr bool
	}{
		{"Valid transfer", account.AccountId, newOwner, false},
		{"Non-existent account", "non_existent_account_id", newOwner, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			targetFunctionHash := common.HexToHash(TRANSFER_ACCOUNT_FUNCTION_HASH)
			sig := newPbTimedSignature(t, privateKey, targetFunctionHash)
			req := &pb.TransferAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof:     sig,
				},
				To: tc.to,
			}
			resp, err := s.TransferAccount(context.Background(), req)

			// Assert
			if tc.expectErr {
				t.Logf("error: %v", err)
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.TxHash)

				// Verify the account was transferred
				accountReq := &pb.GetAccountRequest{AccountId: tc.accountId}
				accountResp, err := s.GetAccount(context.Background(), accountReq)
				assert.NoError(t, err)
				assert.NotNil(t, accountResp)
				assert.Equal(t, tc.to, accountResp.Account.Owner)
			}
		})
	}
}

func TestDeleteAccount(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		expectErr bool
	}{
		{"Valid deletion", account.AccountId, false},
		{"Non-existent account", "non_existent_account_id", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetFunctionHash := common.HexToHash(DELETE_ACCOUNT_FUNCTION_HASH)
			sig := newPbTimedSignature(t, privateKey, targetFunctionHash)
			// Execute
			req := &pb.DeleteAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof:     sig,
				},
			}
			resp, err := s.DeleteAccount(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.TxHash)

				// Verify the account was deleted
				accountReq := &pb.GetAccountRequest{AccountId: tc.accountId}
				_, err := s.GetAccount(context.Background(), accountReq)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "account not found")
			}
		})
	}
}

func TestUnlockAccount(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		expectErr bool
	}{
		{"Valid unlock", account.AccountId, false},
		{"Non-existent account", "non_existent_account_id", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetFunctionHash := common.HexToHash(UNLOCK_ACCOUNT_FUNCTION_HASH)
			sig := newPbTimedSignature(t, privateKey, targetFunctionHash)
			// Execute
			req := &pb.UnlockAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof:     sig,
				},
			}
			resp, err := s.UnlockAccount(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.TxHash)

				// Verify the account was unlocked
				isLockedReq := &pb.IsAccountLockedRequest{AccountId: tc.accountId}
				isLockedResp, err := s.IsAccountLocked(context.Background(), isLockedReq)
				assert.NoError(t, err)
				assert.NotNil(t, isLockedResp)
				assert.False(t, isLockedResp.Result)
			}
		})
	}
}

func TestApproveAddress(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)
	newApprovedAddress := "0x1234567890123456789012345678901234567890"
	targetFunctionHash := common.HexToHash(APPROVE_ADDRESS_FUNCTION_HASH)
	sig := newPbTimedSignature(t, privateKey, targetFunctionHash)

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		address   string
		expectErr bool
	}{
		{"Valid approval", account.AccountId, newApprovedAddress, false},
		{"Non-existent account", "non_existent_account_id", newApprovedAddress, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.ApproveAddressRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof:     sig,
				},
				Address: tc.address,
			}
			resp, err := s.ApproveAddress(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.TxHash)

				// Verify the address was approved
				isApprovedReq := &pb.IsApprovedRequest{
					AccountId: tc.accountId,
					Address:   tc.address,
				}
				isApprovedResp, err := s.IsApproved(context.Background(), isApprovedReq)
				assert.NoError(t, err)
				assert.NotNil(t, isApprovedResp)
				assert.True(t, isApprovedResp.Result)
			}
		})
	}
}

func TestRevokeApproval(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)
	addressToApprove := "0x1234567890123456789012345678901234567890"
	targetFunctionHashApprove := common.HexToHash(APPROVE_ADDRESS_FUNCTION_HASH)
	targetFunctionHashRevoke := common.HexToHash(REVOKE_APPROVAL_FUNCTION_HASH)
	sigApprove := newPbTimedSignature(t, privateKey, targetFunctionHashApprove)

	// Approve the address first
	approveReq := &pb.ApproveAddressRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: account.AccountId,
			Proof:     sigApprove,
		},
		Address: addressToApprove,
	}
	_, err := s.ApproveAddress(context.Background(), approveReq)
	assert.NoError(t, err, "ApproveAddress call should not return an error")

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		address   string
		expectErr bool
	}{
		{"Valid revocation", account.AccountId, addressToApprove, false},
		{"Non-existent account", "non_existent_account_id", addressToApprove, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			sigRevoke := newPbTimedSignature(t, privateKey, targetFunctionHashRevoke)
			revokeReq := &pb.RevokeApprovalRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof:     sigRevoke,
				},
				Address: tc.address,
			}
			resp, err := s.RevokeApproval(context.Background(), revokeReq)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.TxHash)

				// Verify the address was revoked
				isApprovedReq := &pb.IsApprovedRequest{
					AccountId: tc.accountId,
					Address:   tc.address,
				}
				isApprovedResp, err := s.IsApproved(context.Background(), isApprovedReq)
				assert.NoError(t, err)
				assert.NotNil(t, isApprovedResp)
				assert.False(t, isApprovedResp.Result)
			}
		})
	}
}

func TestGetNonce(t *testing.T) {
	// Setup
	signerAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce := getNonce(t, signerAddress)
	// Create a new account to increase the nonce
	newAccount(t, privateKey)

	// Test cases
	testCases := []struct {
		name      string
		address   string
		expectErr bool
		expected  uint64
	}{
		{"Valid nonce", signerAddress.Hex(), false, nonce + 1},
		{"Not used address", "0x0000000000000000000000000000000000000000", false, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.GetNonceRequest{
				Address: tc.address,
			}
			resp, err := s.GetNonce(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tc.expected, resp.Nonce)
			}
		})
	}
}

func TestIsAccountLocked(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		expectErr bool
		expected  bool
	}{
		{"Existing account", account.AccountId, false, true},              // Assuming newly created accounts are locked by default
		{"Non-existent account", "non_existent_account_id", false, false}, // Assuming non-existent accounts return false
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.IsAccountLockedRequest{
				AccountId: tc.accountID,
			}
			resp, err := s.IsAccountLocked(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.IsType(t, &pb.IsAccountLockedResponse{}, resp)
				assert.Equal(t, tc.expected, resp.Result)
			}
		})
	}
}

func TestSign(t *testing.T) {
	// Setup
	account := newAccount(t, privateKey)

	targetFunctionHashUnlock := common.HexToHash(UNLOCK_ACCOUNT_FUNCTION_HASH)
	_, err := s.UnlockAccount(context.Background(), &pb.UnlockAccountRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: account.AccountId,
			Proof:     newPbTimedSignature(t, privateKey, targetFunctionHashUnlock),
		},
	})
	assert.NoError(t, err)

	message := []byte("Test message to sign")
	messageHash := crypto.Keccak256(message)
	messageHashHex := hex.EncodeToString(messageHash)

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		data      string
		expectErr bool
	}{
		{"Valid signing", account.AccountId, messageHashHex, false},
		{"Non-existent account", "non_existent_account_id", messageHashHex, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			targetFunctionHashSign := common.HexToHash(SIGN_FUNCTION_HASH)
			sig := newPbTimedSignature(t, privateKey, targetFunctionHashSign)
			// Execute
			req := &pb.SignRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof:     sig,
				},
				Data: tc.data,
			}
			resp, err := s.Sign(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.TxHash)

				// Recover the public key from the account
				accountResp, err := s.GetAccount(context.Background(), &pb.GetAccountRequest{AccountId: tc.accountId})
				assert.NoError(t, err)

				t.Logf("Original pubKeyX: %v", accountResp.Account.PublicKeyX)
				t.Logf("Original pubKeyY: %v", accountResp.Account.PublicKeyY)

				pubKeyX, ok := new(big.Int).SetString(accountResp.Account.PublicKeyX, 16)
				assert.True(t, ok, "Failed to parse pubKeyX")
				t.Logf("Parsed pubKeyX: %v", pubKeyX)

				pubKeyY, ok := new(big.Int).SetString(accountResp.Account.PublicKeyY, 16)
				assert.True(t, ok, "Failed to parse pubKeyY")
				t.Logf("Parsed pubKeyY: %v", pubKeyY)

				pubKey := ecdsa.PublicKey{
					Curve: crypto.S256(),
					X:     pubKeyX,
					Y:     pubKeyY,
				}

				t.Logf("Final pubKey: %+v", pubKey)

				signatureBytes, err := hex.DecodeString(resp.Signature)
				assert.NoError(t, err)
				t.Logf("Signature: %x", signatureBytes)

				if len(signatureBytes) != 65 {
					t.Fatalf("Invalid signature length: expected 65, got %d", len(signatureBytes))
				}

				signature := signatureBytes[:64]
				recoveryID := signatureBytes[64]

				messageHash, err := hex.DecodeString(tc.data)
				assert.NoError(t, err)
				t.Logf("Message hash: %x", messageHash)

				sigPublicKey, err := crypto.Ecrecover(messageHash, append(signature, recoveryID))
				assert.NoError(t, err)

				recoveredPubKey, err := crypto.UnmarshalPubkey(sigPublicKey)
				assert.NoError(t, err)
				t.Logf("Recovered pubKey: %+v", recoveredPubKey)

				assert.Equal(t, pubKey, *recoveredPubKey, "Recovered public key does not match the account's public key")

				isValid := crypto.VerifySignature(sigPublicKey, messageHash, signature)
				assert.True(t, isValid, "Signature verification failed")
			}
		})
	}
}

/*
 * Helpers
 */
func getNonce(t *testing.T, address common.Address) uint64 {
	nonce, err := s.taStoreContractBind.Nonces(&bind.CallOpts{}, address)
	if err != nil {
		t.Fatalf("Failed to get nonce: %v", err)
	}
	return nonce
}

func newAccount(t *testing.T, privateKey *ecdsa.PrivateKey) *pb.Account {
	targetFunctionHash := common.HexToHash(CREATE_ACCOUNT_FUNCTION_HASH)
	sig := newTimedSignature(t, privateKey, targetFunctionHash)
	receipt := s.taStoreContract.SendConfidentialRequest("createAccount", []interface{}{sig}, nil)
	ev, err := s.taStoreContract.Abi.Events["AccountCreated"].ParseLog(receipt.Logs[0])
	if err != nil {
		t.Fatalf("failed to parse log: %v", err)
	}
	accountId = ev["accountId"].(string)

	return &pb.Account{
		AccountId: accountId,
		Owner:     crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
	}
}

func newPbTimedSignature(t *testing.T, privateKey *ecdsa.PrivateKey, targetFunctionHash [32]byte) *pb.TimedSignature {
	sig := _newTimedSignature(t, privateKey, targetFunctionHash)
	return &pb.TimedSignature{
		ValidFor:           sig.ValidFor,
		MessageHash:        hex.EncodeToString(sig.MessageHash[:]),
		Signature:          hex.EncodeToString(sig.Signature),
		Signer:             sig.Signer.Hex(),
		Nonce:              sig.Nonce,
		TargetFunctionHash: hex.EncodeToString(sig.TargetFunctionHash[:]),
	}
}

func newTimedSignature(t *testing.T, privateKey *ecdsa.PrivateKey, targetFunctionHash [32]byte) *ct.SignatureVerifierTimedSignature {
	return _newTimedSignature(t, privateKey, targetFunctionHash)
}

func _newTimedSignature(t *testing.T, privateKey *ecdsa.PrivateKey, targetFunctionHash [32]byte) *ct.SignatureVerifierTimedSignature {
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	nonce := getNonce(t, crypto.PubkeyToAddress(privateKey.PublicKey))
	messageHash, signature, err := generateTimedSignature(int64(validFor), privateKey, nonce, targetFunctionHash)
	if err != nil {
		t.Fatalf("failed to generate timed signature: %v", err)
	}
	return &ct.SignatureVerifierTimedSignature{
		ValidFor:           validFor,
		MessageHash:        messageHash,
		Signature:          signature,
		Signer:             crypto.PubkeyToAddress(privateKey.PublicKey),
		Nonce:              nonce,
		TargetFunctionHash: targetFunctionHash,
	}
}

func generateTimedSignature(validFor int64, privateKey *ecdsa.PrivateKey, nonce uint64, targetFunctionHash [32]byte) (messageHash [32]byte, signature []byte, err error) {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Step 1: Create the message hash
	// Combine validFor timestamp, signer's address, nonce, and targetFunctionHash, then hash with Keccak256
	messageHash = crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(validFor).Bytes(), 8),
		common.LeftPadBytes(address.Bytes(), 20),
		common.LeftPadBytes(big.NewInt(int64(nonce)).Bytes(), 8),
		targetFunctionHash[:],
	)

	// Step 2: Apply Mycel-specific prefix
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
	// This ensures compatibility with Mycel's signature standard
	signature[64] += 27

	return messageHash, signature, nil
}
