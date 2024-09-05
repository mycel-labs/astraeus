package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"

	framework "github.com/mycel-labs/transferable-account/src/go/framework"
	pb "github.com/mycel-labs/transferable-account/src/go/pb"
)

var (
	fr              *framework.Framework
	taStoreContract *framework.Contract
	accountId       string
	privateKey      *ecdsa.PrivateKey
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
	taStoreContract = fr.Suave.DeployContract(taStoreContractPath)
	os.Setenv("TA_STORE_CONTRACT_ADDRESS", taStoreContract.Contract.Address().Hex())

	// Initialize test data
	var err error
	privateKey, err = crypto.HexToECDSA("91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12")
	if err != nil {
		t.Fatalf("failed to convert hex to private key: %v", err)
	}
}

func createAccount(t *testing.T, privateKey *ecdsa.PrivateKey) *pb.Account {
	sig := newTimedSignature(t, privateKey)
	receipt := taStoreContract.SendConfidentialRequest("createAccount", []interface{}{sig}, nil)
	ev, err := taStoreContract.Abi.Events["AccountCreated"].ParseLog(receipt.Logs[0])
	if err != nil {
		t.Fatalf("failed to parse log: %v", err)
	}
	accountId = ev["accountId"].(string)

	return &pb.Account{
		AccountId: accountId,
		Owner:     crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
	}
}

func newPbTimedSignature(t *testing.T, privateKey *ecdsa.PrivateKey) *pb.TimedSignature {
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	messageHash, signature, err := generateTimedSignature(int64(validFor), privateKey)
	if err != nil {
		t.Fatalf("failed to generate timed signature: %v", err)
	}
	return &pb.TimedSignature{
		ValidFor:    validFor,
		MessageHash: messageHash[:],
		Signature:   signature,
		Signer:      fundedAddress,
	}
}

func newTimedSignature(t *testing.T, privateKey *ecdsa.PrivateKey) *TimedSignature {
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	messageHash, signature, err := generateTimedSignature(int64(validFor), privateKey)
	if err != nil {
		t.Fatalf("failed to generate timed signature: %v", err)
	}
	sig := &TimedSignature{
		ValidFor:    validFor,
		MessageHash: messageHash,
		Signature:   signature,
		Signer:      crypto.PubkeyToAddress(privateKey.PublicKey),
	}
	return sig
}

func generateTimedSignature(validFor int64, privateKey *ecdsa.PrivateKey) (messageHash [32]byte, signature []byte, err error) {
	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	// Step 1: Create the message hash
	// Combine validFor timestamp and signer's address, then hash with Keccak256
	messageHash = crypto.Keccak256Hash(
		common.LeftPadBytes(big.NewInt(validFor).Bytes(), 8),
		common.LeftPadBytes(address.Bytes(), 20),
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

func TestCreateAccount(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}
	sig := newTimedSignature(t, privateKey)

	// Execute
	req := &pb.CreateAccountRequest{
		Proof: &pb.TimedSignature{
			ValidFor:    sig.ValidFor,
			MessageHash: sig.MessageHash[:],
			Signature:   sig.Signature,
			Signer:      sig.Signer.Hex(),
		},
	}
	resp, err := s.CreateAccount(context.Background(), req)

	// Assert
	assert.NoError(t, err, "CreateAccount call should not return an error")
	assert.NotNil(t, resp, "Response should not be nil")
	assert.IsType(t, &pb.BytesResponse{}, resp, "Response type is incorrect")
	assert.NotEmpty(t, resp.Data, "Account ID should not be empty")

	// Verify the account was created
	accountReq := &pb.AccountIdRequest{AccountId: string(resp.Data)}
	accountResp, err := s.GetAccount(context.Background(), accountReq)
	assert.NoError(t, err, "GetAccount call should not return an error")
	assert.NotNil(t, accountResp, "Account response should not be nil")
	assert.Equal(t, string(resp.Data), accountResp.Account.AccountId, "Account ID should match")
}

func TestGetAccount(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)

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
			req := &pb.AccountIdRequest{AccountId: tc.accountID}
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
	s := &server{
		taStoreContract: taStoreContract,
	}
	testAddress := common.HexToAddress("0x1234567890123456789012345678901234567890")
	sig := newTimedSignature(t, privateKey)
	s.taStoreContract.SendConfidentialRequest("approveAddress", []interface{}{sig, accountId, testAddress}, nil)

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		address   string
		expected  bool
	}{
		{"Approved address", accountId, testAddress.String(), true},
		{"Not approved address", accountId, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"Non-existent account ID", "non_existent_account_id", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.AccountIdToAddressRequest{
				AccountId: tc.accountID,
				Address:   tc.address,
			}
			resp, err := s.IsApproved(context.Background(), req)

			// Assert
			assert.NoError(t, err, "IsApproved call should not return an error")
			assert.NotNil(t, resp, "Response should not be nil")
			assert.IsType(t, &pb.BoolResponse{}, resp, "Response type is incorrect")
			assert.Equal(t, tc.expected, resp.Result, "Unexpected result for IsApproved")
		})
	}
}

func TestIsOwner(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		address   string
		expected  bool
	}{
		{"Is owner", accountId, fundedAddress, true},
		{"Not owner", accountId, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", false},
		{"Non-existent account ID", "non_existent_account_id", fundedAddress, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.AccountIdToAddressRequest{
				AccountId: tc.accountID,
				Address:   tc.address,
			}
			resp, err := s.IsOwner(context.Background(), req)

			// Assert
			assert.NoError(t, err, "IsOwner call should not return an error")
			assert.NotNil(t, resp, "Response should not be nil")
			assert.IsType(t, &pb.BoolResponse{}, resp, "Response type is incorrect")
			assert.Equal(t, tc.expected, resp.Result, "Unexpected result for IsOwner")
		})
	}
}

func TestTransferAccount(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)
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
			sig := newPbTimedSignature(t, privateKey)
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
				assert.Equal(t, tc.accountId, string(resp.Data))

				// Verify the account was transferred
				accountReq := &pb.AccountIdRequest{AccountId: tc.accountId}
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
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)

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
			sig := newPbTimedSignature(t, privateKey)
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
				assert.Equal(t, tc.accountId, string(resp.Data))

				// Verify the account was deleted
				accountReq := &pb.AccountIdRequest{AccountId: tc.accountId}
				_, err := s.GetAccount(context.Background(), accountReq)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "account not found")
			}
		})
	}
}

func TestUnlockAccount(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)

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
			sig := newPbTimedSignature(t, privateKey)
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
				assert.Equal(t, tc.accountId, string(resp.Data))

				// Verify the account was unlocked
				isLockedReq := &pb.AccountIdRequest{AccountId: tc.accountId}
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
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)
	newApprovedAddress := "0x1234567890123456789012345678901234567890"
	sig := newPbTimedSignature(t, privateKey)

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
				assert.Equal(t, tc.accountId, string(resp.Data))

				// Verify the address was approved
				isApprovedReq := &pb.AccountIdToAddressRequest{
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
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)
	addressToApprove := "0x1234567890123456789012345678901234567890"
	sig := newPbTimedSignature(t, privateKey)

	// Approve the address first
	approveReq := &pb.ApproveAddressRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: account.AccountId,
			Proof:     sig,
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
			req := &pb.RevokeApprovalRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof:     sig,
				},
				Address: tc.address,
			}
			resp, err := s.RevokeApproval(context.Background(), req)

			// Assert
			if tc.expectErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Result)

				// Verify the address was revoked
				isApprovedReq := &pb.AccountIdToAddressRequest{
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

func TestIsAccountLocked(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)

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
			req := &pb.AccountIdRequest{
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
				assert.IsType(t, &pb.BoolResponse{}, resp)
				assert.Equal(t, tc.expected, resp.Result)
			}
		})
	}
}

func TestSign(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}
	account := createAccount(t, privateKey)
	sig := newTimedSignature(t, privateKey)

	taStoreContract.SendConfidentialRequest("unlockAccount", []interface{}{sig, account.AccountId}, nil)

	message := []byte("Test message to sign")
	messageHash := crypto.Keccak256(message)

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		data      []byte
		expectErr bool
	}{
		{"Valid signing", account.AccountId, messageHash, false},
		{"Non-existent account", "non_existent_account_id", messageHash, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sig := newPbTimedSignature(t, privateKey)
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
				assert.NotEmpty(t, resp.Data)

				// Recover the public key from the account
				accountResp, err := s.GetAccount(context.Background(), &pb.AccountIdRequest{AccountId: tc.accountId})
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

				// Verify the signature
				signature := resp.Data[:64]
				recoveryID := resp.Data[64]
				messageHash := tc.data

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
