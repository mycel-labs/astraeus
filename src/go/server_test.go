package main

import (
	"context"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"

	framework "github.com/mycel-labs/transferable-account/framework"
	pb "github.com/mycel-labs/transferable-account/pb"
)

var (
	fr              *framework.Framework
	taStoreContract *framework.Contract
	accountId       string
)

const fundedAddress = "0xBE69d72ca5f88aCba033a063dF5DBe43a4148De0"

// TestMain is used for test setup and teardown
func TestMain(m *testing.M) {
	// Setup
	t := &testing.T{}
	setup(t)

	// Run tests
	code := m.Run()

	// Teardown
	teardown()

	// Exit with the test result code
	os.Exit(code)
}

func setup(t *testing.T) {
	fr = framework.New()

	// Deploy contract
	taStoreContract = fr.Suave.DeployContract(taStoreContractPath)
	os.Setenv("TA_STORE_CONTRACT_ADDRESS", taStoreContract.Contract.Address().Hex())

	// Initialize test data
	sig := &TimedSignature{}
	receipt := taStoreContract.SendConfidentialRequest("createAccount", []interface{}{sig}, nil)
	ev, err := taStoreContract.Abi.Events["AccountCreated"].ParseLog(receipt.Logs[0])
	if err != nil {
		t.Fatalf("failed to parse log: %v", err)
	}
	accountId = ev["accountId"].(string)
	t.Logf("accountId: %s", accountId)
}

func teardown() {
	// Perform any cleanup tasks
}

func TestCreateAccount(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}

	// Execute
	req := &pb.CreateAccountRequest{}
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

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		expectErr bool
	}{
		{"Valid account", accountId, false},
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
	sig := &TimedSignature{
		Signer: common.HexToAddress(fundedAddress),
	}
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

	newOwner := "0x1234567890123456789012345678901234567890"

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		to        string
		expectErr bool
	}{
		{"Valid transfer", accountId, newOwner, false},
		{"Non-existent account", "non_existent_account_id", newOwner, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.TransferAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof: &pb.TimedSignature{
						Signer: fundedAddress,
					},
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

	// Create a new account for deletion
	createReq := &pb.CreateAccountRequest{}
	createResp, err := s.CreateAccount(context.Background(), createReq)
	assert.NoError(t, err, "CreateAccount call should not return an error")
	newAccountId := string(createResp.Data)

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		expectErr bool
	}{
		{"Valid deletion", newAccountId, false},
		{"Non-existent account", "non_existent_account_id", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.DeleteAccountRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof: &pb.TimedSignature{
						Signer: fundedAddress,
					},
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

func TestApproveAddress(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}

	// Create a new account for approval
	createReq := &pb.CreateAccountRequest{}
	createResp, err := s.CreateAccount(context.Background(), createReq)
	assert.NoError(t, err, "CreateAccount call should not return an error")
	newAccountId := string(createResp.Data)

	newApprovedAddress := "0x1234567890123456789012345678901234567890"

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		address   string
		expectErr bool
	}{
		{"Valid approval", newAccountId, newApprovedAddress, false},
		{"Non-existent account", "non_existent_account_id", newApprovedAddress, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.ApproveAddressRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof: &pb.TimedSignature{
						Signer: fundedAddress,
					},
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

	// Create a new account for approval and revocation
	createReq := &pb.CreateAccountRequest{}
	createResp, err := s.CreateAccount(context.Background(), createReq)
	assert.NoError(t, err, "CreateAccount call should not return an error")
	newAccountId := string(createResp.Data)

	addressToApprove := "0x1234567890123456789012345678901234567890"

	// Approve the address first
	approveReq := &pb.ApproveAddressRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: newAccountId,
			Proof: &pb.TimedSignature{
				Signer: fundedAddress,
			},
		},
		Address: addressToApprove,
	}
	_, err = s.ApproveAddress(context.Background(), approveReq)
	assert.NoError(t, err, "ApproveAddress call should not return an error")

	// Test cases
	testCases := []struct {
		name      string
		accountId string
		address   string
		expectErr bool
	}{
		{"Valid revocation", newAccountId, addressToApprove, false},
		{"Non-existent account", "non_existent_account_id", addressToApprove, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Execute
			req := &pb.RevokeApprovalRequest{
				Base: &pb.AccountOperationRequest{
					AccountId: tc.accountId,
					Proof: &pb.TimedSignature{
						Signer: fundedAddress,
					},
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
