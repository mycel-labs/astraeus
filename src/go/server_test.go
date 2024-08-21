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
	cfg             *framework.Config
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

func TestGetAccount(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}

	// Test case
	testAccountID := accountId

	// Execute
	req := &pb.AccountIdRequest{AccountId: testAccountID}
	resp, err := s.GetAccount(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
}

func TestGetAccountError(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}

	// Test case
	testAccountID := "non_existent_account_id"

	// Execute
	req := &pb.AccountIdRequest{AccountId: testAccountID}
	resp, err := s.GetAccount(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "account not found")
}

func TestIsApproved(t *testing.T) {
	// Test case
	testAccountID := accountId
	testAddress := common.HexToAddress("0x1234567890123456789012345678901234567890")

	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}
	s.taStoreContract.SendConfidentialRequest("approveAddress", []interface{}{&TimedSignature{}, testAccountID, testAddress}, nil)

	// Execute
	req := &pb.AccountIdToAddressRequest{
		AccountId: testAccountID,
		Address:   testAddress.String(),
	}
	resp, err := s.IsApproved(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.IsType(t, &pb.BoolResponse{}, resp)
	assert.True(t, resp.Result)
}

func TestIsApprovedError(t *testing.T) {
	// Setup
	s := &server{
		taStoreContract: taStoreContract,
	}

	// Test cases
	testCases := []struct {
		name      string
		accountID string
		address   string
	}{
		{"Not approved address", accountId, "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
		{"Non-existent account ID", "non_existent_account_id", "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
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
			assert.False(t, resp.Result, "Should not be approved")
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
