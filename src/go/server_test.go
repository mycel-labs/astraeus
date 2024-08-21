package main

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	framework "github.com/mycel-labs/transferable-account/framework"
	pb "github.com/mycel-labs/transferable-account/pb"
)

var (
	fr              *framework.Framework
	taStoreContract *framework.Contract
	accountId       string
)

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
