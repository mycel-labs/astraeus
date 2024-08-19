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
	taStoreContract *framework.Contract
)

// TestMain is used for test setup and teardown
func TestMain(m *testing.M) {
	// Setup
	setup()

	// Run tests
	code := m.Run()

	// Teardown
	teardown()

	// Exit with the test result code
	os.Exit(code)
}

func setup() {
	// Deploy contract or perform other setup tasks
	// For example:
	// deployContract()
	// initializeTestData()
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
	testAccountID := "test_account_id"
	expectedAccount := &pb.Account{
		// Fill with expected account data
	}

	// Execute
	req := &pb.AccountIdRequest{AccountId: testAccountID}
	resp, err := s.GetAccount(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, expectedAccount, resp.Account)
}

// TODO: Add more test cases for other methods

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
	assert.Contains(t, err.Error(), "account data type is unexpected")
}
