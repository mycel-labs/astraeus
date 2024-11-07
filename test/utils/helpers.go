package testutil

import (
	"crypto/ecdsa"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"

	"github.com/mycel-labs/astraeus/src/go/framework"
	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
	impl "github.com/mycel-labs/astraeus/src/go/server"
)

func CreateAccountHelper(t *testing.T, taStoreContract *framework.Contract, privKey *ecdsa.PrivateKey) (string, error) {
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	createSig, err := NewPbTimedSignature(taStoreContract, privKey, validFor, common.HexToHash(impl.CREATE_ACCOUNT_FUNCTION_HASH))
	if err != nil {
		return "", fmt.Errorf("failed to generate timed signature: %v", err)
	}
	createAccountRequest := &pb.CreateAccountRequest{
		Proof: createSig,
	}
	createAccountResponse, resp, err := CreateAccount(createAccountRequest)
	if err != nil {
		return "", fmt.Errorf("failed to create account: %w", err)
	}
	assert.Equal(t, 200, resp.StatusCode)
	return createAccountResponse.AccountId, nil
}

// Helper function to approve an address
func ApproveAddressHelper(t *testing.T, taStoreContract *framework.Contract, accountId string, ownerPrivKey *ecdsa.PrivateKey, addressToApprove string) error {
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	approveSig, err := NewPbTimedSignature(taStoreContract, ownerPrivKey, validFor, common.HexToHash(impl.APPROVE_ADDRESS_FUNCTION_HASH))
	if err != nil {
		return fmt.Errorf("failed to generate timed signature: %w", err)
	}
	approveAddressRequest := &pb.ApproveAddressRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: accountId,
			Proof:     approveSig,
		},
		Address: addressToApprove,
	}
	_, resp, err := ApproveAddress(approveAddressRequest)
	assert.NoError(t, err, "Failed to approve address")
	assert.Equal(t, 200, resp.StatusCode)
	if err != nil {
		return fmt.Errorf("failed to approve address: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// Helper function to unlock an account
func UnlockAccountHelper(t *testing.T, taStoreContract *framework.Contract, accountId string, ownerPrivKey *ecdsa.PrivateKey) error {
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	unlockSig, err := NewPbTimedSignature(taStoreContract, ownerPrivKey, validFor, common.HexToHash(impl.UNLOCK_ACCOUNT_FUNCTION_HASH))
	if err != nil {
		return fmt.Errorf("failed to generate timed signature: %w", err)
	}
	unlockAccountRequest := &pb.UnlockAccountRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: accountId,
			Proof:     unlockSig,
		},
	}
	_, resp, err := UnlockAccount(unlockAccountRequest)
	if err != nil {
		return fmt.Errorf("failed to unlock account: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	assert.NoError(t, err, "Failed to unlock account")
	assert.Equal(t, 200, resp.StatusCode)
	return nil
}
