package testutil

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
)

func CreateAccountHelper(t *testing.T, privKey *ecdsa.PrivateKey) string {
	createSig, err := GenerateTimedSignature(time.Now().Unix()+86400, privKey)
	if err != nil {
		t.Fatalf("Failed to generate timed signature: %v", err)
	}
	createAccountRequest := &pb.CreateAccountRequest{
		Proof: createSig,
	}
	createAccountResponse, resp, err := CreateAccount(createAccountRequest)
	if err != nil {
		t.Fatalf("Failed to create account: %v", err)
	}
	assert.Equal(t, 200, resp.StatusCode)
	return createAccountResponse.AccountId
}

// Helper function to approve an address
func ApproveAddressHelper(t *testing.T, accountId string, ownerPrivKey *ecdsa.PrivateKey, addressToApprove string) {
	approveSig, err := GenerateTimedSignature(time.Now().Unix()+86400, ownerPrivKey)
	if err != nil {
		t.Fatalf("Failed to generate timed signature: %v", err)
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
}

// Helper function to unlock an account
func UnlockAccountHelper(t *testing.T, accountId string, ownerPrivKey *ecdsa.PrivateKey) {
	unlockSig, err := GenerateTimedSignature(time.Now().Unix()+86400, ownerPrivKey)
	if err != nil {
		t.Fatalf("Failed to generate timed signature: %v", err)
	}
	unlockAccountRequest := &pb.UnlockAccountRequest{
		Base: &pb.AccountOperationRequest{
			AccountId: accountId,
			Proof:     unlockSig,
		},
	}
	_, resp, err := UnlockAccount(unlockAccountRequest)
	assert.NoError(t, err, "Failed to unlock account")
	assert.Equal(t, 200, resp.StatusCode)
}
