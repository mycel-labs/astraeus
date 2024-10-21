package testutil

import (
	"crypto/ecdsa"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"

	"github.com/mycel-labs/astraeus/src/go/framework"
	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
	impl "github.com/mycel-labs/astraeus/src/go/server"
)

func CreateAccountHelper(t *testing.T, taStoreContract *framework.Contract, privKey *ecdsa.PrivateKey) string {
	signTestUtil := &SignTestUtil{
		T:               t,
		TaStoreContract: taStoreContract,
	}
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	createSig := signTestUtil.NewPbTimedSignature(privKey, validFor, common.HexToHash(impl.CREATE_ACCOUNT_FUNCTION_HASH))
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
func ApproveAddressHelper(t *testing.T, taStoreContract *framework.Contract, accountId string, ownerPrivKey *ecdsa.PrivateKey, addressToApprove string) {
	signTestUtil := &SignTestUtil{
		T:               t,
		TaStoreContract: taStoreContract,
	}
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	approveSig := signTestUtil.NewPbTimedSignature(ownerPrivKey, validFor, common.HexToHash(impl.APPROVE_ADDRESS_FUNCTION_HASH))
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
func UnlockAccountHelper(t *testing.T, taStoreContract *framework.Contract, accountId string, ownerPrivKey *ecdsa.PrivateKey) {
	signTestUtil := &SignTestUtil{
		T:               t,
		TaStoreContract: taStoreContract,
	}
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	unlockSig := signTestUtil.NewPbTimedSignature(ownerPrivKey, validFor, common.HexToHash(impl.UNLOCK_ACCOUNT_FUNCTION_HASH))
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
