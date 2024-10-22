package testutil

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	ct "github.com/mycel-labs/astraeus/src/go/contract"
	"github.com/mycel-labs/astraeus/src/go/framework"
	pb "github.com/mycel-labs/astraeus/src/go/pb/api/v1"
	impl "github.com/mycel-labs/astraeus/src/go/server"
)

func NewAccount(taStoreContract *framework.Contract, privateKey *ecdsa.PrivateKey) (*pb.Account, error) {
	targetFunctionHash := common.HexToHash(impl.CREATE_ACCOUNT_FUNCTION_HASH)
	validFor := uint64(time.Now().AddDate(1, 0, 0).Unix())
	sig, err := NewTimedSignature(taStoreContract, privateKey, validFor, targetFunctionHash)
	if err != nil {
		return nil, fmt.Errorf("failed to create timed signature: %v", err)
	}
	receipt := taStoreContract.SendConfidentialRequest("createAccount", []interface{}{sig}, nil)
	ev, err := taStoreContract.Abi.Events["AccountCreated"].ParseLog(receipt.Logs[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse log: %v", err)
	}
	accountId := ev["accountId"].(string)

	return &pb.Account{
		AccountId: accountId,
		Owner:     crypto.PubkeyToAddress(privateKey.PublicKey).Hex(),
	}, nil
}

func NewPbTimedSignature(taStoreContract *framework.Contract, privateKey *ecdsa.PrivateKey, validFor uint64, targetFunctionHash [32]byte) (*pb.TimedSignature, error) {
	sig, err := newTimedSignature(taStoreContract, privateKey, validFor, targetFunctionHash)
	if err != nil {
		return nil, err
	}
	return &pb.TimedSignature{
		ValidFor:           validFor,
		MessageHash:        hex.EncodeToString(sig.MessageHash[:]),
		Signature:          hex.EncodeToString(sig.Signature),
		Signer:             sig.Signer.Hex(),
		Nonce:              sig.Nonce,
		TargetFunctionHash: hex.EncodeToString(sig.TargetFunctionHash[:]),
	}, nil
}

func NewTimedSignature(taStoreContract *framework.Contract, privateKey *ecdsa.PrivateKey, validFor uint64, targetFunctionHash [32]byte) (*ct.SignatureVerifierTimedSignature, error) {
	return newTimedSignature(taStoreContract, privateKey, validFor, targetFunctionHash)
}

func newTimedSignature(taStoreContract *framework.Contract, privateKey *ecdsa.PrivateKey, validFor uint64, targetFunctionHash [32]byte) (*ct.SignatureVerifierTimedSignature, error) {
	nonce, err := getNonce(taStoreContract, crypto.PubkeyToAddress(privateKey.PublicKey))
	if err != nil {
		return nil, err
	}
	messageHash, signature, err := generateTimedSignature(int64(validFor), privateKey, nonce, targetFunctionHash)
	if err != nil {
		return nil, fmt.Errorf("failed to generate timed signature: %v", err)
	}
	return &ct.SignatureVerifierTimedSignature{
		ValidFor:           validFor,
		MessageHash:        messageHash,
		Signature:          signature,
		Signer:             crypto.PubkeyToAddress(privateKey.PublicKey),
		Nonce:              nonce,
		TargetFunctionHash: targetFunctionHash,
	}, nil
}

func getNonce(taStoreContract *framework.Contract, address common.Address) (uint64, error) {
	result := taStoreContract.Call("getNonce", []interface{}{address})
	if len(result) == 0 || result[0] == nil {
		return 0, fmt.Errorf("empty result")
	}
	nonce, ok := result[0].(uint64)
	if !ok {
		return 0, fmt.Errorf("nonce data type is unexpected")
	}
	return nonce, nil
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
