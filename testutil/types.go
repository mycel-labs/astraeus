package testutil

import (
	"github.com/ethereum/go-ethereum/common"
)

type TimedSignature struct {
	ValidFor    uint64
	MessageHash [32]byte
	Signature   []byte
	Signer      common.Address
}
