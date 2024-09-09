package framework

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/suave/sdk"
)

/*
** BindToExistingContract creates a Contract struct for an already deployed contract
** @param address: the address of the contract
** @param path: the path to the contract artifact
** @return: a Contract struct
** @error: an error if the contract is not foun
 */
func (c *Chain) BindToExistingContract(address common.Address, path string) (*Contract, error) {
	artifact, err := ReadArtifact(path)
	if err != nil {
		panic(err)
	}

	sdkContract := sdk.GetContract(address, artifact.Abi, c.clt)

	return &Contract{
		Contract:   sdkContract,
		clt:        c.clt,
		kettleAddr: c.kettleAddr,
		addr:       address,
		Abi:        artifact.Abi,
	}, nil
}
