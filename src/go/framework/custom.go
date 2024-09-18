package framework

import (
	"log"

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

// WithCustomConfig sets custom configuration for the framework.
func WithCustomConfig(privateKey string, rpcUrl string) ConfigOption {
	if privateKey == "" && rpcUrl == "" {
		log.Fatal("PRIVATE_KEY or RPC_URL must be set")
	} else {
		if privateKey == "" {
			log.Println("PRIVATE_KEY is not set, using default funded account in devnet")
			// This account is funded in your local SUAVE devnet
			// address: 0xBE69d72ca5f88aCba033a063dF5DBe43a4148De0
			privateKey = "91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12"
		} else if rpcUrl == "" {
			log.Println("RPC_URL is not set, using default: http://localhost:8545")
			rpcUrl = "http://localhost:8545"
		}
	}
	log.Printf("Using PRIVATE_KEY: %s", privateKey)
	log.Printf("Using RPC_URL: %s", rpcUrl)
	fundedAccount := NewPrivKeyFromHex(privateKey)
	return func(c *Config) {
		c.FundedAccount = fundedAccount
		c.KettleRPC = rpcUrl
	}
}

// WithCustomConfigL1 sets custom configuration for the framework with L1 support.
func WithCustomConfigL1(privateKey string, rpcUrl string, l1PrivateKey string, l1RpcUrl string) ConfigOption {
	if privateKey == "" && rpcUrl == "" {
		log.Fatal("PRIVATE_KEY or RPC_URL must be set")
	} else {
		if privateKey == "" {
			log.Println("PRIVATE_KEY is not set, using default funded account in devnet")
			// This account is funded in your local SUAVE devnet
			// address: 0xBE69d72ca5f88aCba033a063dF5DBe43a4148De0
			privateKey = "91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12"
		} else if rpcUrl == "" {
			log.Println("RPC_URL is not set, using default: http://localhost:8545")
			rpcUrl = "http://localhost:8545"
		}
	}
	if l1PrivateKey == "" && l1RpcUrl == "" {
		log.Fatal("L1_PRIVATE_KEY or L1_RPC_URL must be set")
	} else {
		if l1PrivateKey == "" {
			log.Fatal("L1_PRIVATE_KEY must be set")
		} else if l1RpcUrl == "" {
			log.Println("L1_RPC_URL is not set, using default: http://localhost:8546")
			rpcUrl = "http://localhost:8545"
		}
	}

	fundedAccount := NewPrivKeyFromHex(privateKey)
	l1FundedAccount := NewPrivKeyFromHex(l1PrivateKey)

	return func(c *Config) {
		c.FundedAccount = fundedAccount
		c.KettleRPC = rpcUrl
		c.FundedAccountL1 = l1FundedAccount
		c.L1RPC = l1RpcUrl
		c.L1Enabled = true
	}
}
