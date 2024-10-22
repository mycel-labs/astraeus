#!/bin/bash

abigen --abi=out/TransferableAccountStore.sol/TransferableAccountStore.abi.json \
	--bin=out/TransferableAccountStore.sol/TransferableAccountStore.bin \
	--pkg=transferableaccountstore \
	--out=src/go/contract/transferable_account_store.go
