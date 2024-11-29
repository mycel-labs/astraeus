## How to test on Local Environment

### Start the local chain

```jsx
make devnet-up  
```

### Build

```jsx
make build
```

### Set the necessary configurations in .env

```jsx
#Local Testnet
PRIVATE_KEY=91ab9a7e53c220e6210460b65a7a3bb2ca181412a8a7b43ff336b3df1737ce12
TA_STORE_CONTRACT_ADDRESS=0xd594760B2A36467ec7F0267382564772D7b0b73c
RPC_URL=http://localhost:8545
```

### Execute test

```jsx
make test-go
```

```jsx
make test-solidity
```