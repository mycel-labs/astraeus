package e2e_test

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/assert"

	"github.com/mycel-labs/transferable-account/src/go/framework"
	"github.com/mycel-labs/transferable-account/src/go/server"
	"github.com/mycel-labs/transferable-account/testutil"
)

var (
	fr              *framework.Framework
	taStoreContract *framework.Contract
)

func TestMain(m *testing.M) {
	// Setup
	t := &testing.T{}
	setup(t)

	// Run tests
	code := m.Run()

	// Exit with the test result code
	os.Exit(code)
}

func startSUAVEServer() error {
	cmd := exec.Command("make", "devnet-up")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Dir = "../../"

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start SUAVE server: %w", err)
	}
	log.Println("SUAVE server started, waiting for it to be ready...")
	time.Sleep(5 * time.Second)

	return nil
}

func startAstraeusServer() {
	log.Println("Starting Astraeus server...")

	// Create a WaitGroup to manage server lifecycle
	var wg sync.WaitGroup
	wg.Add(1)

	// Start the Astraeus server in a separate goroutine
	go server.StartServer(&wg)

	// Wait for a short time to allow the server to start
	time.Sleep(5 * time.Second)
	log.Println("Astraeus server is up and running.")
}

func setup(t *testing.T) {
	// Start SUAVE server
	if err := startSUAVEServer(); err != nil {
		t.Fatalf("Failed to start SUAVE server: %v", err)
	}
	// Deploy contract
	fr = framework.New()
	taStoreContract = fr.Suave.DeployContract(testutil.TAStoreContractPath)
	contractAddress := taStoreContract.Contract.Address().String()
	err := os.Setenv("TA_STORE_CONTRACT_ADDRESS", contractAddress)
	if err != nil {
		fmt.Println("Error setting environment variable:", err)
	}

	// Generate private key
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}
	err = os.Setenv("PRIVATE_KEY", privKey.X.String())
	if err != nil {
		fmt.Println("Error setting environment variable:", err)
	}

	startAstraeusServer()
}

func TestCreateAccountE2E(t *testing.T) {
	// Setup
	privKey, err := crypto.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	testCases := []struct {
		name        string
		validFor    int64
		expectValid bool
	}{
		{
			name:        "Valid signature",
			validFor:    time.Now().Unix() + 86400, // 1 day later
			expectValid: true,
		},
		{
			name:        "Expired signature",
			validFor:    time.Now().Unix() - 86400, // 1 day ago
			expectValid: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup
			messageHash, signature, err := testutil.GenerateTimedSignature(tc.validFor, privKey)
			if err != nil {
				t.Fatalf("Failed to generate timed signature: %v", err)
			}

			timedSignature := testutil.TimedSignature{
				ValidFor:    uint64(tc.validFor),
				MessageHash: messageHash,
				Signature:   signature,
				Signer:      crypto.PubkeyToAddress(privKey.PublicKey),
			}

			response := testutil.CreateAccount(timedSignature)
			valid := response.StatusCode == 200

			assert.Equal(t, tc.expectValid, valid)
		})
	}

}
