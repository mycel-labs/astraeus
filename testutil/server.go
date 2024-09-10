package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	pb "github.com/mycel-labs/transferable-account/src/go/pb/api/v1"
	"github.com/mycel-labs/transferable-account/src/go/server"
)

func StartAstraeusServer() {
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

func SendRequest(url string, data map[string]interface{}) *http.Response {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Fatal("Failed to marshal JSON:", err)
	}

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Fatal("Failed to send request:", err)
	}
	defer resp.Body.Close()

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response:", err)
	}

	return resp
}

func CreateAccount(timedSignature *pb.TimedSignature) *http.Response {
	url := fmt.Sprintf("%s/v1/accounts", HostURL)
	data := map[string]interface{}{
		"proof": map[string]interface{}{
			"validFor":    timedSignature.ValidFor,
			"messageHash": timedSignature.MessageHash,// Convert to hex string
			"signature":   timedSignature.Signature,   // Convert to hex string
			"signer":      timedSignature.Signer,
		},
	}
	return SendRequest(url, data)
}
