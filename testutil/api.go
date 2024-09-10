package testutil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

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

func CreateAccount(timedSignature TimedSignature) *http.Response {
	url := fmt.Sprintf("%s/v1/accounts", HostURL)
	data := map[string]interface{}{
		"proof": map[string]interface{}{
			"validFor":    timedSignature.ValidFor,
			"messageHash": fmt.Sprintf("%x", timedSignature.MessageHash), // Convert to hex string
			"signature":   fmt.Sprintf("%x", timedSignature.Signature),   // Convert to hex string
			"signer":      timedSignature.Signer.Hex(),
		},
	}
	return SendRequest(url, data)
}
