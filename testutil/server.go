package testutil

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

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

func PostServer(url string, request proto.Message, response proto.Message) (*http.Response, error) {
	// Marshal the Protobuf request to JSON
	jsonData, err := protojson.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	// Send the HTTP POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, fmt.Errorf("failed to read response body: %w", err)
	}

	// Unmarshal the response into the Protobuf response message
	err = protojson.Unmarshal(body, response)
	if err != nil {
		return resp, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	// Return status code and no error
	return resp, nil
}

func GetServer(url string, responseMessage proto.Message) *http.Response {
	// Send the GET request to the specified URL
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("Failed to send GET request:", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Failed to read response body:", err)
	}

	// Unmarshal the JSON response into the provided Protobuf message
	err = protojson.Unmarshal(body, responseMessage)
	if err != nil {
		log.Fatal("Failed to unmarshal JSON to Protobuf:", err)
	}

	return resp
}

func CreateAccount(createAccountRequest *pb.CreateAccountRequest) (*pb.CreateAccountResponse, *http.Response, error) {
	url := fmt.Sprintf("%s/v1/accounts", HostURL)

	// Create the Protobuf response message
	createAccountResponse := &pb.CreateAccountResponse{}

	resp, err := PostServer(url, createAccountRequest, createAccountResponse)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to process CreateAccount request: %w", err)
	}

	return createAccountResponse, resp, nil
}

func TransferAccount(transferAccountRequest *pb.TransferAccountRequest) (*pb.TransferAccountResponse, *http.Response, error) {
	url := fmt.Sprintf("%s/v1/accounts/%s/transfer", HostURL, transferAccountRequest.Base.AccountId)

	// Create the Protobuf response message
	transferAccountResponse := &pb.TransferAccountResponse{}

	// Use the generalized function to send the request and receive the response
	resp, err := PostServer(url, transferAccountRequest, transferAccountResponse)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to process TransferAccount request: %w", err)
	}

	return transferAccountResponse, resp, nil
}

func DeleteAccount(deleteAccountRequest *pb.DeleteAccountRequest) (*pb.DeleteAccountResponse, *http.Response, error) {
	url := fmt.Sprintf("%s/v1/accounts/%s", HostURL, deleteAccountRequest.Base.AccountId)

	// Create the Protobuf response message
	deleteAccountResponse := &pb.DeleteAccountResponse{}

	// Use the generalized function to send the request and receive the response
	resp, err := PostServer(url, deleteAccountRequest, deleteAccountResponse)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to process DeleteAccount request: %w", err)
	}

	return deleteAccountResponse, resp, nil
}


func UnlockAccount(unlockAccountRequest *pb.UnlockAccountRequest) (*pb.UnlockAccountResponse, *http.Response, error) {
	url := fmt.Sprintf("%s/v1/accounts/%s/unlock", HostURL, unlockAccountRequest.Base.AccountId)

	// Create the Protobuf response message
	unlockAccountResponse := &pb.UnlockAccountResponse{}

	// Use the generalized function to send the request and receive the response
	resp, err := PostServer(url, unlockAccountRequest, unlockAccountResponse)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to process UnlockAccount request: %w", err)
	}

	return unlockAccountResponse, resp, nil
}

func ApproveAddress(approveAddressRequest *pb.ApproveAddressRequest) (*pb.ApproveAddressResponse, *http.Response, error) {
	url := fmt.Sprintf("%s/v1/accounts/%s/approve", HostURL, approveAddressRequest.Base.AccountId)

	// Create the Protobuf response message
	approveAddressResponse := &pb.ApproveAddressResponse{}

	// Use the generalized function to send the request and receive the response
	resp, err := PostServer(url, approveAddressRequest, approveAddressResponse)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to process ApproveAddress request: %w", err)
	}

	return approveAddressResponse, resp, nil
}

func RevokeApproval(revokeApprovalRequest *pb.RevokeApprovalRequest) (*pb.RevokeApprovalResponse, *http.Response, error) {
	url := fmt.Sprintf("%s/v1/accounts/%s/revoke", HostURL, revokeApprovalRequest.Base.AccountId)

	// Create the Protobuf response message
	revokeApprovalResponse := &pb.RevokeApprovalResponse{}

	// Use the generalized function to send the request and receive the response
	resp, err := PostServer(url, revokeApprovalRequest, revokeApprovalResponse)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to process RevokeApproval request: %w", err)
	}

	return revokeApprovalResponse, resp, nil
}

func Sign(signRequest *pb.SignRequest) (*pb.SignResponse, *http.Response, error) {
	url := fmt.Sprintf("%s/v1/accounts/%s/sign", HostURL, signRequest.Base.AccountId)

	// Create the Protobuf response message
	signResponse := &pb.SignResponse{}

	// Use the generalized function to send the request and receive the response
	resp, err := PostServer(url, signRequest, signResponse)
	if err != nil {
		return nil, resp, fmt.Errorf("failed to process Sign request: %w", err)
	}

	return signResponse, resp, nil
}
// func GetAccount(getAccountRequest *pb.GetAccountRequest) *http.Response {
// url := fmt.Sprintf("%s/v1/accounts/%s", HostURL, getAccountRequest.AccountId)
// }
//
// func IsApproved(isApprovedRequest *pb.IsApprovedRequest) *http.Response {
// url := fmt.Sprintf("%s/v1/accounts/%s/approved/%s", HostURL, isApprovedRequest.AccountId, isApprovedRequest.Address)
// }
//
// func IsOwner(isOwnerRequest *pb.IsOwnerRequest) *http.Response {
// url := fmt.Sprintf("%s/v1/accounts/%s/owner/%s", HostURL, isOwnerRequest.AccountId, isOwnerRequest.Address)
// }
//
// func IsAccountLocked(isAccountLockedRequest *pb.IsAccountLockedRequest) *http.Response {
// url := fmt.Sprintf("%s/v1/accounts/%s/locked", HostURL, isAccountLockedRequest.AccountId)
// }
