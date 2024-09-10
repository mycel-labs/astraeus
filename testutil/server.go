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

func PostServer(url string, message proto.Message) *http.Response {
	jsonData, err := protojson.Marshal(message)
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

func CreateAccount(createAccountRequest *pb.CreateAccountRequest) *http.Response {
	url := fmt.Sprintf("%s/v1/accounts", HostURL)
	return PostServer(url, createAccountRequest)
}

func TransferAccount(transferAccountRequest *pb.TransferAccountRequest) *http.Response {
	url := fmt.Sprintf("%s/v1/accounts/%s/transfer", HostURL, transferAccountRequest.Base.AccountId)
	return PostServer(url, transferAccountRequest)
}

func DeleteAccount(deleteAccountRequest *pb.DeleteAccountRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s", HostURL, deleteAccountRequest.Base.AccountId)
  return PostServer(url, deleteAccountRequest)
}

func UnlockAccount(unlockAccountRequest *pb.UnlockAccountRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s/unlock", HostURL, unlockAccountRequest.Base.AccountId)
  return PostServer(url, unlockAccountRequest)
}

func ApproveAddress(approveAddressRequest *pb.ApproveAddressRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s/approve", HostURL, approveAddressRequest.Base.AccountId)
  return PostServer(url, approveAddressRequest)
}

func RevokeApproval(revokeApprovalRequest *pb.RevokeApprovalRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s/revoke", HostURL, revokeApprovalRequest.Base.AccountId)
  return PostServer(url, revokeApprovalRequest)
}

func Sign(SignRequest *pb.SignRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s/sign", HostURL, SignRequest.Base.AccountId)
  return PostServer(url, SignRequest)
}

func GetAccount(getAccountRequest *pb.GetAccountRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s", HostURL, getAccountRequest.AccountId)
  return GetServer(url, getAccountRequest)
}

func IsApproved(isApprovedRequest *pb.IsApprovedRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s/approved/%s", HostURL, isApprovedRequest.AccountId, isApprovedRequest.Address)
  return GetServer(url, isApprovedRequest)
}

func IsOwner(isOwnerRequest *pb.IsOwnerRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s/owner/%s", HostURL, isOwnerRequest.AccountId, isOwnerRequest.Address)
  return GetServer(url, isOwnerRequest)
}

func IsAccountLocked(isAccountLockedRequest *pb.IsAccountLockedRequest) *http.Response {
  url := fmt.Sprintf("%s/v1/accounts/%s/locked", HostURL, isAccountLockedRequest.AccountId)
  return GetServer(url, isAccountLockedRequest)
}
