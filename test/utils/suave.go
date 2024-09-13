package testutil

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

func StartSUAVEServer() error {
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
