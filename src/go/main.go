package main

import (
	"sync"

	"github.com/mycel-labs/transferable-account/src/go/server"
)

func main() {
	var wg sync.WaitGroup
	wg.Add(1)

	go server.StartServer(&wg)

	wg.Wait()
}
