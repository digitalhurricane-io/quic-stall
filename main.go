package main

import (
	"fmt"
	"github.com/digitalhurricane-io/slow-quic-speed-repro/client"
	"github.com/digitalhurricane-io/slow-quic-speed-repro/server"
	"time"
)

func main() {
	const port = 7000
	go server.Run(port)
	time.Sleep(2 * time.Second)
	client.Start(fmt.Sprintf("127.0.0.1:%d", port))
}
