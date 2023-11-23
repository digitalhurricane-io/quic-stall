package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	logPkg "log"
	"os"
	"time"
)

var log = logPkg.New(os.Stdout, "[client]: ", logPkg.LstdFlags)

func Start(addr string) {

	config := &quic.Config{
		KeepAlivePeriod: 2 * time.Second,
		MaxIdleTimeout:  10 * time.Second,
		Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			role := "server"
			if p == logging.PerspectiveClient {
				role = "client"
			}
			filename := fmt.Sprintf("./log/log_%x_%s.qlog", connID, role)
			f, err := os.Create(filename)
			if err != nil {
				log.Println(fmt.Errorf("failed to create file for qlog: %w", err))
				return nil
			}
			return qlog.NewConnectionTracer(f, p, connID)
		},
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"z"}, // must match server
	}

	log.Println("connecting to server")

	conn, err := quic.DialAddr(context.Background(), addr, tlsConfig, config)
	if err != nil {
		log.Println("failed to dial server: ", err)
		return
	}

	openStreamsAndSendData(conn)

	log.Println("exiting")
}

func openStreamsAndSendData(conn quic.Connection) {
	for {
		time.Sleep(3 * time.Second)

		stream, err := conn.OpenStream()
		if err != nil {
			log.Println("failed to open stream: ", err)
			return
		}

		log.Println("opened data stream")

		sendData(stream)
	}
}

func sendData(stream quic.Stream) {
	defer func() {
		err := stream.Close()
		if err != nil {
			log.Println("err closing stream: ", err)
		} else {
			log.Println("stream closed")
		}
	}()

	buf := make([]byte, 32*1024)

	for i := 0; i < 500; i++ {
		time.Sleep(5 * time.Millisecond)

		err := stream.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err != nil {
			log.Println("failed to set deadline: ", err)
			return
		}

		_, err = stream.Write(buf)
		if err != nil {
			log.Println("err writing to stream: ", err)
			return
		}
	}

	log.Println("finished sending data")
}
