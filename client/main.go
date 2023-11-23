package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	"io"
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
		log.Println(fmt.Errorf("failed to dial server: %w", err))
		//continue
		return
	}

	// accept hello streams
	go acceptHelloStreams(conn)

	sendData(conn)

	//err = conn.CloseWithError(0, "going away")
	//if err != nil {
	//	log.Println(fmt.Errorf("err closing conn: %w", err))
	//}
	//log.Println("client closed conn")
}

func sendData(conn quic.Connection) {
	for {
		time.Sleep(3 * time.Second)
		stream, err := conn.OpenStream()
		if err != nil {
			log.Println(fmt.Errorf("failed to open stream: %w", err))
			//continue
			return
		}

		log.Println("opened data stream")
		buf := make([]byte, 32*1024)

		for i := 0; i < 500; i++ {
			time.Sleep(5 * time.Millisecond)

			stream.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			_, err := stream.Write(buf)
			if err != nil {
				log.Println(fmt.Errorf("err writing to test stream: %w", err))
				break
			}

		}

		err = stream.Close()
		if err != nil {
			log.Println(fmt.Errorf("err closing stream: %w", err))
		}

		log.Println("closed stream")
	}
}

func acceptHelloStreams(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Println(fmt.Errorf("failed to accept stream: %w", err))
			return
		}

		go readHelloStream(stream)
	}
}

func readHelloStream(s quic.Stream) {
	var buf = make([]byte, 32*1024)

	for {
		n, err := s.Read(buf)
		if n > 0 {
			log.Printf("read from hello stream: %s\n", string(buf[:n]))
		}
		if err != nil {

			if !errors.Is(err, io.EOF) {
				log.Println(fmt.Errorf("err reading from stream: %w n: %d", err, n))
			}

			s.Close()
			return
		}
	}
}
