package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/logging"
	"github.com/quic-go/quic-go/qlog"
	logPkg "log"
	"math/big"
	"net"
	"os"
	"time"
)

var log = logPkg.New(os.Stdout, "[server]: ", logPkg.LstdFlags)

func Run(port int) {

	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: port})
	if err != nil {
		log.Fatal("failed to listen on udp")
	}

	// use a sha-256 hash of key as sha-256 is the required 32 bytes long
	statelessResetKey := quic.StatelessResetKey(sha256.Sum256([]byte("a314kjdsaf903245jlsfhww")))

	tr := quic.Transport{
		Conn:              udpConn,
		StatelessResetKey: &statelessResetKey,
	}

	config := &quic.Config{
		MaxIncomingStreams: 10,
		KeepAlivePeriod:    2 * time.Second,
		MaxIdleTimeout:     10 * time.Second,
		Allow0RTT:          true,
		Tracer: func(ctx context.Context, p logging.Perspective, connID quic.ConnectionID) *logging.ConnectionTracer {
			role := "server"
			if p == logging.PerspectiveClient {
				role = "client"
			}
			filename := fmt.Sprintf("./log/log_%x_%s.qlog", connID, role)
			f, err := os.Create(filename)
			if err != nil {
				log.Println("failed to create file for qlog: ", err)
				return nil
			}
			return qlog.NewConnectionTracer(f, p, connID)
		},
	}

	listener, err := tr.Listen(generateTLSConfig(), config)
	if err != nil {
		log.Fatal("failed to start quic listener: ", err)
	}

	log.Printf("listening on %d", port)

	conn, err := listener.Accept(context.Background())
	if err != nil {
		log.Println("failed to get conn from quic listener: ", err)
		return
	}

	acceptDataStreams(conn)

	log.Println("Exiting")
}

// Accept client streams. Read from stream then close the stream before client is finished sending.
func acceptDataStreams(conn quic.Connection) {
	for {
		s, err := conn.AcceptStream(context.Background())
		if err != nil {
			log.Println("failed to accept stream: ", err)
			return
		}

		log.Println("accepted data stream")

		go readFromDataStream(s)
	}
}

func readFromDataStream(s quic.Stream) {
	defer func() {
		err := s.Close()
		if err != nil {
			log.Println("err closing stream: ", err)
		} else {
			log.Println("stream closed")
		}
	}()

	var buf = make([]byte, 32*1024)

	var bytesRead int

	for {
		n, err := s.Read(buf)
		if n > 0 {
			log.Printf("read %d bytes from data stream", n)
		}
		if err != nil {
			log.Println("failed to read from stream: ", err)
			return
		}

		bytesRead += n

		// close the stream while client is still sending
		if bytesRead > 64*1024 {
			log.Println("closed data stream before receiving all data")
			return
		}
	}
}

// GenerateTLSConfig Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"z"},
	}
}
