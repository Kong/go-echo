package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"

	uuid "github.com/google/uuid"
)

func main() {

	// ENV
	tcpPort := os.Getenv("TCP_PORT")
	if tcpPort == "" {
		tcpPort = "1025"
	}

	nodeName := os.Getenv("NODE_NAME")
	podName := os.Getenv("POD_NAME")
	podNamespace := os.Getenv("POD_NAMESPACE")
	podIP := os.Getenv("POD_IP")
	serviceAccountName := os.Getenv("SERVICE_ACCOUNT")

	tlsPort := os.Getenv("TLS_PORT")
	tlsCACertFile := os.Getenv("TLS_CA_CERT_FILE")
	tlsCertFile := os.Getenv("TLS_CERT_FILE")
	tlsKeyFile := os.Getenv("TLS_KEY_FILE")

	message := ""

	if nodeName != "" {
		message = message + fmt.Sprintf("Welcome, you are connected to node %s.\n", nodeName)
	}

	if podName != "" {
		message = message + fmt.Sprintf("Running on Pod %s.\n", podName)
	}

	if podNamespace != "" {
		message = message + fmt.Sprintf("In namespace %s.\n", podNamespace)
	}

	if podIP != "" {
		message = message + fmt.Sprintf("With IP address %s.\n", podIP)
	}

	if serviceAccountName != "" {
		message = message + fmt.Sprintf("Service %s.\n", serviceAccountName)
	}

	if tlsPort != "" && tlsCertFile != "" && tlsKeyFile != "" {

		roots := x509.NewCertPool()
		if tlsCACertFile != "" {
			caCertPEM, err := os.ReadFile(tlsCACertFile)
			if err != nil {
				log.Panicf("failed to load CA, err %v", err)
			}
			roots.AppendCertsFromPEM(caCertPEM)
		}

		cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
		if err != nil {
			log.Panicf("failed to load cert, err %v", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      roots,
		}
		tlsListener, err := tls.Listen("tcp", ":"+tlsPort, tlsConfig)
		if err != nil {
			log.Panicf("failed to listen on TLS port %s: %v", tlsPort, err)
		}

		log.Printf("listen TLS on port %s", tlsPort)
		go func() {
			for {
				conn, err := tlsListener.Accept()
				if err != nil {
					log.Panicln("tls accept fail", err)
				}

				tlsMsg := message + "Through TLS connection.\n"
				go handleTCPRequest(conn, tlsMsg)
			}
		}()
	}

	l, err := net.Listen("tcp", ":"+tcpPort)
	if err != nil {
		log.Panicln(err)
	}

	log.Println("Listening on TCP port", tcpPort)
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Panicln(err)
		}

		go handleTCPRequest(conn, message)
	}
}

func handleTCPRequest(conn net.Conn, message string) {
	callUuidV4, _ := uuid.NewUUID()
	clientId := callUuidV4.String()

	log.Println(clientId + " - TCP connection open.")
	defer conn.Close()
	defer log.Println(clientId + " - TCP connection closed.")

	conn.Write([]byte(message))

	for {
		buf := make([]byte, 1024)
		size, err := conn.Read(buf)
		if err != nil {
			return
		}
		data := buf[:size]

		log.Println(clientId+" - Received Raw Data:", data)
		log.Printf(clientId+" - Received Data (converted to string): %s", data)
		conn.Write(data)
	}
}
