package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	uuid "github.com/google/uuid"
)

func main() {

	// ENV
	tcpPort := os.Getenv("TCP_PORT")
	if tcpPort == "" {
		tcpPort = "1025"
	}
	udpPort := os.Getenv("UDP_PORT")
	if udpPort == "" {
		udpPort = "1026"
	}
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "1027"
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
		message = message + fmt.Sprintf("Service account %s.\n", serviceAccountName)
	}

	// spawn a TLS server if TLS_PORT, TLS_CERT_FILE, TLS_KEY_FILE are set.
	// append CA cert from TLS_CA_CERT_FILE if set.
	if tlsPort != "" && tlsCertFile != "" && tlsKeyFile != "" {
		tlsListener, err := makeTLSListner(
			tlsPort, tlsCACertFile, tlsCertFile, tlsKeyFile,
		)
		if err != nil {
			log.Panicln(err)
		}

		tlsMsg := message + "Through TLS connection.\n"
		log.Println("Listening on TLS port", tlsPort)
		go listenAndHandle(tlsListener, tlsMsg)
	}

	// spawn a UDP server
	u, err := net.ListenPacket("udp", ":"+udpPort)
	if err != nil {
		log.Panicln(err)
	}

	log.Println("Listening on UDP port", udpPort)
	defer u.Close()

	go listenPacketAndHandle(u, message)

	// spawn an HTTP server
	http.HandleFunc("/", generateHTTPHandler(message))
	h, err := net.Listen("tcp", ":"+httpPort)
	if err != nil {
		log.Panicln(err)
	}

	log.Println("Listening on HTTP port", httpPort)
	defer h.Close()

	go func() {
		err := http.Serve(h, nil)
		log.Println("HTTP server exited: ", err)
	}()

	// spawn a TCP server
	l, err := net.Listen("tcp", ":"+tcpPort)
	if err != nil {
		log.Panicln(err)
	}

	log.Println("Listening on TCP port", tcpPort)
	defer l.Close()

	listenAndHandle(l, message)
}

func listenAndHandle(listener net.Listener, message string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Panicln(err)
		}

		go handleTCPRequest(conn, message)
	}
}

func listenPacketAndHandle(conn net.PacketConn, message string) {
	for {
		buf := make([]byte, 1024)
		size, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Println("Read error:", err)
			continue
		}
		_, err = conn.WriteTo([]byte(message), addr)
		if err != nil {
			log.Println("Message write error:", err)
			continue
		}
		data := buf[:size]
		log.Println("Received Raw UDP Data:", data)
		log.Printf("Received UDP Data (converted to string): %s", data)
		_, err = conn.WriteTo(data, addr)
		if err != nil {
			log.Println("Echo write error:", err)
			continue
		}
		continue
	}

}

func generateHTTPHandler(message string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		callUuidV4, err := uuid.NewUUID()
		if err != nil {
			log.Println("could not generate a client ID", err)
		}
		clientId := callUuidV4.String()

		log.Println(clientId + " - HTTP connection open.")
		defer log.Println(clientId + " - HTTP connection closed.")

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Println(clientId+" - HTTP body read error: ", err)
			http.Error(w, fmt.Sprintf("could not read data: %s", err), http.StatusInternalServerError)
			return
		}
		log.Println(clientId+" - Received HTTP Raw Data:", body)
		log.Printf(clientId+" - Received HTTP Data (converted to string): %s", body)

		_, err = io.WriteString(w, message)
		if err != nil {
			log.Println("could not write data", err)
			http.Error(w, fmt.Sprintf("could not write data: %s", err), http.StatusInternalServerError)
			return
		}
		_, err = io.WriteString(w, string(body)+"\n")
		if err != nil {
			log.Println("could not write data", err)
			http.Error(w, fmt.Sprintf("could not write data: %s", err), http.StatusInternalServerError)
			return
		}
	}
}

func handleTCPRequest(conn net.Conn, message string) {
	callUuidV4, err := uuid.NewUUID()
	clientId := callUuidV4.String()
	if err != nil {
		log.Println("could not generate a client ID", err)
	}

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
		_, err = conn.Write(data)
		if err != nil {
			log.Println("could not write data", err)
		}
	}
}

func makeTLSListner(tlsPort string, tlsCACertFile string, tlsCertFile string, tlsKeyFile string) (
	net.Listener, error) {

	roots := x509.NewCertPool()
	if tlsCACertFile != "" {
		caCertPEM, err := os.ReadFile(tlsCACertFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA, err %v", err)
		}
		if !roots.AppendCertsFromPEM(caCertPEM) {
			return nil, fmt.Errorf("failed to append CA cert")
		}
	}

	cert, err := tls.LoadX509KeyPair(tlsCertFile, tlsKeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load cert, err %v", err)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      roots,
	}
	tlsListener, err := tls.Listen("tcp", ":"+tlsPort, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on TLS port %s: %v", tlsPort, err)
	}

	return tlsListener, nil
}
