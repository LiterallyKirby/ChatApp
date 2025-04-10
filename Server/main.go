package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
)

func main() {
	fmt.Println("Starting server...")
	server()
}

func server() {
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	fmt.Println("Client connected:", conn.RemoteAddr())
	defer conn.Close()

	// Create a buffered reader and read the incoming message
	reader := bufio.NewReader(conn)
	message, err := reader.ReadString('\n') // Capture the message here
	if err != nil {
		log.Println("Error reading from connection:", err)
		return
	}

	// Log the message received from the client (optional)
	log.Println("Received:", message)

	// Send a response back to the client
	response := "Hello from server!"
	conn.Write([]byte(response))
}
