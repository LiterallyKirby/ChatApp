package main

import (
	"bufio"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	//"log"
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

var clients = make(map[net.Conn]string)

var commands = []string{"Quit", "ChangeNick", "ListUsers", "Help"}

func handleConnection(conn net.Conn) {
	fmt.Println("Client connected:", conn.RemoteAddr())
	defer conn.Close()

	// Create a buffered reader and read the incoming message
	reader := bufio.NewReader(conn)
	conn.Write([]byte("Welcome to the server!\n"))
	conn.Write([]byte("Please enter a Username:\n"))
	nickname, _ := reader.ReadString('\n') // Capture the nickname
	trimmedNickname := strings.TrimSpace(nickname)
	if trimmedNickname == "" {
		rand := strconv.Itoa(rand.IntN(1000)) // Generate a random number
		anonUsername := "Anon" + rand         // Default to "Anon" if no nickname is provided
		nickname = anonUsername
	} else {
		nickname = nickname[:len(nickname)-1] // Remove the newline character
	}
	clients[conn] = nickname // Add the client to the map with their nickname

	BroadcastMessage(fmt.Sprintf("%s has joined the chat\n", nickname))

	for {
		message, _ := reader.ReadString('\n')
		trimmed := strings.TrimSpace(message)
		if trimmed != "" {
			cleanedMessage := message[:len(message)-1] // Remove the newline character
			firstChar := cleanedMessage[0]
			if firstChar == '/' {
				switch cleanedMessage {
				case "/quit":
					conn.Close()
					delete(clients, conn) // Remove the client from the map
					goodbyeMessage := nickname + " has left the chat\n"
					BroadcastMessage(goodbyeMessage)
				case "/nick":

				}
			} else {
				messageToSend := nickname + ": " + cleanedMessage + "\n"
				BroadcastMessage(messageToSend)
			}

		} else {
			continue
		}
	}
	conn.Close()
	delete(clients, conn) // Remove the client from the map
	goodbyeMessage := nickname + " has left the chat\n"
	BroadcastMessage(goodbyeMessage)
}

func BroadcastMessage(message string) {
	for conn := range clients {
		conn.Write([]byte(message))
	}
}
