package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand/v2"
	"net/http"
	"os"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/websocket"
	//"log"
)

type MessagePacket struct {
	Type string `json:"type"`
	From string `json:"from"`
	To   string `json:"to,omitempty"`
	Body string `json:"body"`
}

type UserStore map[string]string

func main() {
	fmt.Println("Starting server...")
	ensureDataDirectory()
	var err error
	users, err = loadUsers()
	if err != nil {
		log.Fatal("Failed to load users:", err)
	}
	server()
}

func server() {
	http.HandleFunc("/ws", handleWebSocket)
	println("Server started on :8080")
	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)
	http.HandleFunc("/chat", serveChatPage)
	fmt.Println("Static file server started")
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/signup", handleSignUp)
	http.ListenAndServe(":8080", nil)
	loadUsers()
	fmt.Println("Ready to accept connections")
}

const userFile = "data/users.json"

func loadUsers() (map[string]string, error) {
	file, err := os.Open("data/users.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var users map[string]string
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

func saveUsers(users map[string]string) error {
	file, err := os.Create("data/users.json")
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	err = encoder.Encode(users)
	if err != nil {
		return err
	}

	return nil
}

var (
	clients = make(map[*websocket.Conn]string)
	users   = make(map[string]string)
	jwtKey  = []byte("super-secret-key") // In production, store this in an env variable

)

var commands = []string{"Quit", "ChangeNick", "ListUsers", "Help"}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func serveChatPage(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "static/chat.html")
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		users, err := loadUsers() // Load users from disk
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		hashedPassword, ok := users[username]
		if !ok {
			fmt.Fprintln(w, "Invalid username or password.")
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
		if err != nil {
			fmt.Fprintln(w, "Invalid username or password.")
			return
		}

		// Set the cookie with additional secure options
		cookie := &http.Cookie{
			Name:     "username",
			Value:    username,
			Path:     "/",
			MaxAge:   86400, // 1 day in seconds
			HttpOnly: true,  // Helps prevent XSS attacks
			Secure:   false, // Set to true if using HTTPS
			SameSite: http.SameSiteLaxMode,
		}
		http.SetCookie(w, cookie)

		// Create JWT token
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": username,
			"exp":      time.Now().Add(24 * time.Hour).Unix(),
		})

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}

		// Set it as a cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "token",
			Value:    tokenString,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})

		// Redirect to the chat page
		http.Redirect(w, r, "/chat", http.StatusSeeOther)

		return
	}

	// If not POST, show the login form
	http.ServeFile(w, r, "static/login.html")
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == "" || password == "" {
			fmt.Fprintln(w, "Username and password required.")
			return
		}

		users, err := loadUsers()
		if err != nil {
			log.Println("Failed to load users:", err)
			fmt.Fprintln(w, "Internal error.")
			return
		}

		if _, exists := users[username]; exists {
			fmt.Fprintln(w, "Username already exists.")
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			log.Println("Hash error:", err)
			fmt.Fprintln(w, "Internal error.")
			return
		}

		users[username] = string(hashedPassword)

		if err := saveUsers(users); err != nil {
			log.Println("Failed to save users:", err)
			fmt.Fprintln(w, "Internal error.")
			return
		}

		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	http.ServeFile(w, r, "static/signup.html")
}

func generateUsername(r *http.Request) string {
	// Generate a random username, prefixed with "Anon" and a random number
	return "Anon" + strconv.Itoa(rand.IntN(10000))
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade initial GET request to a websocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("WebSocket upgrade error:", err)
		return
	}
	defer ws.Close()

	// Retrieve the username from the cookie (or generate one if not found)

	var username string

	cookie, err := r.Cookie("token")
	if err != nil {
		log.Println("No token cookie found, redirecting or denying access")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	tokenStr := cookie.Value
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		username = claims["username"].(string)
		log.Println("Authenticated user:", username)
	} else {
		log.Println("Invalid token:", err)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	// Notify others
	BroadcastJSON(MessagePacket{
		Type: "info",
		Body: fmt.Sprintf("%s joined the chat", username),
	})

	for {
		var msg MessagePacket
		err := ws.ReadJSON(&msg)
		if err != nil {
			fmt.Println("WebSocket read error:", err)
			break
		}

		switch msg.Type {
		case "nick":
			old := clients[ws]
			clients[ws] = msg.Body
			BroadcastJSON(MessagePacket{
				Type: "info",
				Body: fmt.Sprintf("%s is now known as %s", old, msg.Body),
			})
		case "broadcast":
			BroadcastJSON(MessagePacket{
				Type: "message",
				From: clients[ws],
				Body: msg.Body,
			})
		case "quit":
			// handled after the loop
			break
		default:
			ws.WriteJSON(MessagePacket{
				Type: "error",
				Body: "Unknown command type",
			})
		}
	}

	// Cleanup
	leaveMsg := fmt.Sprintf("%s has left the chat", clients[ws])
	delete(clients, ws)
	BroadcastJSON(MessagePacket{
		Type: "info",
		Body: leaveMsg,
	})
}

func ensureDataDirectory() error {
	// Create the directory if it doesn't exist
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		err := os.Mkdir("data", 0755)
		if err != nil {
			return fmt.Errorf("failed to create data directory: %v", err)
		}
	}

	// Check if users.json file exists
	if _, err := os.Stat("data/users.json"); os.IsNotExist(err) {
		// Create the file if it doesn't exist
		file, err := os.Create("data/users.json")
		if err != nil {
			return fmt.Errorf("failed to create users.json file: %v", err)
		}
		defer file.Close()

		// Initialize with an empty users map (or whatever structure you use)
		users := make(map[string]string)
		encoder := json.NewEncoder(file)
		err = encoder.Encode(users)
		if err != nil {
			return fmt.Errorf("failed to initialize users file: %v", err)
		}
	}

	return nil
}

/*
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
			if trimmed == "" {
				continue
			}

			firstChar := trimmed[0]
			if firstChar == '/' {
				switch trimmed {
				case "/quit":
					conn.Close()
					delete(clients, conn)
					goodbyeMessage := nickname + " has left the chat\n"
					BroadcastMessage(goodbyeMessage)
					return

				case "/nick":
					conn.Write([]byte("Enter a new nickname:\n"))
					newNickRaw, _ := reader.ReadString('\n')
					newNick := strings.TrimSpace(newNickRaw)

					if newNick == "" {
						newNick = "Anon" + strconv.Itoa(rand.IntN(1000))
					}

					oldNick := nickname
					nickname = newNick
					clients[conn] = nickname

					BroadcastMessage(fmt.Sprintf("%s is now known as %s\n", oldNick, nickname))
				}
			} else {
				messageToSend := nickname + ": " + trimmed + "\n"
				BroadcastMessage(messageToSend)
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
*/
func BroadcastJSON(msg MessagePacket) {
	for conn := range clients {

		err := conn.WriteJSON(msg)
		if err != nil {
			log.Println("WebSocket write error:", err)
		}
	}
}
