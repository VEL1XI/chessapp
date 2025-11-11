package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var (
	db       *sql.DB
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
	lobbies     = make(map[int]*Lobby)
	lobbiesLock sync.RWMutex
)

type User struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	Password     string `json:"password,omitempty"`
	ProfilePic   string `json:"profile_pic"`
	TotalWins    int    `json:"total_wins"`
	TotalLosses  int    `json:"total_losses"`
	TotalDraws   int    `json:"total_draws"`
	TotalMatches int    `json:"total_matches"`
}

type Lobby struct {
	ID          int
	WhitePlayer string
	BlackPlayer string
	Turn        string
	FEN         string
	InGame      bool
	Clients     map[*websocket.Conn]*Client
	mutex       sync.RWMutex
}

type Client struct {
	Username string
	UserID   int
	Color    string
}

type WSMessage struct {
	Type    string                 `json:"type"`
	Payload map[string]interface{} `json:"payload"`
}

func main() {
	// Initialize database
	initDB()

	// Create uploads directory
	os.MkdirAll("uploads", 0755)

	// Initialize lobbies (8 lobbies)
	for i := 1; i <= 8; i++ {
		lobbies[i] = &Lobby{
			ID:      i,
			Turn:    "w",
			FEN:     "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1",
			Clients: make(map[*websocket.Conn]*Client),
		}
	}

	router := mux.NewRouter()

	// CORS Middleware
	router.Use(corsMiddleware)

	// API Routes
	api := router.PathPrefix("/api").Subrouter()
	api.HandleFunc("/register", registerHandler).Methods("POST", "OPTIONS")
	api.HandleFunc("/login", loginHandler).Methods("POST", "OPTIONS")
	api.HandleFunc("/lobbies", lobbiesHandler).Methods("GET", "OPTIONS")
	api.HandleFunc("/lobby/{id}/ws", lobbyWebSocketHandler)
	api.HandleFunc("/user/{id}", getUserHandler).Methods("GET", "OPTIONS")
	api.HandleFunc("/user/{id}", updateUserHandler).Methods("PUT", "OPTIONS")
	api.HandleFunc("/user/{id}/stats", getUserStatsHandler).Methods("GET", "OPTIONS")
	api.HandleFunc("/user-by-username/{username}", getUserByUsernameHandler).Methods("GET", "OPTIONS")
	api.HandleFunc("/upload-profile-pic", uploadProfilePicHandler).Methods("POST", "OPTIONS")

	// Static files
	router.PathPrefix("/uploads/").Handler(http.StripPrefix("/uploads/", http.FileServer(http.Dir("./uploads"))))
	router.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	fmt.Println("🚀 Server running on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func initDB() {
	var err error
	db, err = sql.Open("sqlite", "./chess.db")
	if err != nil {
		log.Fatal(err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		profile_pic TEXT DEFAULT '/uploads/default-avatar.png',
		total_wins INTEGER DEFAULT 0,
		total_losses INTEGER DEFAULT 0,
		total_draws INTEGER DEFAULT 0,
		total_matches INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS games (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		lobby_id INTEGER,
		white_player TEXT,
		black_player TEXT,
		winner TEXT,
		result TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatal(err)
	}

	log.Println("✅ Database initialized successfully")
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Validate username
	if user.Username == "" || len(user.Username) < 3 {
		http.Error(w, `{"error": "Username minimal 3 karakter"}`, http.StatusBadRequest)
		return
	}

	// Validate password
	if user.Password == "" || len(user.Password) < 6 {
		http.Error(w, `{"error": "Password minimal 6 karakter"}`, http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, `{"error": "Error processing password"}`, http.StatusInternalServerError)
		return
	}

	result, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)",
		user.Username, string(hashedPassword))

	if err != nil {
		http.Error(w, `{"error": "Username sudah digunakan"}`, http.StatusConflict)
		return
	}

	id, _ := result.LastInsertId()
	user.ID = int(id)
	user.Password = ""
	user.ProfilePic = "/uploads/default-avatar.png"
	user.TotalWins = 0
	user.TotalLosses = 0
	user.TotalDraws = 0
	user.TotalMatches = 0

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)

	log.Printf("✅ User registered: %s (ID: %d)", user.Username, user.ID)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginData User
	if err := json.NewDecoder(r.Body).Decode(&loginData); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	var user User
	var hashedPassword string

	err := db.QueryRow("SELECT id, username, password, profile_pic, total_wins, total_losses, total_draws, total_matches FROM users WHERE username = ?",
		loginData.Username).Scan(&user.ID, &user.Username, &hashedPassword, &user.ProfilePic, &user.TotalWins, &user.TotalLosses, &user.TotalDraws, &user.TotalMatches)

	if err != nil {
		http.Error(w, `{"error": "Username atau password salah"}`, http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(loginData.Password)); err != nil {
		http.Error(w, `{"error": "Username atau password salah"}`, http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)

	log.Printf("✅ User logged in: %s (ID: %d)", user.Username, user.ID)
}

func lobbiesHandler(w http.ResponseWriter, r *http.Request) {
	lobbiesLock.RLock()
	defer lobbiesLock.RUnlock()

	type LobbyInfo struct {
		ID          int  `json:"id"`
		PlayerCount int  `json:"playerCount"`
		InGame      bool `json:"inGame"`
	}

	var lobbyList []LobbyInfo

	for i := 1; i <= 8; i++ {
		lobby, exists := lobbies[i]
		if !exists {
			continue
		}

		lobby.mutex.RLock()
		lobbyList = append(lobbyList, LobbyInfo{
			ID:          lobby.ID,
			PlayerCount: len(lobby.Clients),
			InGame:      lobby.InGame,
		})
		lobby.mutex.RUnlock()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(lobbyList)
}

func lobbyWebSocketHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	lobbyID, err := strconv.Atoi(vars["id"])
	if err != nil {
		log.Println("Invalid lobby ID:", err)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Upgrade error:", err)
		return
	}

	lobbiesLock.RLock()
	lobby := lobbies[lobbyID]
	lobbiesLock.RUnlock()

	if lobby == nil {
		log.Printf("Lobby %d not found", lobbyID)
		conn.Close()
		return
	}

	log.Printf("🔌 WebSocket connection established for lobby %d", lobbyID)
	handleWebSocket(conn, lobby)
}

func handleWebSocket(conn *websocket.Conn, lobby *Lobby) {
	defer conn.Close()

	var client *Client

	for {
		var msg WSMessage
		err := conn.ReadJSON(&msg)
		if err != nil {
			if client != nil {
				lobby.mutex.Lock()
				delete(lobby.Clients, conn)

				log.Printf("❌ Player %s disconnected from lobby %d", client.Username, lobby.ID)

				// Notify other players
				for c := range lobby.Clients {
					c.WriteJSON(WSMessage{
						Type: "playerLeft",
						Payload: map[string]interface{}{
							"username": client.Username,
						},
					})
				}

				// Reset lobby if empty
				if len(lobby.Clients) == 0 {
					lobby.WhitePlayer = ""
					lobby.BlackPlayer = ""
					lobby.InGame = false
					lobby.Turn = "w"
					lobby.FEN = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"
					log.Printf("🔄 Lobby %d reset (empty)", lobby.ID)
				}
				lobby.mutex.Unlock()
			}
			break
		}

		switch msg.Type {
		case "join":
			lobby.mutex.Lock()

			username := msg.Payload["username"].(string)
			userID := int(msg.Payload["userId"].(float64))

			client = &Client{
				Username: username,
				UserID:   userID,
			}

			// Check if player is reconnecting
			isReconnect := false
			if lobby.WhitePlayer == username {
				client.Color = "white"
				isReconnect = true
			} else if lobby.BlackPlayer == username {
				client.Color = "black"
				isReconnect = true
			} else {
				// Assign color for new player
				if lobby.WhitePlayer == "" {
					lobby.WhitePlayer = username
					client.Color = "white"
				} else if lobby.BlackPlayer == "" {
					lobby.BlackPlayer = username
					client.Color = "black"
					lobby.InGame = true
				}
			}

			lobby.Clients[conn] = client

			if isReconnect {
				log.Printf("🔄 Player %s reconnected to lobby %d as %s", username, lobby.ID, client.Color)
			} else {
				log.Printf("✅ Player %s joined lobby %d as %s", username, lobby.ID, client.Color)
			}

			// Send current game state to joining player
			conn.WriteJSON(WSMessage{
				Type: "playerJoined",
				Payload: map[string]interface{}{
					"username": username,
					"color":    client.Color,
					"game": map[string]interface{}{
						"white_player": lobby.WhitePlayer,
						"black_player": lobby.BlackPlayer,
						"turn":         lobby.Turn,
						"fen":          lobby.FEN,
					},
				},
			})

			// Broadcast to all other clients
			for c := range lobby.Clients {
				if c != conn {
					c.WriteJSON(WSMessage{
						Type: "playerJoined",
						Payload: map[string]interface{}{
							"username": username,
							"color":    client.Color,
							"game": map[string]interface{}{
								"white_player": lobby.WhitePlayer,
								"black_player": lobby.BlackPlayer,
								"turn":         lobby.Turn,
								"fen":          lobby.FEN,
							},
						},
					})
				}
			}

			lobby.mutex.Unlock()

		case "move":
			lobby.mutex.Lock()

			from := msg.Payload["from"].(string)
			to := msg.Payload["to"].(string)
			promotion := ""
			if p, ok := msg.Payload["promotion"].(string); ok {
				promotion = p
			}

			if fen, ok := msg.Payload["fen"].(string); ok {
				lobby.FEN = fen
			}

			// Toggle turn
			if lobby.Turn == "w" {
				lobby.Turn = "b"
			} else {
				lobby.Turn = "w"
			}

			log.Printf("♟️ Move in lobby %d: %s → %s", lobby.ID, from, to)

			// Broadcast move to all other clients
			for c := range lobby.Clients {
				if c != conn {
					c.WriteJSON(WSMessage{
						Type: "move",
						Payload: map[string]interface{}{
							"from":      from,
							"to":        to,
							"promotion": promotion,
							"game": map[string]interface{}{
								"turn": lobby.Turn,
								"fen":  lobby.FEN,
							},
						},
					})
				}
			}

			lobby.mutex.Unlock()

		case "gameOver":
			lobby.mutex.Lock()

			winner := msg.Payload["winner"].(string)
			result := msg.Payload["result"].(string)

			log.Printf("🏁 Game over in lobby %d - Winner: %s, Result: %s", lobby.ID, winner, result)

			// Save game to database
			_, err := db.Exec("INSERT INTO games (lobby_id, white_player, black_player, winner, result) VALUES (?, ?, ?, ?, ?)",
				lobby.ID, lobby.WhitePlayer, lobby.BlackPlayer, winner, result)

			if err != nil {
				log.Println("❌ Error saving game:", err)
			}

			// Update user stats
			if result == "draw" {
				updateUserStats(lobby.WhitePlayer, "draw")
				updateUserStats(lobby.BlackPlayer, "draw")
			} else {
				winnerUsername := lobby.WhitePlayer
				loserUsername := lobby.BlackPlayer
				if winner == "black" {
					winnerUsername = lobby.BlackPlayer
					loserUsername = lobby.WhitePlayer
				}

				updateUserStats(winnerUsername, "win")
				updateUserStats(loserUsername, "loss")
			}

			// Broadcast game over to all clients
			for c := range lobby.Clients {
				c.WriteJSON(WSMessage{
					Type: "gameOver",
					Payload: map[string]interface{}{
						"winner": winner,
						"result": result,
					},
				})
			}

			lobby.mutex.Unlock()

		case "rematch":
			lobby.mutex.Lock()

			log.Printf("🔄 Rematch requested in lobby %d", lobby.ID)

			// Swap colors for rematch
			oldWhite := lobby.WhitePlayer
			oldBlack := lobby.BlackPlayer

			lobby.WhitePlayer = oldBlack
			lobby.BlackPlayer = oldWhite

			// Update client colors
			for _, client := range lobby.Clients {
				if client.Username == lobby.WhitePlayer {
					client.Color = "white"
				} else if client.Username == lobby.BlackPlayer {
					client.Color = "black"
				}
			}

			// Reset game
			lobby.Turn = "w"
			lobby.FEN = "rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1"

			log.Printf("🔄 Colors swapped: %s (white) vs %s (black)", lobby.WhitePlayer, lobby.BlackPlayer)

			// Broadcast rematch to all clients
			for c := range lobby.Clients {
				c.WriteJSON(WSMessage{
					Type: "rematch",
					Payload: map[string]interface{}{
						"game": map[string]interface{}{
							"white_player": lobby.WhitePlayer,
							"black_player": lobby.BlackPlayer,
							"turn":         lobby.Turn,
							"fen":          lobby.FEN,
						},
					},
				})
			}

			lobby.mutex.Unlock()
		}
	}
}

func updateUserStats(username string, result string) {
	switch result {
	case "win":
		_, err := db.Exec("UPDATE users SET total_wins = total_wins + 1, total_matches = total_matches + 1 WHERE username = ?", username)
		if err != nil {
			log.Printf("❌ Error updating win stats for %s: %v", username, err)
		} else {
			log.Printf("✅ Updated stats for %s: +1 win", username)
		}
	case "loss":
		_, err := db.Exec("UPDATE users SET total_losses = total_losses + 1, total_matches = total_matches + 1 WHERE username = ?", username)
		if err != nil {
			log.Printf("❌ Error updating loss stats for %s: %v", username, err)
		} else {
			log.Printf("✅ Updated stats for %s: +1 loss", username)
		}
	case "draw":
		_, err := db.Exec("UPDATE users SET total_draws = total_draws + 1, total_matches = total_matches + 1 WHERE username = ?", username)
		if err != nil {
			log.Printf("❌ Error updating draw stats for %s: %v", username, err)
		} else {
			log.Printf("✅ Updated stats for %s: +1 draw", username)
		}
	}
}

func getUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	var user User
	err := db.QueryRow("SELECT id, username, profile_pic, total_wins, total_losses, total_draws, total_matches FROM users WHERE id = ?",
		userID).Scan(&user.ID, &user.Username, &user.ProfilePic, &user.TotalWins, &user.TotalLosses, &user.TotalDraws, &user.TotalMatches)

	if err != nil {
		http.Error(w, `{"error": "User tidak ditemukan"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func getUserByUsernameHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	username := vars["username"]

	var user User
	err := db.QueryRow("SELECT id, username, profile_pic, total_wins, total_losses, total_draws, total_matches FROM users WHERE username = ?",
		username).Scan(&user.ID, &user.Username, &user.ProfilePic, &user.TotalWins, &user.TotalLosses, &user.TotalDraws, &user.TotalMatches)

	if err != nil {
		http.Error(w, `{"error": "User tidak ditemukan"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func updateUserHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	var updateData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&updateData); err != nil {
		http.Error(w, `{"error": "Invalid request body"}`, http.StatusBadRequest)
		return
	}

	// Build dynamic update query
	query := "UPDATE users SET "
	args := []interface{}{}
	updates := []string{}

	if username, ok := updateData["username"].(string); ok && username != "" {
		// Validate username length
		if len(username) < 3 {
			http.Error(w, `{"error": "Username minimal 3 karakter"}`, http.StatusBadRequest)
			return
		}

		// Check if username already exists
		var count int
		db.QueryRow("SELECT COUNT(*) FROM users WHERE username = ? AND id != ?", username, userID).Scan(&count)
		if count > 0 {
			http.Error(w, `{"error": "Username sudah digunakan"}`, http.StatusConflict)
			return
		}
		updates = append(updates, "username = ?")
		args = append(args, username)
		log.Printf("📝 Updating username for user ID %s to: %s", userID, username)
	}

	if profilePic, ok := updateData["profile_pic"].(string); ok && profilePic != "" {
		updates = append(updates, "profile_pic = ?")
		args = append(args, profilePic)
		log.Printf("📷 Updating profile pic for user ID %s", userID)
	}

	if len(updates) == 0 {
		http.Error(w, `{"error": "Tidak ada data untuk diupdate"}`, http.StatusBadRequest)
		return
	}

	query += updates[0]
	for i := 1; i < len(updates); i++ {
		query += ", " + updates[i]
	}
	query += " WHERE id = ?"
	args = append(args, userID)

	_, err := db.Exec(query, args...)
	if err != nil {
		log.Printf("❌ Update error for user ID %s: %v", userID, err)
		http.Error(w, `{"error": "Gagal update user"}`, http.StatusInternalServerError)
		return
	}

	// Return updated user
	var user User
	err = db.QueryRow("SELECT id, username, profile_pic, total_wins, total_losses, total_draws, total_matches FROM users WHERE id = ?",
		userID).Scan(&user.ID, &user.Username, &user.ProfilePic, &user.TotalWins, &user.TotalLosses, &user.TotalDraws, &user.TotalMatches)

	if err != nil {
		log.Printf("❌ Error fetching updated user: %v", err)
		http.Error(w, `{"error": "Gagal mengambil data user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)

	log.Printf("✅ User profile updated successfully for: %s (ID: %d)", user.Username, user.ID)
}

func getUserStatsHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	userID := vars["id"]

	var stats struct {
		TotalMatches int `json:"total_matches"`
		TotalWins    int `json:"total_wins"`
		TotalLosses  int `json:"total_losses"`
		TotalDraws   int `json:"total_draws"`
	}

	err := db.QueryRow("SELECT total_matches, total_wins, total_losses, total_draws FROM users WHERE id = ?",
		userID).Scan(&stats.TotalMatches, &stats.TotalWins, &stats.TotalLosses, &stats.TotalDraws)

	if err != nil {
		http.Error(w, `{"error": "User tidak ditemukan"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func uploadProfilePicHandler(w http.ResponseWriter, r *http.Request) {
	// Parse multipart form (max 10MB)
	err := r.ParseMultipartForm(10 << 20)
	if err != nil {
		http.Error(w, `{"error": "File terlalu besar"}`, http.StatusBadRequest)
		return
	}

	file, handler, err := r.FormFile("profile_pic")
	if err != nil {
		http.Error(w, `{"error": "Gagal membaca file"}`, http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Check file size (max 5MB)
	if handler.Size > 5*1024*1024 {
		http.Error(w, `{"error": "File terlalu besar, maksimal 5MB"}`, http.StatusBadRequest)
		return
	}

	// Validate file type
	allowedTypes := map[string]bool{
		"image/jpeg": true,
		"image/jpg":  true,
		"image/png":  true,
		"image/gif":  true,
	}

	buffer := make([]byte, 512)
	_, err = file.Read(buffer)
	if err != nil {
		http.Error(w, `{"error": "Gagal membaca file"}`, http.StatusInternalServerError)
		return
	}
	file.Seek(0, 0) // Reset file pointer

	contentType := http.DetectContentType(buffer)
	if !allowedTypes[contentType] {
		http.Error(w, `{"error": "Format file tidak didukung. Gunakan JPG, PNG, atau GIF"}`, http.StatusBadRequest)
		return
	}

	// Create unique filename
	ext := filepath.Ext(handler.Filename)
	filename := fmt.Sprintf("%d%s", time.Now().UnixNano(), ext)
	filePath := filepath.Join("uploads", filename)

	// Save file
	dst, err := os.Create(filePath)
	if err != nil {
		log.Printf("❌ Error creating file: %v", err)
		http.Error(w, `{"error": "Gagal menyimpan file"}`, http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	_, err = io.Copy(dst, file)
	if err != nil {
		log.Printf("❌ Error saving file: %v", err)
		http.Error(w, `{"error": "Gagal menyimpan file"}`, http.StatusInternalServerError)
		return
	}

	url := "/uploads/" + filename

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"url": url,
	})

	log.Printf("✅ Profile picture uploaded: %s", filename)
}
