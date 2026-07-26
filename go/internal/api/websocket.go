package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		allowedOrigins := []string{
			"http://localhost:8000",
			"http://127.0.0.1:8000",
			"http://localhost:8080",
			"http://127.0.0.1:8080",
		}
		if envOrigins := os.Getenv("TRAKSHYA_CORS_ORIGINS"); envOrigins != "" {
			allowedOrigins = strings.Split(envOrigins, ",")
		}
		for _, allowed := range allowedOrigins {
			if origin == allowed {
				return true
			}
		}
		return false
	},
}

type WebSocketHub struct {
	clients map[*websocket.Conn]bool
	mu      sync.Mutex
}

var hub = &WebSocketHub{
	clients: make(map[*websocket.Conn]bool),
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	hub.mu.Lock()
	hub.clients[conn] = true
	hub.mu.Unlock()

	defer func() {
		hub.mu.Lock()
		delete(hub.clients, conn)
		hub.mu.Unlock()
		conn.Close()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func BroadcastIncident(incident interface{}) {
	data, err := json.Marshal(map[string]interface{}{
		"type":    "incident",
		"payload": incident,
	})
	if err != nil {
		return
	}

	hub.mu.Lock()
	clients := make([]*websocket.Conn, 0, len(hub.clients))
	for conn := range hub.clients {
		clients = append(clients, conn)
	}
	hub.mu.Unlock()

	var broken []*websocket.Conn
	for _, conn := range clients {
		if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
			log.Printf("WebSocket write error: %v", err)
			conn.Close()
			broken = append(broken, conn)
		}
	}
	if len(broken) > 0 {
		hub.mu.Lock()
		defer hub.mu.Unlock()
		for _, conn := range broken {
			delete(hub.clients, conn)
		}
	}
}
