package ws

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
)

type SSEClient struct {
	ch   chan []byte
	done chan struct{}
}

type SSEHub struct {
	mu      sync.RWMutex
	clients map[string]*SSEClient
}

func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients: make(map[string]*SSEClient),
	}
}

func (h *SSEHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := &SSEClient{
		ch:   make(chan []byte, 10),
		done: make(chan struct{}),
	}

	id := fmt.Sprintf("%d", len(h.clients))
	h.mu.Lock()
	h.clients[id] = client
	h.mu.Unlock()

	defer func() {
		h.mu.Lock()
		delete(h.clients, id)
		h.mu.Unlock()
	}()

	notify := r.Context().Done()

	for {
		select {
		case <-notify:
			return
		case data := <-client.ch:
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		}
	}
}

func (h *SSEHub) Broadcast(event string, payload interface{}) {
	data, err := json.Marshal(map[string]interface{}{
		"event":   event,
		"payload": payload,
	})
	if err != nil {
		return
	}

	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, client := range h.clients {
		select {
		case client.ch <- data:
		default:
		}
	}
}
