package agents

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Agent struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IP        string    `json:"ip"`
	Version   string    `json:"version"`
	Status    string    `json:"status"`
	LastSeen  time.Time `json:"last_seen"`
	Commands  []Command `json:"commands,omitempty"`
}

type Command struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Payload   string `json:"payload"`
	Status    string `json:"status"`
}

type FleetManager struct {
	mu      sync.RWMutex
	agents  map[string]*Agent
}

func NewFleetManager() *FleetManager {
	return &FleetManager{
		agents: make(map[string]*Agent),
	}
}

func (fm *FleetManager) Register(agent *Agent) {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	if agent.ID == "" {
		agent.ID = uuid.New().String()
	}
	agent.Status = "active"
	agent.LastSeen = time.Now()
	fm.agents[agent.ID] = agent
}

func (fm *FleetManager) Heartbeat(id string) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	agent, exists := fm.agents[id]
	if exists {
		agent.LastSeen = time.Now()
		agent.Status = "active"
	}
	return exists
}

func (fm *FleetManager) GetAgent(id string) *Agent {
	fm.mu.RLock()
	defer fm.mu.RUnlock()
	return fm.agents[id]
}

func (fm *FleetManager) ListAgents() []*Agent {
	fm.mu.RLock()
	defer fm.mu.RUnlock()

	result := make([]*Agent, 0, len(fm.agents))
	for _, a := range fm.agents {
		result = append(result, a)
	}
	return result
}

func (fm *FleetManager) SendCommand(id, cmdType, payload string) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	agent, exists := fm.agents[id]
	if !exists {
		return false
	}

	agent.Commands = append(agent.Commands, Command{
		ID:      uuid.New().String(),
		Type:    cmdType,
		Payload: payload,
		Status:  "pending",
	})
	return true
}

func (fm *FleetManager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		fm.mu.RLock()
		agents := make([]*Agent, 0, len(fm.agents))
		for _, a := range fm.agents {
			agents = append(agents, a)
		}
		fm.mu.RUnlock()
		json.NewEncoder(w).Encode(agents)

	case http.MethodPost:
		var agent Agent
		if err := json.NewDecoder(r.Body).Decode(&agent); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		fm.Register(&agent)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(agent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (fm *FleetManager) StartPruner() {
	ticker := time.NewTicker(1 * time.Minute)
	go func() {
		for range ticker.C {
			fm.mu.Lock()
			for _, agent := range fm.agents {
				if time.Since(agent.LastSeen) > 5*time.Minute {
					agent.Status = "offline"
				}
			}
			fm.mu.Unlock()
		}
	}()
}
