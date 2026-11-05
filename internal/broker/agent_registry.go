package broker

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrAgentNotFound = errors.New("agent not registered")

type AgentManifest struct {
	AgentID         string    `json:"agent_id"`
	Name            string    `json:"name"`
	Purpose         string    `json:"purpose"`
	ModelProvider   string    `json:"model_provider"`
	AllowedServices []string  `json:"allowed_services"`
	AllowedTools    []string  `json:"allowed_tools"`
	RegisteredAt    time.Time `json:"registered_at"`
}

type AgentRegistry struct {
	db    *sql.DB
	cache sync.Map
}

func NewAgentRegistry(db *sql.DB) (*AgentRegistry, error) {
	ar := &AgentRegistry{db: db}
	if err := ar.initSchema(); err != nil {
		return nil, fmt.Errorf("agent registry schema init: %w", err)
	}
	return ar, nil
}

func (ar *AgentRegistry) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS agent_manifests (
		agent_id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		purpose TEXT NOT NULL,
		model_provider TEXT NOT NULL,
		allowed_services TEXT NOT NULL,
		allowed_tools TEXT NOT NULL,
		registered_at DATETIME NOT NULL
	);
	`
	_, err := ar.db.Exec(schema)
	return err
}

func (ar *AgentRegistry) Register(m *AgentManifest) error {
	if m.AgentID == "" {
		return errors.New("agent_id cannot be empty")
	}
	m.RegisteredAt = time.Now().UTC()

	srvJSON, _ := json.Marshal(m.AllowedServices)
	toolsJSON, _ := json.Marshal(m.AllowedTools)

	query := `
	INSERT INTO agent_manifests (agent_id, name, purpose, model_provider, allowed_services, allowed_tools, registered_at)
	VALUES (?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(agent_id) DO UPDATE SET
		name=excluded.name,
		purpose=excluded.purpose,
		model_provider=excluded.model_provider,
		allowed_services=excluded.allowed_services,
		allowed_tools=excluded.allowed_tools;
	`
	_, err := ar.db.Exec(query, m.AgentID, m.Name, m.Purpose, m.ModelProvider, string(srvJSON), string(toolsJSON), m.RegisteredAt)
	if err != nil {
		return err
	}

	ar.cache.Store(m.AgentID, m)
	return nil
}

func (ar *AgentRegistry) Get(agentID string) (*AgentManifest, error) {
	if val, ok := ar.cache.Load(agentID); ok {
		return val.(*AgentManifest), nil
	}

	var m AgentManifest
	var srvStr, toolsStr string
	query := `SELECT agent_id, name, purpose, model_provider, allowed_services, allowed_tools, registered_at FROM agent_manifests WHERE agent_id = ?`
	err := ar.db.QueryRow(query, agentID).Scan(&m.AgentID, &m.Name, &m.Purpose, &m.ModelProvider, &srvStr, &toolsStr, &m.RegisteredAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAgentNotFound
	}
	if err != nil {
		return nil, err
	}

	json.Unmarshal([]byte(srvStr), &m.AllowedServices)
	json.Unmarshal([]byte(toolsStr), &m.AllowedTools)

	ar.cache.Store(agentID, &m)
	return &m, nil
}

func (ar *AgentRegistry) List() ([]AgentManifest, error) {
	rows, err := ar.db.Query(`SELECT agent_id, name, purpose, model_provider, allowed_services, allowed_tools, registered_at FROM agent_manifests ORDER BY registered_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AgentManifest
	for rows.Next() {
		var m AgentManifest
		var srvStr, toolsStr string
		if err := rows.Scan(&m.AgentID, &m.Name, &m.Purpose, &m.ModelProvider, &srvStr, &toolsStr, &m.RegisteredAt); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(srvStr), &m.AllowedServices)
		json.Unmarshal([]byte(toolsStr), &m.AllowedTools)
		list = append(list, m)
	}
	return list, nil
}
