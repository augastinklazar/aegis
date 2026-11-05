package sandbox

import (
	"database/sql"
	"fmt"
	"time"
)

type StateCounter struct {
	db *sql.DB
}

func NewStateCounter(db *sql.DB) (*StateCounter, error) {
	sc := &StateCounter{db: db}
	if err := sc.initSchema(); err != nil {
		return nil, fmt.Errorf("state counter schema init: %w", err)
	}
	return sc, nil
}

func (sc *StateCounter) initSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS state_metrics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id TEXT NOT NULL,
		metric TEXT NOT NULL,
		amount REAL NOT NULL,
		timestamp DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_state_agent_metric_ts ON state_metrics(agent_id, metric, timestamp);
	`
	_, err := sc.db.Exec(schema)
	return err
}

func (sc *StateCounter) Record(agentID, metric string, amount float64) error {
	now := time.Now().UTC()
	query := `INSERT INTO state_metrics (agent_id, metric, amount, timestamp) VALUES (?, ?, ?, ?)`
	_, err := sc.db.Exec(query, agentID, metric, amount, now)
	return err
}

func (sc *StateCounter) DailySum(agentID, metric string) float64 {
	return sc.WindowSum(agentID, metric, 24*time.Hour)
}

func (sc *StateCounter) HourlySum(agentID, metric string) float64 {
	return sc.WindowSum(agentID, metric, time.Hour)
}

func (sc *StateCounter) WindowSum(agentID, metric string, window time.Duration) float64 {
	cutoff := time.Now().UTC().Add(-window)
	query := `SELECT COALESCE(SUM(amount), 0.0) FROM state_metrics WHERE agent_id = ? AND metric = ? AND timestamp >= ?`
	var sum float64
	err := sc.db.QueryRow(query, agentID, metric, cutoff).Scan(&sum)
	if err != nil {
		return 0.0
	}
	return sum
}

func (sc *StateCounter) DailyCount(agentID, metric string) int64 {
	cutoff := time.Now().UTC().Add(-24 * time.Hour)
	query := `SELECT COUNT(*) FROM state_metrics WHERE agent_id = ? AND metric = ? AND timestamp >= ?`
	var count int64
	err := sc.db.QueryRow(query, agentID, metric, cutoff).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}
