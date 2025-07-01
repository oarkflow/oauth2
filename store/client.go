package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"

	"github.com/oarkflow/oauth2"
	"github.com/oarkflow/oauth2/models"
)

// NewClientStore create client store
func NewClientStore() *ClientStore {
	return &ClientStore{
		data: make(map[string]oauth2.ClientInfo),
	}
}

// ClientStore client information store
type ClientStore struct {
	sync.RWMutex
	data map[string]oauth2.ClientInfo
}

// GetByID according to the ID for the client information
func (cs *ClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	cs.RLock()
	defer cs.RUnlock()

	if c, ok := cs.data[id]; ok {
		return c, nil
	}
	return nil, errors.New("not found")
}

// Set set client information
func (cs *ClientStore) Set(id string, cli oauth2.ClientInfo) (err error) {
	cs.Lock()
	defer cs.Unlock()

	cs.data[id] = cli
	return
}

func NewSQLClientStore(db *sql.DB) *SQLClientStore {
	return &SQLClientStore{DB: db}
}

// SQLClientStore implements oauth2.ClientStore using a SQL database.
type SQLClientStore struct {
	DB *sql.DB
}

// GetByID fetches client info from the database by client ID.
func (s *SQLClientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	row := s.DB.QueryRowContext(ctx, `SELECT info FROM clients WHERE id = ?`, id)
	var infoJSON string
	if err := row.Scan(&infoJSON); err != nil {
		if err == sql.ErrNoRows {
			return nil, errors.New("not found")
		}
		return nil, err
	}
	var info models.Client
	if err := json.Unmarshal([]byte(infoJSON), &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// Set stores or updates client info in the database.
func (s *SQLClientStore) Set(id string, cli oauth2.ClientInfo) error {
	b, err := json.Marshal(cli)
	if err != nil {
		return err
	}
	_, err = s.DB.Exec(`INSERT OR REPLACE INTO clients(id, info) VALUES (?, ?)`, id, string(b))
	return err
}

// SetupClientsTable creates the clients table if it does not exist.
func SetupClientsTable(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS clients (
		id TEXT PRIMARY KEY,
		info TEXT NOT NULL
	);
	`)
	return err
}
