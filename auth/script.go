package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func storeDemoData(db *sql.DB) {
	var err error
	// Demo data
	pass := "Secret12345@"
	if err := validatePasswordPolicy(pass); err != nil {
		log.Fatalf("Demo password policy: %v", err)
	}
	passHash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	_, err = db.Exec(`INSERT INTO users(id, username, email, created_at, updated_at) VALUES(?,?,?,?,?)`,
		"u1", "alice", "alice@example.com", time.Now(), time.Now())
	if err != nil {
		log.Fatalf("Demo user insert error: %v", err)
	}
	_, err = db.Exec(`INSERT INTO credentials(id, user_id, type, provider, identifier, secret_hash, created_at)
	VALUES(?,?,?,?,?,?,?)`,
		"c1", "u1", "password", "internal", "alice", string(passHash), time.Now())
	if err != nil {
		log.Fatalf("Demo password credential insert error: %v", err)
	}
	key, keyHash, _ := generateAPIKey()
	_, err = db.Exec(`INSERT INTO credentials(id, user_id, type, provider, identifier, secret_hash, created_at)
	VALUES(?,?,?,?,?,?,?)`,
		"k1", "u1", "apikey", "internal", "k1", keyHash, time.Now())
	if err != nil {
		log.Fatalf("Demo apikey credential insert error: %v", err)
	}
	fmt.Println("Api Key", key)
}

func setupSchema(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE NOT NULL,
		phone TEXT,
		full_name TEXT,
		avatar_url TEXT,
		email_verified INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS credentials (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		type TEXT NOT NULL,
		provider TEXT,
		identifier TEXT,
		secret_hash TEXT,
		metadata TEXT,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_used_at TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token TEXT NOT NULL UNIQUE,
		user_agent TEXT,
		ip TEXT,
		expires_at TIMESTAMP NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS password_resets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		used INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS failed_logins (
		user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
		count INTEGER NOT NULL DEFAULT 0,
		locked_at TIMESTAMP,
		updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS password_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		hash TEXT NOT NULL,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS email_verifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		used INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
		token_hash TEXT NOT NULL,
		expires_at TIMESTAMP NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_credentials_user_id ON credentials(user_id);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
	CREATE INDEX IF NOT EXISTS idx_failed_logins_user_id ON failed_logins(user_id);
	CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id);
	CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
	`)
	return err
}
