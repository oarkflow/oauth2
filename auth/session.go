package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// --- Session Management ---

type Session struct {
	ID        string
	UserID    string
	Token     string
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}

type SessionStore struct {
	DB      *sql.DB
	hmacKey []byte
}

func NewSessionStore(db *sql.DB, hmacKey []byte) *SessionStore {
	return &SessionStore{DB: db, hmacKey: hmacKey}
}

func (s *SessionStore) Create(ctx context.Context, userID, userAgent, ip string, ttl time.Duration) (Session, error) {
	id, err := generateRandomString(32)
	if err != nil {
		return Session{}, err
	}
	token := s.generateSessionToken(id, userID)
	expires := time.Now().Add(ttl)
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO sessions(id, user_id, token, user_agent, ip, expires_at, revoked, created_at)
		VALUES(?,?,?,?,?,?,0,?)
	`, id, userID, token, userAgent, ip, expires, time.Now())
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID:        id,
		UserID:    userID,
		Token:     token,
		ExpiresAt: expires,
		Revoked:   false,
		CreatedAt: time.Now(),
	}, nil
}

func (s *SessionStore) Validate(ctx context.Context, token string) (Session, error) {
	var sess Session
	row := s.DB.QueryRowContext(ctx, `
		SELECT id, user_id, token, expires_at, revoked, created_at
		FROM sessions WHERE token = ?
	`, token)
	var revoked int
	err := row.Scan(&sess.ID, &sess.UserID, &sess.Token, &sess.ExpiresAt, &revoked, &sess.CreatedAt)
	if err != nil {
		return Session{}, errors.New("invalid session")
	}
	if revoked != 0 || time.Now().After(sess.ExpiresAt) {
		return Session{}, errors.New("session expired or revoked")
	}
	// Verify token HMAC
	parts := strings.Split(sess.Token, ".")
	if len(parts) != 2 {
		return Session{}, errors.New("invalid session token format")
	}
	expected := s.signSessionToken(parts[0])
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) != 1 {
		return Session{}, errors.New("invalid session token signature")
	}
	return sess, nil
}

func (s *SessionStore) Revoke(ctx context.Context, token string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET revoked=1 WHERE token=?`, token)
	return err
}

func (s *SessionStore) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE sessions SET revoked=1 WHERE user_id=?`, userID)
	return err
}

func (s *SessionStore) generateSessionToken(sessionID, userID string) string {
	payload := sessionID + ":" + userID + ":" + fmt.Sprint(time.Now().UnixNano())
	sig := s.signSessionToken(payload)
	return payload + "." + sig
}

func (s *SessionStore) signSessionToken(payload string) string {
	h := hmac.New(sha512.New, s.hmacKey)
	h.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}
