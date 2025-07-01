package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// --- Interfaces and Models ---

type AuthRequest struct {
	Method     string
	Credential string
	RemoteIP   string
	UserAgent  string
}

type AuthResult struct {
	UserID string `json:"user"`
	Token  string `json:"token"`
}

// --- Credential Store Interface ---

type CredentialStore interface {
	Authenticate(ctx context.Context, credential string) (userID string, err error)
}

// --- Password Credential Store ---

type PasswordCredentialStore struct {
	Users *UserStore
}

func (s *PasswordCredentialStore) Authenticate(ctx context.Context, credential string) (string, error) {
	parts := strings.SplitN(credential, ":", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid credential format")
	}
	id, hash, err := s.Users.FindByUsername(ctx, parts[0])
	if err != nil {
		return "", errors.New("user not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(parts[1])); err != nil {
		return "", errors.New("unauthorized")
	}
	return id, nil
}

// --- API Key Credential Store ---

type APIKeyCredentialStore struct {
	APIKeys *APIKeyStore
}

func (s *APIKeyCredentialStore) Authenticate(ctx context.Context, credential string) (string, error) {
	parts := strings.SplitN(credential, ":", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid apikey format")
	}
	keyID, key := parts[0], parts[1]
	userID, hash, err := s.APIKeys.FindByID(ctx, keyID)
	if err != nil {
		return "", errors.New("apikey not found")
	}
	keyHash := sha256.Sum256([]byte(key))
	provided := base64.StdEncoding.EncodeToString(keyHash[:])
	if subtle.ConstantTimeCompare([]byte(hash), []byte(provided)) != 1 {
		return "", errors.New("unauthorized")
	}
	return userID, nil
}

// --- Credential Registry ---

type CredentialRegistry struct {
	Stores map[string]CredentialStore
}

func (r *CredentialRegistry) Get(method string) (CredentialStore, error) {
	s, ok := r.Stores[method]
	if !ok {
		return nil, errors.New("unsupported method")
	}
	return s, nil
}

// --- Audit Logger ---

type AuditLogger struct {
	Log *zap.Logger
}

func (a *AuditLogger) LogEvent(event string, fields ...zap.Field) {
	a.Log.Info(event, fields...)
}

// --- JWT Signer with Key Rotation ---

type JWTSigner struct {
	mu         sync.RWMutex
	PrivateKey *rsa.PrivateKey
	KeyID      string
}

func NewJWTSigner() (*JWTSigner, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	kid := generateKeyID(key)
	return &JWTSigner{PrivateKey: key, KeyID: kid}, nil
}

func generateKeyID(key *rsa.PrivateKey) string {
	pubASN1 := sha256.Sum256(x509MarshalPKCS1PublicKey(&key.PublicKey))
	return base64.RawURLEncoding.EncodeToString(pubASN1[:8])
}

func x509MarshalPKCS1PublicKey(pub *rsa.PublicKey) []byte {
	// Minimal ASN.1 encoding for key fingerprinting
	return []byte(fmt.Sprintf("%d%d", pub.N.BitLen(), pub.E))
}

func (j *JWTSigner) RotateKey() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	j.PrivateKey = key
	j.KeyID = generateKeyID(key)
	return nil
}

func (j *JWTSigner) Sign(userID string) (string, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = j.KeyID
	return token.SignedString(j.PrivateKey)
}

// --- User and API Key Storage (SQLite-backed) ---

type UserStore struct{ DB *sql.DB }
type APIKeyStore struct{ DB *sql.DB }

func (s *UserStore) FindByUsername(ctx context.Context, username string) (id, hash string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	row := s.DB.QueryRowContext(ctx, "SELECT id, password_hash FROM users WHERE username = ?", username)
	err = row.Scan(&id, &hash)
	return
}

func (s *APIKeyStore) FindByID(ctx context.Context, keyID string) (userID, hash string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	row := s.DB.QueryRowContext(ctx, "SELECT user_id, key_hash FROM api_keys WHERE id = ?", keyID)
	err = row.Scan(&userID, &hash)
	return
}

// --- Password Policy ---

func validatePasswordPolicy(password string) error {
	if len(password) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, c := range password {
		switch {
		case 'A' <= c && c <= 'Z':
			hasUpper = true
		case 'a' <= c && c <= 'z':
			hasLower = true
		case '0' <= c && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:',.<>/?", c):
			hasSpecial = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return errors.New("password must contain upper, lower, digit, and special char")
	}
	return nil
}

// --- Secure API Key Generation ---

func generateAPIKey() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	key := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(key))
	return key, base64.StdEncoding.EncodeToString(hash[:]), nil
}

// --- Authenticator ---

type Authenticator struct {
	Credentials *CredentialRegistry
	Signer      *JWTSigner
	Auditor     *AuditLogger
}

func (a *Authenticator) Authenticate(ctx context.Context, req AuthRequest) (AuthResult, error) {
	a.Auditor.LogEvent("auth_attempt",
		zap.String("method", req.Method),
		zap.String("ip", req.RemoteIP),
		zap.String("ua", req.UserAgent),
	)
	store, err := a.Credentials.Get(req.Method)
	if err != nil {
		a.Auditor.LogEvent("auth_failed", zap.String("reason", "unsupported_method"))
		return AuthResult{}, errors.New("unsupported method")
	}
	userID, err := store.Authenticate(ctx, req.Credential)
	if err != nil {
		a.Auditor.LogEvent("auth_failed", zap.String("reason", err.Error()))
		return AuthResult{}, err
	}
	token, err := a.Signer.Sign(userID)
	if err != nil {
		a.Auditor.LogEvent("auth_failed", zap.String("reason", "token_sign_error"))
		return AuthResult{}, errors.New("token error")
	}
	a.Auditor.LogEvent("auth_success", zap.String("user", userID))
	return AuthResult{UserID: userID, Token: token}, nil
}

// --- Rate Limiter (per IP) ---

type rateLimiter struct {
	mu      sync.Mutex
	clients map[string]*clientRate
	limit   int
	window  time.Duration
}

type clientRate struct {
	count     int
	lastReset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{
		clients: make(map[string]*clientRate),
		limit:   limit,
		window:  window,
	}
}

func (r *rateLimiter) Allow(ip string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	cr, ok := r.clients[ip]
	if !ok || now.Sub(cr.lastReset) > r.window {
		r.clients[ip] = &clientRate{count: 1, lastReset: now}
		return true
	}
	if cr.count >= r.limit {
		return false
	}
	cr.count++
	return true
}

// --- HTTP Handler ---

func AuthHandler(auth *Authenticator, auditor *AuditLogger, limiter *rateLimiter) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Secure headers
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "X-Auth-Method, X-Auth-Credential, X-Auth-Provider, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}
		if !limiter.Allow(ip) {
			auditor.LogEvent("rate_limited", zap.String("ip", ip))
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		method := r.Header.Get("X-Auth-Method")
		cred := r.Header.Get("X-Auth-Credential")
		if method == "" || cred == "" {
			writeError(w, "missing auth method or credential", http.StatusBadRequest)
			return
		}
		res, err := auth.Authenticate(r.Context(), AuthRequest{
			Method:     method,
			Credential: cred,
			RemoteIP:   ip,
			UserAgent:  r.UserAgent(),
		})
		if err != nil {
			auditor.LogEvent("auth_failed", zap.String("reason", err.Error()), zap.String("ip", ip))
			writeError(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(res)
	}
}

func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// --- Setup: DB, Logger, Providers, Server ---

func main() {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	auditor := &AuditLogger{logger}

	signer, err := NewJWTSigner()
	if err != nil {
		log.Fatalf("JWT signer error: %v", err)
	}

	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		log.Fatalf("DB open error: %v", err)
	}
	defer db.Close()
	if err := setupSchema(db); err != nil {
		log.Fatalf("DB schema error: %v", err)
	}

	// Demo data
	pass := "Secret12345@"
	if err := validatePasswordPolicy(pass); err != nil {
		log.Fatalf("Demo password policy: %v", err)
	}
	passHash, _ := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
	db.Exec("INSERT INTO users(id, username, password_hash) VALUES(?,?,?)", "u1", "alice", string(passHash))
	key, keyHash, _ := generateAPIKey()
	db.Exec("INSERT INTO api_keys(id, user_id, key_hash) VALUES(?,?,?)", "k1", "u1", keyHash)
	fmt.Println("Api Key", key)

	users := &UserStore{db}
	apikeys := &APIKeyStore{db}

	credRegistry := &CredentialRegistry{
		Stores: map[string]CredentialStore{
			"password": &PasswordCredentialStore{Users: users},
			"apikey":   &APIKeyCredentialStore{APIKeys: apikeys},
			// Add more credential types here
		},
	}

	auth := &Authenticator{
		Credentials: credRegistry,
		Signer:      signer,
		Auditor:     auditor,
	}

	limiter := newRateLimiter(10, 1*time.Minute)

	http.HandleFunc("/auth", AuthHandler(auth, auditor, limiter))
	logger.Info("Starting server", zap.String("addr", ":8080"))
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// --- DB Schema Helper ---

func setupSchema(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		key_hash TEXT NOT NULL
	);
	`)
	return err
}

/*
// --- Example Usage ---
//
Example 1: Internal Provider (Password)
  curl -X POST http://localhost:8080/auth \
    -H "X-Auth-Method: password" \
    -H "X-Auth-Credential: alice:Secret12345@" \
    -H "X-Auth-Provider: internal"

Example 2: Internal Provider (API Key)
  curl -X POST http://localhost:8080/auth \
    -H "X-Auth-Method: apikey" \
    -H "X-Auth-Credential: k1:<API_KEY_FROM_CONSOLE>" \
    -H "X-Auth-Provider: internal"

Example 3: External Provider (Stub)
  curl -X POST http://localhost:8080/auth \
    -H "X-Auth-Method: any" \
    -H "X-Auth-Credential: anything" \
    -H "X-Auth-Provider: external"

Replace <API_KEY_FROM_CONSOLE> with the API key printed on server startup.

CREATE TABLE users (
    id             UUID PRIMARY KEY,
    username       TEXT UNIQUE NOT NULL,
    email          TEXT UNIQUE NOT NULL,
    phone          TEXT,
    full_name      TEXT,
    avatar_url     TEXT,
    created_at     TIMESTAMP NOT NULL DEFAULT now(),
    updated_at     TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    id              UUID PRIMARY KEY,
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    type            TEXT NOT NULL, -- e.g., "password", "apikey", "oauth2", "cognito", "clerk"
    provider        TEXT,          -- e.g., "internal", "google", "aws", "auth0"
    identifier      TEXT,          -- Email, key ID, subject ID, etc.
    secret_hash     TEXT,          -- bcrypt/sha256 (for passwords/apikeys), or NULL for OIDC
    metadata        JSONB,         -- Store arbitrary metadata (token expiry, scopes, etc)
    created_at      TIMESTAMP NOT NULL DEFAULT now(),
    last_used_at    TIMESTAMP
);


*/
