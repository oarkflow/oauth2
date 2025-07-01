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
	Provider   string
	RemoteIP   string
	UserAgent  string
}

type AuthResult struct {
	UserID string `json:"user"`
	Token  string `json:"token"`
}

type AuthProvider interface {
	Authenticate(ctx context.Context, req AuthRequest) (AuthResult, error)
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

// --- Internal Provider (Password, API Key) ---

type InternalProvider struct {
	Users   *UserStore
	APIKeys *APIKeyStore
	Signer  *JWTSigner
	Auditor *AuditLogger
}

func (p *InternalProvider) Authenticate(ctx context.Context, req AuthRequest) (AuthResult, error) {
	p.Auditor.LogEvent("auth_attempt",
		zap.String("method", req.Method),
		zap.String("ip", req.RemoteIP),
		zap.String("ua", req.UserAgent),
	)
	switch req.Method {
	case "password":
		parts := strings.SplitN(req.Credential, ":", 2)
		if len(parts) != 2 {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "invalid_credential_format"))
			return AuthResult{}, errors.New("invalid credential format")
		}
		id, hash, err := p.Users.FindByUsername(ctx, parts[0])
		if err != nil {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "user_not_found"))
			return AuthResult{}, errors.New("user not found")
		}
		if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(parts[1])); err != nil {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "wrong_password"))
			return AuthResult{}, errors.New("unauthorized")
		}
		token, err := p.Signer.Sign(id)
		if err != nil {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "token_sign_error"))
			return AuthResult{}, errors.New("token error")
		}
		p.Auditor.LogEvent("auth_success", zap.String("user", id))
		return AuthResult{UserID: id, Token: token}, nil

	case "apikey":
		parts := strings.SplitN(req.Credential, ":", 2)
		if len(parts) != 2 {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "invalid_apikey_format"))
			return AuthResult{}, errors.New("invalid apikey format")
		}
		keyID, key := parts[0], parts[1]
		userID, hash, err := p.APIKeys.FindByID(ctx, keyID)
		if err != nil {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "apikey_not_found"))
			return AuthResult{}, errors.New("apikey not found")
		}
		keyHash := sha256.Sum256([]byte(key))
		provided := base64.StdEncoding.EncodeToString(keyHash[:])
		if subtle.ConstantTimeCompare([]byte(hash), []byte(provided)) != 1 {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "apikey_wrong"))
			return AuthResult{}, errors.New("unauthorized")
		}
		token, err := p.Signer.Sign(userID)
		if err != nil {
			p.Auditor.LogEvent("auth_failed", zap.String("reason", "token_sign_error"))
			return AuthResult{}, errors.New("token error")
		}
		p.Auditor.LogEvent("auth_success", zap.String("user", userID))
		return AuthResult{UserID: userID, Token: token}, nil

	default:
		p.Auditor.LogEvent("auth_failed", zap.String("reason", "unsupported_method"))
		return AuthResult{}, errors.New("unsupported method")
	}
}

// --- External Provider Example (Stub) ---

type ExternalProvider struct {
	Name    string
	Auditor *AuditLogger
	// Add config/clients as needed
}

func (e *ExternalProvider) Authenticate(ctx context.Context, req AuthRequest) (AuthResult, error) {
	e.Auditor.LogEvent("auth_attempt_external",
		zap.String("provider", e.Name),
		zap.String("ip", req.RemoteIP),
		zap.String("ua", req.UserAgent),
	)
	// Implement actual external provider logic here
	return AuthResult{}, errors.New("external provider not implemented")
}

// --- Provider Registry ---

type ProviderRegistry struct {
	Providers map[string]AuthProvider
}

func (r *ProviderRegistry) Get(name string) (AuthProvider, error) {
	prov, ok := r.Providers[name]
	if !ok {
		return nil, errors.New("provider not found")
	}
	return prov, nil
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

func AuthHandler(registry *ProviderRegistry, auditor *AuditLogger, limiter *rateLimiter) http.HandlerFunc {
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
		providerName := r.Header.Get("X-Auth-Provider")
		if providerName == "" {
			providerName = "internal"
		}
		provider, err := registry.Get(providerName)
		if err != nil {
			auditor.LogEvent("auth_failed", zap.String("reason", "provider_not_found"), zap.String("ip", ip))
			writeError(w, "provider not found", http.StatusBadRequest)
			return
		}
		res, err := provider.Authenticate(r.Context(), AuthRequest{
			Method:     method,
			Credential: cred,
			Provider:   providerName,
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
	pass := "Secret1234!@"
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
	internal := &InternalProvider{Users: users, APIKeys: apikeys, Signer: signer, Auditor: auditor}
	external := &ExternalProvider{Name: "external", Auditor: auditor}

	registry := &ProviderRegistry{
		Providers: map[string]AuthProvider{
			"internal": internal,
			"external": external,
			// Add more providers here
		},
	}

	limiter := newRateLimiter(10, 1*time.Minute)

	http.HandleFunc("/auth", AuthHandler(registry, auditor, limiter))
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
