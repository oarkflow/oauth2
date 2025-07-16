package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// --- Interfaces and Models ---

type AuthRequest struct {
	Method     string
	Identifier string
	Secret     string
	RemoteIP   string
	UserAgent  string
}

type AuthResult struct {
	UserID string `json:"user"`
	Token  string `json:"token"`
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
	pubASN1 := x509.MarshalPKCS1PublicKey(&key.PublicKey)
	hash := sha256.Sum256(pubASN1)
	return base64.RawURLEncoding.EncodeToString(hash[:8])
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

// --- JWT Signer with Roles/Scopes ---

func (j *JWTSigner) SignWithClaims(userID string, roles []UserRole, scopes []string) (string, error) {
	j.mu.RLock()
	defer j.mu.RUnlock()
	claims := jwt.MapClaims{
		"sub":    userID,
		"roles":  roles,
		"scopes": scopes,
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = j.KeyID
	return token.SignedString(j.PrivateKey)
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

func generateRandomString(n int) (string, error) {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b), nil
}

// --- Password Reset Token Management ---

func generateResetToken() (string, string) {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, base64.StdEncoding.EncodeToString(hash[:])
}

// --- Authenticator (add session support) ---

type Authenticator struct {
	Credentials *CredentialRegistry
	Signer      *JWTSigner
	Auditor     *AuditLogger
	Sessions    *SessionStore
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
	userID, err := store.Authenticate(ctx, req.Identifier, req.Secret)
	if err != nil {
		a.Auditor.LogEvent("auth_failed", zap.String("reason", err.Error()))
		return AuthResult{}, err
	}
	token, err := a.Signer.Sign(userID)
	if err != nil {
		a.Auditor.LogEvent("auth_failed", zap.String("reason", "token_sign_error"))
		return AuthResult{}, errors.New("token error")
	}
	// --- Create session ---
	sess, err := a.Sessions.Create(ctx, userID, req.UserAgent, req.RemoteIP, 24*time.Hour)
	if err != nil {
		a.Auditor.LogEvent("session_create_failed", zap.String("user", userID))
		return AuthResult{}, errors.New("session error")
	}
	a.Auditor.LogEvent("auth_success", zap.String("user", userID))
	return AuthResult{UserID: userID, Token: token + "|" + sess.Token}, nil
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

func writeError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// --- HTTP Handlers for Session and Password Management ---

func extractSessionToken(r *http.Request) string {
	// Try Authorization: Bearer <token> or Cookie: session_token
	authz := r.Header.Get("Authorization")
	if strings.HasPrefix(authz, "Bearer ") {
		parts := strings.SplitN(authz, " ", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	cookie, err := r.Cookie("session_token")
	if err == nil {
		return cookie.Value
	}
	return ""
}

// --- Middleware for HTTP Timeout ---

func withTimeout(h http.Handler, timeout time.Duration) http.Handler {
	return http.TimeoutHandler(h, timeout, `{"error":"request timeout"}`)
}

// --- CSRF Token Utilities ---

func generateCSRFToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type FailedLogin struct {
	UserID    string
	Count     int
	LockedAt  time.Time
	UpdatedAt time.Time
}

const (
	maxFailedAttempts      = 5
	lockoutDuration        = 15 * time.Minute
	backoffBase            = 2 * time.Second
	backoffMax             = 30 * time.Second
	passwordHistoryLength  = 5
	passwordRotationPeriod = 90 * 24 * time.Hour // 90 days
)

func recordFailedLogin(db *sql.DB, userID string) error {
	_, err := db.Exec(`
		INSERT INTO failed_logins(user_id, count, locked_at, updated_at)
		VALUES(?,?,?,?)
		ON CONFLICT(user_id) DO UPDATE SET
			count = count + 1,
			updated_at = CURRENT_TIMESTAMP,
			locked_at = CASE WHEN count+1 >= ? THEN CURRENT_TIMESTAMP ELSE locked_at END
	`, userID, 1, nil, time.Now(), maxFailedAttempts)
	return err
}

func resetFailedLogin(db *sql.DB, userID string) error {
	_, err := db.Exec(`DELETE FROM failed_logins WHERE user_id=?`, userID)
	return err
}

func getFailedLogin(db *sql.DB, userID string) (FailedLogin, error) {
	var f FailedLogin
	row := db.QueryRow(`SELECT user_id, count, locked_at, updated_at FROM failed_logins WHERE user_id=?`, userID)
	err := row.Scan(&f.UserID, &f.Count, &f.LockedAt, &f.UpdatedAt)
	return f, err
}

// --- Password History & Rotation ---

func storePasswordHistory(db *sql.DB, userID, hash string) error {
	_, err := db.Exec(`INSERT INTO password_history(user_id, hash, created_at) VALUES(?,?,?)`, userID, hash, time.Now())
	if err != nil {
		return err
	}
	_, _ = db.Exec(`
		DELETE FROM password_history
		WHERE user_id=? AND rowid NOT IN (
			SELECT rowid FROM password_history WHERE user_id=? ORDER BY created_at DESC LIMIT ?
		)
	`, userID, userID, passwordHistoryLength)
	return nil
}

func checkPasswordReuse(db *sql.DB, userID, newHash string) (bool, error) {
	rows, err := db.Query(`SELECT hash FROM password_history WHERE user_id=? ORDER BY created_at DESC LIMIT ?`, userID, passwordHistoryLength)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var oldHash string
		if err := rows.Scan(&oldHash); err == nil {
			if bcrypt.CompareHashAndPassword([]byte(oldHash), []byte(newHash)) == nil {
				return true, nil
			}
		}
	}
	return false, nil
}

func checkPasswordRotation(db *sql.DB, userID string) (bool, error) {
	var lastChanged time.Time
	row := db.QueryRow(`SELECT MAX(created_at) FROM password_history WHERE user_id=?`, userID)
	if err := row.Scan(&lastChanged); err != nil {
		return false, err
	}
	return time.Since(lastChanged) > passwordRotationPeriod, nil
}

// --- Email Verification & MFA Enrollment ---

func markEmailVerified(db *sql.DB, userID string) error {
	_, err := db.Exec(`UPDATE users SET email_verified=1 WHERE id=?`, userID)
	return err
}

func isEmailVerified(db *sql.DB, userID string) (bool, error) {
	var verified int
	row := db.QueryRow(`SELECT email_verified FROM users WHERE id=?`, userID)
	if err := row.Scan(&verified); err != nil {
		return false, err
	}
	return verified == 1, nil
}

func enrollTOTP(db *sql.DB, userID, secret string) error {
	_, err := db.Exec(`INSERT INTO credentials(id, user_id, type, provider, identifier, secret_hash, metadata, created_at)
		VALUES(?,?,?,?,?,?,?,?)`,
		"totp-"+userID, userID, "totp", "internal", userID, "", `{"secret":"`+secret+`"}`, time.Now())
	return err
}

// --- Refresh Tokens & Revocation ---

type RefreshToken struct {
	ID        string
	UserID    string
	Token     string
	ExpiresAt time.Time
	Revoked   bool
	CreatedAt time.Time
}

func generateRefreshToken() (string, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(token))
	return token, base64.StdEncoding.EncodeToString(hash[:]), nil
}

func storeRefreshToken(db *sql.DB, userID, tokenHash string, expires time.Time) error {
	_, err := db.Exec(`INSERT INTO refresh_tokens(user_id, token_hash, expires_at, revoked, created_at) VALUES(?,?,?,?,?)`,
		userID, tokenHash, expires, 0, time.Now())
	return err
}

func revokeRefreshToken(db *sql.DB, tokenHash string) error {
	_, err := db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?`, tokenHash)
	return err
}

func validateRefreshToken(db *sql.DB, token string) (string, error) {
	hash := sha256.Sum256([]byte(token))
	var userID string
	var expires time.Time
	var revoked int
	row := db.QueryRow(`SELECT user_id, expires_at, revoked FROM refresh_tokens WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
	if err := row.Scan(&userID, &expires, &revoked); err != nil || revoked != 0 || time.Now().After(expires) {
		return "", errors.New("invalid or expired refresh token")
	}
	return userID, nil
}

// --- Secure Cookie Attributes ---

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		// Domain: "yourdomain.com", // Set if needed
		MaxAge: 86400,
	})
}

// --- RBAC & Scopes ---

type UserRole string

const (
	RoleUser  UserRole = "user"
	RoleAdmin UserRole = "admin"
	// ...add more as needed
)

type User struct {
	ID            string
	Username      string
	Email         string
	EmailVerified bool
	Roles         []UserRole
	// ...existing fields...
}

// --- Password Reset via Email (SMTP/SES stub) ---

func sendEmailSMTP(to, subject, html string) error {
	// Integrate with SMTP/SES/SendGrid here
	return nil
}

// --- Audit Trail: Async Logging (stub, replace with ELK/CloudWatch/other) ---

type AuditEvent struct {
	Event  string
	Fields []zap.Field
	Time   time.Time
}

type AsyncAuditLogger struct {
	ch chan AuditEvent
}

func NewAsyncAuditLogger() *AsyncAuditLogger {
	return &AsyncAuditLogger{ch: make(chan AuditEvent, 1000)}
}

func (a *AsyncAuditLogger) LogEvent(event string, fields ...zap.Field) {
	a.ch <- AuditEvent{Event: event, Fields: fields, Time: time.Now()}
}

// --- Distributed Rate Limiting (stub, use Redis or Envoy) ---

type DistributedRateLimiter struct {
	// Use Redis or external service
}

func (r *DistributedRateLimiter) Allow(ip string) bool {
	// Implement Redis-based rate limiting here
	return true
}

// --- OIDC/JWK Caching (stub) ---

type CachedKeySet struct {
	ks    oidc.KeySet
	exp   time.Time
	mutex sync.Mutex
}

func NewCachedKeySet(issuer string) *CachedKeySet {
	return &CachedKeySet{}
}

func (c *CachedKeySet) Verify(ctx context.Context, token string) (*oidc.IDToken, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if time.Now().After(c.exp) {
		// Fetch and cache new keys, set c.exp from Cache-Control header
	}
	return nil, nil // implement actual verification
}

// --- DB Connection Pooling & Prepared Statements ---

func setupDB(dsn string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(1 * time.Hour)
	// Prepare statements here and store in struct for reuse
	return db, nil
}

func generateTOTPSecret() string {
	// Generates a random 20-byte base32 secret for TOTP
	secret := make([]byte, 20)
	if _, err := rand.Read(secret); err != nil {
		return ""
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
}

func generateUserID(username string) string {
	// Generates a unique user ID based on username and current time
	h := sha256.New()
	h.Write([]byte(username))
	h.Write([]byte(fmt.Sprint(time.Now().UnixNano())))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))[:16]
}

func main() {
	logger, _ := zap.NewProduction()
	defer func() {
		_ = logger.Sync()
	}()
	auditor := &AuditLogger{logger}

	signer, err := NewJWTSigner()
	if err != nil {
		log.Fatalf("JWT signer error: %v", err)
	}

	db, err := setupDB("store.db")
	if err != nil {
		log.Fatalf("DB open error: %v", err)
	}
	defer db.Close()
	setupSchema(db)
	// Setup credential registry for extensibility
	credentialRegistry := &CredentialRegistry{
		Stores: map[string]CredentialStore{
			"password": &SQLCredentialStore{DB: db},
			"apikey":   &SQLCredentialStore{DB: db},
			"cognito":  &SQLCredentialStore{DB: db},
			"oauth2":   &SQLCredentialStore{DB: db},
			"google":   &SQLCredentialStore{DB: db},
			"clerk":    &SQLCredentialStore{DB: db},
			"totp":     &SQLCredentialStore{DB: db},
			"mfa":      &SQLCredentialStore{DB: db},
			"2fa":      &SQLCredentialStore{DB: db},
		},
	}

	// Secure HMAC key for sessions
	hmacKey := make([]byte, 64)
	if _, err := rand.Read(hmacKey); err != nil {
		log.Fatalf("HMAC key gen error: %v", err)
	}
	sessionStore := NewSessionStore(db, hmacKey)

	auth := &Authenticator{
		Credentials: credentialRegistry,
		Signer:      signer,
		Auditor:     auditor,
		Sessions:    sessionStore,
	}

	limiter := newRateLimiter(10, 1*time.Minute)

	// Secure endpoints with middleware
	http.Handle("/auth", securityMiddleware(csrfMiddleware(withTimeout(AuthHandler(auth, auditor, limiter), 10*time.Second))))
	http.Handle("/login", securityMiddleware(csrfMiddleware(withTimeout(FrontendHandler(auth), 10*time.Second))))
	http.Handle("/logout", securityMiddleware(csrfMiddleware(withTimeout(LogoutHandler(auth), 10*time.Second))))
	http.Handle("/forgot-password", securityMiddleware(csrfMiddleware(withTimeout(FrontendForgotPasswordHandler(db), 10*time.Second))))
	http.Handle("/reset-password", securityMiddleware(csrfMiddleware(withTimeout(FrontendResetPasswordHandler(db, auth), 10*time.Second))))
	http.Handle("/change-password", securityMiddleware(csrfMiddleware(withTimeout(FrontendChangePasswordHandler(db, auth), 10*time.Second))))
	http.Handle("/register", securityMiddleware(csrfMiddleware(withTimeout(RegisterHandler(db, sendEmailSMTP), 10*time.Second))))
	http.Handle("/verify-email", securityMiddleware(csrfMiddleware(withTimeout(VerifyEmailHandler(db), 10*time.Second))))
	http.Handle("/enroll-totp", securityMiddleware(csrfMiddleware(withTimeout(EnrollTOTPHandler(db), 10*time.Second))))
	http.Handle("/sessions", securityMiddleware(csrfMiddleware(withTimeout(ListSessionsHandler(db), 10*time.Second))))
	http.Handle("/revoke-session", securityMiddleware(csrfMiddleware(withTimeout(RevokeSessionHandler(db), 10*time.Second))))
	logger.Info("Starting server", zap.String("addr", ":8080"))
	if _, err := os.Stat("server.crt"); os.IsNotExist(err) {
		log.Println("TLS certificate 'server.crt' not found. Generate with:")
		log.Println("  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
	}
	if _, err := os.Stat("server.key"); os.IsNotExist(err) {
		log.Println("TLS key 'server.key' not found. Generate with:")
		log.Println("  openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -nodes -subj '/CN=localhost'")
	}
	log.Fatal(http.ListenAndServeTLS(":8080", "server.crt", "server.key", nil))
}
