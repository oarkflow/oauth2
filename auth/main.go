package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"database/sql"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
	
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/coreos/go-oidc"
	"github.com/golang-jwt/jwt/v5"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pquerna/otp/totp"
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

// --- Credential Store Interface ---

type CredentialStore interface {
	Authenticate(ctx context.Context, identifier, secret string) (userID string, err error)
}

// --- Credential Store Implementation (for all methods) ---

type SQLCredentialStore struct {
	DB *sql.DB
}

func (s *SQLCredentialStore) Authenticate(ctx context.Context, identifier, secret string) (string, error) {
	var (
		userID     string
		secretHash string
		typ        string
		provider   string
		metadata   sql.NullString
	)
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	row := s.DB.QueryRowContext(ctx, `
		SELECT user_id, secret_hash, type, provider, metadata FROM credentials
		WHERE identifier = ?
	`, identifier)
	err := row.Scan(&userID, &secretHash, &typ, &provider, &metadata)
	if err != nil {
		return "", errors.New("credential not found")
	}
	
	// Account lockout check
	if typ == "password" {
		failed, err := getFailedLogin(s.DB, identifier)
		if err == nil && failed.Count >= maxFailedAttempts && time.Since(failed.LockedAt) < lockoutDuration {
			return "", errors.New("account locked due to too many failed attempts")
		}
	}
	
	switch typ {
	case "password":
		if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)); err != nil {
			_ = recordFailedLogin(s.DB, identifier)
			// Exponential backoff
			failed, _ := getFailedLogin(s.DB, identifier)
			delay := backoffBase * time.Duration(1<<failed.Count)
			if delay > backoffMax {
				delay = backoffMax
			}
			time.Sleep(delay)
			return "", errors.New("unauthorized")
		}
		_ = resetFailedLogin(s.DB, identifier)
		// Password rotation enforcement
		rotate, _ := checkPasswordRotation(s.DB, identifier)
		if rotate {
			return "", errors.New("password rotation required")
		}
		return userID, nil
	case "apikey":
		keyHash := sha256.Sum256([]byte(secret))
		provided := base64.StdEncoding.EncodeToString(keyHash[:])
		if subtle.ConstantTimeCompare([]byte(secretHash), []byte(provided)) != 1 {
			return "", errors.New("unauthorized")
		}
		return userID, nil
	case "cognito":
		// metadata: {"region":"us-east-1","userPoolId":"...","clientId":"..."}
		var meta struct {
			Region     string `json:"region"`
			UserPoolId string `json:"userPoolId"`
			ClientId   string `json:"clientId"`
		}
		if err := json.Unmarshal([]byte(metadata.String), &meta); err != nil {
			return "", errors.New("invalid cognito metadata")
		}
		cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(meta.Region))
		if err != nil {
			return "", errors.New("aws config error")
		}
		cip := cognitoidentityprovider.NewFromConfig(cfg)
		// secret = id_token or access_token
		// Validate token using Cognito's JWKS
		providerURL := fmt.Sprintf("https://cognito-idp.%s.amazonaws.com/%s", meta.Region, meta.UserPoolId)
		verifier := oidc.NewVerifier(providerURL, oidc.NewRemoteKeySet(ctx, providerURL+"/.well-known/jwks.json"), &oidc.Config{ClientID: meta.ClientId})
		idToken, err := verifier.Verify(ctx, secret)
		if err != nil {
			return "", errors.New("invalid cognito token")
		}
		claims := struct{ Sub string }{}
		if err := idToken.Claims(&claims); err != nil {
			return "", errors.New("invalid cognito claims")
		}
		// Use cip to fetch user info from Cognito (using access token)
		getUserInput := &cognitoidentityprovider.GetUserInput{
			AccessToken: &secret,
		}
		_, err = cip.GetUser(ctx, getUserInput)
		if err != nil {
			return "", errors.New("cognito user fetch failed")
		}
		// Optionally, check claims.Sub matches identifier
		return userID, nil
	case "oauth2", "google", "clerk":
		// metadata: {"issuer":"...","clientId":"..."}
		var meta struct {
			Issuer   string `json:"issuer"`
			ClientId string `json:"clientId"`
		}
		if err := json.Unmarshal([]byte(metadata.String), &meta); err != nil {
			return "", errors.New("invalid oauth2 metadata")
		}
		provider, err := oidc.NewProvider(ctx, meta.Issuer)
		if err != nil {
			return "", errors.New("oidc provider error")
		}
		verifier := provider.Verifier(&oidc.Config{ClientID: meta.ClientId})
		idToken, err := verifier.Verify(ctx, secret)
		if err != nil {
			return "", errors.New("invalid oauth2 token")
		}
		claims := struct{ Sub string }{}
		if err := idToken.Claims(&claims); err != nil {
			return "", errors.New("invalid oauth2 claims")
		}
		// Optionally, check claims.Sub matches identifier
		return userID, nil
	case "totp":
		// metadata: {"secret":"BASE32SECRET"}
		var meta struct {
			Secret string `json:"secret"`
		}
		if err := json.Unmarshal([]byte(metadata.String), &meta); err != nil {
			return "", errors.New("invalid totp metadata")
		}
		if !totp.Validate(secret, meta.Secret) {
			return "", errors.New("invalid totp code")
		}
		return userID, nil
	case "mfa", "2fa":
		// metadata: {"type":"totp","secret":"..."} or {"type":"sms","code":"..."}
		var meta map[string]interface{}
		if err := json.Unmarshal([]byte(metadata.String), &meta); err != nil {
			return "", errors.New("invalid mfa metadata")
		}
		switch meta["type"] {
		case "totp":
			if !totp.Validate(secret, meta["secret"].(string)) {
				return "", errors.New("invalid mfa totp code")
			}
			return userID, nil
		case "sms":
			// For demo, compare code directly (in production, store hashed code)
			if meta["code"] != secret {
				return "", errors.New("invalid mfa sms code")
			}
			return userID, nil
		default:
			return "", errors.New("unsupported mfa type")
		}
	default:
		return "", errors.New("unsupported credential type")
	}
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
		identifier := r.Header.Get("X-Auth-Identifier")
		secret := r.Header.Get("X-Auth-Secret")
		if method == "" || identifier == "" || secret == "" {
			writeError(w, "missing auth method, identifier or secret", http.StatusBadRequest)
			return
		}
		res, err := auth.Authenticate(r.Context(), AuthRequest{
			Method:     method,
			Identifier: identifier,
			Secret:     secret,
			RemoteIP:   ip,
			UserAgent:  r.UserAgent(),
		})
		if err != nil {
			auditor.LogEvent("auth_failed", zap.String("reason", err.Error()), zap.String("ip", ip))
			writeError(w, err.Error(), http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(res)
	}
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

func LogoutHandler(auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractSessionToken(r)
		if token == "" {
			writeError(w, "missing session token", http.StatusUnauthorized)
			return
		}
		if err := auth.Sessions.Revoke(r.Context(), token); err != nil {
			writeError(w, "logout failed", http.StatusInternalServerError)
			return
		}
		// Clear session cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "session_token",
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			HttpOnly: true,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- Frontend HTTP Handlers for Password Management ---

func FrontendForgotPasswordHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		if r.Method == http.MethodPost {
			email := r.FormValue("email")
			if email == "" {
				data["Error"] = "Email required"
				_ = forgotTmpl.Execute(w, data)
				return
			}
			var userID string
			row := db.QueryRow(`SELECT id FROM users WHERE email=?`, email)
			if err := row.Scan(&userID); err != nil {
				data["Error"] = "User not found"
				_ = forgotTmpl.Execute(w, data)
				return
			}
			token, hash := generateResetToken()
			_, err := db.Exec(`INSERT INTO password_resets(user_id, token_hash, expires_at, used) VALUES(?,?,?,0)`,
				userID, hash, time.Now().Add(30*time.Minute))
			if err != nil {
				data["Error"] = "Could not create reset token"
				_ = forgotTmpl.Execute(w, data)
				return
			}
			// In production, send token via email. Here, just show it.
			data["ResetToken"] = token
		}
		_ = forgotTmpl.Execute(w, data)
	}
}

func FrontendResetPasswordHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		if r.Method == http.MethodPost {
			token := r.FormValue("token")
			password := r.FormValue("password")
			if token == "" || password == "" {
				data["Error"] = "Token and new password required"
				_ = resetTmpl.Execute(w, data)
				return
			}
			if err := validatePasswordPolicy(password); err != nil {
				data["Error"] = err.Error()
				_ = resetTmpl.Execute(w, data)
				return
			}
			hash := sha256.Sum256([]byte(token))
			var userID string
			var expires time.Time
			var used int
			row := db.QueryRow(`SELECT user_id, expires_at, used FROM password_resets WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
			if err := row.Scan(&userID, &expires, &used); err != nil || used != 0 || time.Now().After(expires) {
				data["Error"] = "Invalid or expired token"
				_ = resetTmpl.Execute(w, data)
				return
			}
			passHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			reused, _ := checkPasswordReuse(db, userID, string(passHash))
			if reused {
				data["Error"] = "Cannot reuse previous passwords"
				_ = resetTmpl.Execute(w, data)
				return
			}
			_, err := db.Exec(`UPDATE credentials SET secret_hash=? WHERE user_id=? AND type='password'`, string(passHash), userID)
			if err != nil {
				data["Error"] = "Could not update password"
				_ = resetTmpl.Execute(w, data)
				return
			}
			_, _ = db.Exec(`UPDATE password_resets SET used=1 WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
			_ = auth.Sessions.RevokeAllForUser(r.Context(), userID)
			_ = storePasswordHistory(db, userID, string(passHash))
			data["Success"] = true
		}
		_ = resetTmpl.Execute(w, data)
	}
}

func FrontendChangePasswordHandler(db *sql.DB, auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		var sessionToken string
		// Try to get session token from cookie
		if cookie, err := r.Cookie("session_token"); err == nil {
			sessionToken = cookie.Value
		}
		if r.Method == http.MethodPost {
			if sessionToken == "" {
				sessionToken = r.FormValue("session_token")
			}
			oldPassword := r.FormValue("old_password")
			newPassword := r.FormValue("new_password")
			if sessionToken == "" || oldPassword == "" || newPassword == "" {
				data["Error"] = "All fields required"
				_ = changeTmpl.Execute(w, data)
				return
			}
			if err := validatePasswordPolicy(newPassword); err != nil {
				data["Error"] = err.Error()
				_ = changeTmpl.Execute(w, data)
				return
			}
			sess, err := auth.Sessions.Validate(r.Context(), sessionToken)
			if err != nil {
				data["Error"] = "Invalid session"
				_ = changeTmpl.Execute(w, data)
				return
			}
			var secretHash string
			row := db.QueryRow(`SELECT secret_hash FROM credentials WHERE user_id=? AND type='password'`, sess.UserID)
			if err := row.Scan(&secretHash); err != nil {
				data["Error"] = "User not found"
				_ = changeTmpl.Execute(w, data)
				return
			}
			if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(oldPassword)); err != nil {
				data["Error"] = "Old password incorrect"
				_ = changeTmpl.Execute(w, data)
				return
			}
			passHash, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
			_, err = db.Exec(`UPDATE credentials SET secret_hash=? WHERE user_id=? AND type='password'`, string(passHash), sess.UserID)
			if err != nil {
				data["Error"] = "Could not update password"
				_ = changeTmpl.Execute(w, data)
				return
			}
			_ = auth.Sessions.RevokeAllForUser(r.Context(), sess.UserID)
			// Clear session cookie
			http.SetCookie(w, &http.Cookie{
				Name:     "session_token",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
			})
			data["Success"] = true
		}
		_ = changeTmpl.Execute(w, data)
	}
}

// --- Update FrontendHandler to set session cookie on login and clear on logout ---

func FrontendHandler(auth *Authenticator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{}
		// Pass CSRF token to template
		if token, ok := r.Context().Value("csrf_token").(string); ok {
			data["CSRFToken"] = token
		} else if cookie, err := r.Cookie("csrf_token"); err == nil {
			data["CSRFToken"] = cookie.Value
		}
		if r.Method == http.MethodPost {
			method := r.FormValue("method")
			var identifier, secret string
			switch method {
			case "password":
				identifier = r.FormValue("username")
				secret = r.FormValue("password")
			case "apikey":
				identifier = "k1"
				secret = r.FormValue("apikey")
			case "cognito", "oauth2", "google", "clerk":
				identifier = r.FormValue("username")
				secret = r.FormValue("token")
			case "totp":
				identifier = r.FormValue("username")
				secret = r.FormValue("totp")
			case "mfa", "2fa":
				identifier = r.FormValue("username")
				secret = r.FormValue("mfa")
			default:
				data["Error"] = "Unsupported method"
				_ = loginTmpl.Execute(w, data)
				return
			}
			res, err := auth.Authenticate(r.Context(), AuthRequest{
				Method:     method,
				Identifier: identifier,
				Secret:     secret,
				RemoteIP:   r.RemoteAddr,
				UserAgent:  r.UserAgent(),
			})
			if err != nil {
				data["Error"] = err.Error()
			} else {
				data["Token"] = res.Token
				// Split by '|'
				toks := strings.SplitN(res.Token, "|", 2)
				if len(toks) == 2 {
					data["SessionToken"] = toks[1]
					setSessionCookie(w, toks[1])
				}
			}
		}
		_ = loginTmpl.Execute(w, data)
	}
}

// --- Middleware for HTTP Timeout ---

func withTimeout(h http.Handler, timeout time.Duration) http.Handler {
	return http.TimeoutHandler(h, timeout, `{"error":"request timeout"}`)
}

// --- Provider Interface for Extensibility ---

type Provider interface {
	Authenticate(ctx context.Context, identifier, secret string, config map[string]interface{}) (string, error)
}

type ProviderRegistry struct {
	Providers map[string]Provider
}

func (r *ProviderRegistry) Get(name string) (Provider, error) {
	p, ok := r.Providers[name]
	if !ok {
		return nil, errors.New("unsupported provider")
	}
	return p, nil
}

// --- Example Provider Implementation (Password) ---

type PasswordProvider struct {
	DB *sql.DB
}

func (p *PasswordProvider) Authenticate(ctx context.Context, identifier, secret string, config map[string]interface{}) (string, error) {
	// Use prepared statement for security
	stmt, err := p.DB.PrepareContext(ctx, `
		SELECT user_id, secret_hash FROM credentials WHERE identifier=? AND type='password'
	`)
	if err != nil {
		return "", errors.New("db error")
	}
	defer stmt.Close()
	var userID, secretHash string
	err = stmt.QueryRow(identifier).Scan(&userID, &secretHash)
	if err != nil {
		return "", errors.New("credential not found")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)); err != nil {
		return "", errors.New("unauthorized")
	}
	return userID, nil
}

// --- Security Middleware ---

func securityMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Enforce HTTPS
		if r.TLS == nil {
			http.Redirect(w, r, "https://"+r.Host+r.RequestURI, http.StatusMovedPermanently)
			return
		}
		// Security headers
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		// CORS (restrict to allowed origins)
		w.Header().Set("Access-Control-Allow-Origin", "https://yourdomain.com")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "X-Auth-Method, X-Auth-Identifier, X-Auth-Secret, Content-Type")
		next.ServeHTTP(w, r)
	})
}

// --- CSRF Token Utilities ---

func generateCSRFToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- CSRF Protection Middleware (improved) ---

func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set CSRF cookie on GET requests
		if r.Method == http.MethodGet {
			token := generateCSRFToken()
			http.SetCookie(w, &http.Cookie{
				Name:     "csrf_token",
				Value:    token,
				Path:     "/",
				HttpOnly: false,
				Secure:   true,
				SameSite: http.SameSiteStrictMode,
				MaxAge:   3600,
			})
			// Also set in context for templates
			ctx := context.WithValue(r.Context(), "csrf_token", token)
			r = r.WithContext(ctx)
		}
		// Enforce CSRF only for browser forms (not for /auth API)
		if r.Method == http.MethodPost && !strings.HasPrefix(r.URL.Path, "/auth") {
			csrfToken := r.Header.Get("X-CSRF-Token")
			if csrfToken == "" {
				csrfToken = r.FormValue("csrf_token")
			}
			cookie, err := r.Cookie("csrf_token")
			if err != nil || csrfToken == "" || csrfToken != cookie.Value {
				log.Printf("CSRF token invalid: header/form=%q cookie=%q", csrfToken, func() string {
					if err == nil {
						return cookie.Value
					}
					return ""
				}())
				http.Error(w, "CSRF token invalid", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- Update loginTmpl to include CSRF token in form ---

var loginTmpl = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html>
<head>
	<title>Login</title>
	<style>
		body { font-family: sans-serif; background: #f7f7f7; }
		.form-box { background: #fff; padding: 2em; margin: 2em auto; max-width: 400px; border-radius: 8px; box-shadow: 0 2px 8px #ccc; }
		.error { color: #b00; }
		.token { word-break: break-all; background: #eee; padding: 0.5em; }
	</style>
	<script>
	function onProviderChange() {
		var method = document.getElementById('method').value;
		document.getElementById('username-row').style.display = (method === 'password') ? '' : 'none';
		document.getElementById('password-row').style.display = (method === 'password') ? '' : 'none';
		document.getElementById('apikey-row').style.display = (method === 'apikey') ? '' : 'none';
		document.getElementById('token-row').style.display = (['oauth2','google','clerk','cognito'].includes(method)) ? '' : 'none';
		document.getElementById('totp-row').style.display = (method === 'totp') ? '' : 'none';
		document.getElementById('mfa-row').style.display = (['mfa','2fa'].includes(method)) ? '' : 'none';
	}
	</script>
</head>
<body>
	<div class="form-box">
		<h2>Login</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .Token}}
			<div>Login successful! JWT:</div>
			<div class="token">{{.Token}}</div>
			<br>
			<form method="POST" action="/logout">
				<input type="hidden" name="session_token" value="{{.SessionToken}}">
				<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
				<button type="submit">Logout</button>
			</form>
			<br>
			<a href="/change-password">Change Password</a>
		{{else}}
		<form method="POST" autocomplete="off">
			<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
			<label for="method">Provider:</label>
			<select name="method" id="method" onchange="onProviderChange()">
				<option value="password">Password</option>
				<option value="apikey">API Key</option>
				<option value="cognito">AWS Cognito</option>
				<option value="oauth2">OAuth2 (Generic)</option>
				<option value="google">Google OAuth2</option>
				<option value="clerk">Clerk</option>
				<option value="totp">TOTP</option>
				<option value="mfa">MultiDevice MFA</option>
				<option value="2fa">2FA</option>
			</select>
			<div id="username-row">
				<label>Username: <input type="text" name="username" autocomplete="username"></label>
			</div>
			<div id="password-row">
				<label>Password: <input type="password" name="password" autocomplete="current-password"></label>
			</div>
			<div id="apikey-row" style="display:none">
				<label>API Key: <input type="text" name="apikey"></label>
			</div>
			<div id="token-row" style="display:none">
				<label>Token: <input type="text" name="token"></label>
			</div>
			<div id="totp-row" style="display:none">
				<label>TOTP Code: <input type="text" name="totp"></label>
			</div>
			<div id="mfa-row" style="display:none">
				<label>MFA/2FA Code: <input type="text" name="mfa"></label>
			</div>
			<br>
			<button type="submit">Login</button>
		</form>
		<a href="/forgot-password">Forgot Password?</a>
		<script>onProviderChange();</script>
		{{end}}
	</div>
</body>
</html>
`))

// Add templates for forgot/reset/change password
var forgotTmpl = template.Must(template.New("forgot").Parse(`
<!DOCTYPE html>
<html>
<head><title>Forgot Password</title></head>
<body>
	<div class="form-box">
		<h2>Forgot Password</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .ResetToken}}
			<div>Reset token (for demo): <span class="token">{{.ResetToken}}</span></div>
			<a href="/reset-password">Reset Password</a>
		{{else}}
		<form method="POST">
			<label>Email: <input type="email" name="email"></label>
			<button type="submit">Send Reset Link</button>
		</form>
		{{end}}
	</div>
</body>
</html>
`))

var resetTmpl = template.Must(template.New("reset").Parse(`
<!DOCTYPE html>
<html>
<head><title>Reset Password</title></head>
<body>
	<div class="form-box">
		<h2>Reset Password</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .Success}}
			<div>Password reset successful. <a href="/login">Login</a></div>
		{{else}}
		<form method="POST">
			<label>Reset Token: <input type="text" name="token"></label><br>
			<label>New Password: <input type="password" name="password"></label><br>
			<button type="submit">Reset Password</button>
		</form>
		{{end}}
	</div>
</body>
</html>
`))

var changeTmpl = template.Must(template.New("change").Parse(`
<!DOCTYPE html>
<html>
<head><title>Change Password</title></head>
<body>
	<div class="form-box">
		<h2>Change Password</h2>
		{{if .Error}}<div class="error">{{.Error}}</div>{{end}}
		{{if .Success}}
			<div>Password changed. Please <a href="/login">login</a> again.</div>
		{{else}}
		<form method="POST">
			<label>Session Token: <input type="text" name="session_token"></label><br>
			<label>Old Password: <input type="password" name="old_password"></label><br>
			<label>New Password: <input type="password" name="new_password"></label><br>
			<button type="submit">Change Password</button>
		</form>
		{{end}}
	</div>
</body>
</html>
`))

// --- Account Lockout & Exponential Backoff ---

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

// --- Refresh Token Endpoint Example ---

func RefreshTokenHandler(auth *Authenticator, db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			writeError(w, "missing refresh token", http.StatusBadRequest)
			return
		}
		userID, err := validateRefreshToken(db, refresh)
		if err != nil {
			writeError(w, "invalid refresh token", http.StatusUnauthorized)
			return
		}
		token, err := auth.Signer.Sign(userID)
		if err != nil {
			writeError(w, "token error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"token": token})
	}
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

// --- User Registration & Email Verification ---

func RegisterHandler(db *sql.DB, sendEmail func(to, subject, html string) error) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		username := r.FormValue("username")
		email := r.FormValue("email")
		password := r.FormValue("password")
		if username == "" || email == "" || password == "" {
			writeError(w, "missing fields", http.StatusBadRequest)
			return
		}
		if err := validatePasswordPolicy(password); err != nil {
			writeError(w, err.Error(), http.StatusBadRequest)
			return
		}
		passHash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		userID := generateUserID(username)
		_, err := db.Exec(`INSERT INTO users(id, username, email, email_verified, created_at, updated_at) VALUES(?,?,?,?,?,?)`,
			userID, username, email, 0, time.Now(), time.Now())
		if err != nil {
			writeError(w, "user exists", http.StatusConflict)
			return
		}
		_, err = db.Exec(`INSERT INTO credentials(id, user_id, type, provider, identifier, secret_hash, created_at)
			VALUES(?,?,?,?,?,?,?)`,
			"c-"+userID, userID, "password", "internal", username, string(passHash), time.Now())
		if err != nil {
			writeError(w, "credential error", http.StatusInternalServerError)
			return
		}
		// Email verification token
		token, hash := generateResetToken()
		_, _ = db.Exec(`INSERT INTO email_verifications(user_id, token_hash, expires_at, used) VALUES(?,?,?,0)`,
			userID, hash, time.Now().Add(24*time.Hour))
		// Send email (stub)
		_ = sendEmail(email, "Verify your account", fmt.Sprintf("Click to verify: https://yourdomain/verify-email?token=%s", token))
		w.WriteHeader(http.StatusCreated)
	}
}

func VerifyEmailHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			writeError(w, "missing token", http.StatusBadRequest)
			return
		}
		hash := sha256.Sum256([]byte(token))
		var userID string
		var expires time.Time
		var used int
		row := db.QueryRow(`SELECT user_id, expires_at, used FROM email_verifications WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
		if err := row.Scan(&userID, &expires, &used); err != nil || used != 0 || time.Now().After(expires) {
			writeError(w, "invalid or expired token", http.StatusBadRequest)
			return
		}
		_ = markEmailVerified(db, userID)
		_, _ = db.Exec(`UPDATE email_verifications SET used=1 WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
		w.Write([]byte("Email verified!"))
	}
}

// --- MFA Enrollment (TOTP) ---

func EnrollTOTPHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.FormValue("user_id")
		if userID == "" {
			writeError(w, "missing user_id", http.StatusBadRequest)
			return
		}
		secret := generateTOTPSecret() // stub, use otp.NewKey()
		_ = enrollTOTP(db, userID, secret)
		// Show QR code or secret to user (not implemented here)
		w.Write([]byte(fmt.Sprintf("TOTP secret: %s", secret)))
	}
}

// --- Password Reset via Email (SMTP/SES stub) ---

func sendEmailSMTP(to, subject, html string) error {
	// Integrate with SMTP/SES/SendGrid here
	return nil
}

// --- Session Concurrency & Device Management ---

func ListSessionsHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		userID := r.FormValue("user_id")
		rows, err := db.Query(`SELECT id, user_agent, ip, created_at, expires_at, revoked FROM sessions WHERE user_id=?`, userID)
		if err != nil {
			writeError(w, "db error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()
		var sessions []map[string]interface{}
		for rows.Next() {
			var id, ua, ip string
			var created, expires time.Time
			var revoked int
			_ = rows.Scan(&id, &ua, &ip, &created, &expires, &revoked)
			sessions = append(sessions, map[string]interface{}{
				"id": id, "user_agent": ua, "ip": ip, "created_at": created, "expires_at": expires, "revoked": revoked != 0,
			})
		}
		_ = json.NewEncoder(w).Encode(sessions)
	}
}

func RevokeSessionHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sessionID := r.FormValue("session_id")
		_, err := db.Exec(`UPDATE sessions SET revoked=1 WHERE id=?`, sessionID)
		if err != nil {
			writeError(w, "db error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
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
