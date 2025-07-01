package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	mathRand "math/rand"
	"net"
	"net/http"
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

// --- Credential Store Implementation (for all methods) ---

type SQLCredentialStore struct {
	DB *sql.DB
}

func (s *SQLCredentialStore) Authenticate(ctx context.Context, credential string) (string, error) {
	parts := strings.SplitN(credential, ":", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid credential format")
	}
	identifier, secret := parts[0], parts[1]

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

	switch typ {
	case "password":
		if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)); err != nil {
			return "", errors.New("unauthorized")
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
	DB *sql.DB
}

func (s *SessionStore) Create(ctx context.Context, userID, userAgent, ip string, ttl time.Duration) (Session, error) {
	id := generateRandomString(32)
	token := generateSessionToken(id, userID)
	expires := time.Now().Add(ttl)
	_, err := s.DB.ExecContext(ctx, `
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

func generateSessionToken(sessionID, userID string) string {
	// HMAC-based token, not guessable
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	h := hmac.New(sha512.New, secret)
	h.Write([]byte(sessionID + ":" + userID + ":" + fmt.Sprint(time.Now().UnixNano())))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[mathRand.Intn(len(letters))]
	}
	return string(b)
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
			_, err := db.Exec(`UPDATE credentials SET secret_hash=? WHERE user_id=? AND type='password'`, string(passHash), userID)
			if err != nil {
				data["Error"] = "Could not update password"
				_ = resetTmpl.Execute(w, data)
				return
			}
			_, _ = db.Exec(`UPDATE password_resets SET used=1 WHERE token_hash=?`, base64.StdEncoding.EncodeToString(hash[:]))
			_ = auth.Sessions.RevokeAllForUser(r.Context(), userID)
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
		if r.Method == http.MethodPost {
			method := r.FormValue("method")
			var credential string
			switch method {
			case "password":
				credential = r.FormValue("username") + ":" + r.FormValue("password")
			case "apikey":
				credential = "k1:" + r.FormValue("apikey")
			case "cognito", "oauth2", "google", "clerk":
				credential = r.FormValue("username") + ":" + r.FormValue("token")
			case "totp":
				credential = r.FormValue("username") + ":" + r.FormValue("totp")
			case "mfa", "2fa":
				credential = r.FormValue("username") + ":" + r.FormValue("mfa")
			default:
				data["Error"] = "Unsupported method"
				_ = loginTmpl.Execute(w, data)
				return
			}
			res, err := auth.Authenticate(r.Context(), AuthRequest{
				Method:     method,
				Credential: credential,
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
					// Set session cookie
					http.SetCookie(w, &http.Cookie{
						Name:     "session_token",
						Value:    toks[1],
						Path:     "/",
						HttpOnly: true,
						Secure:   true,
						SameSite: http.SameSiteStrictMode,
						MaxAge:   86400,
					})
				}
			}
		}
		_ = loginTmpl.Execute(w, data)
	}
}

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
				<button type="submit">Logout</button>
			</form>
			<br>
			<a href="/change-password">Change Password</a>
		{{else}}
		<form method="POST" autocomplete="off">
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

	db, err := sql.Open("sqlite3", "store.db")
	if err != nil {
		log.Fatalf("DB open error: %v", err)
	}
	defer func() {
		_ = db.Close()
	}()
	if err := setupSchema(db); err != nil {
		log.Fatalf("DB schema error: %v", err)
	}

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

	credStore := &SQLCredentialStore{DB: db}
	credRegistry := &CredentialRegistry{
		Stores: map[string]CredentialStore{
			"password": credStore,
			"apikey":   credStore,
			"cognito":  credStore,
			"oauth2":   credStore,
			"google":   credStore,
			"clerk":    credStore,
			"totp":     credStore,
			"mfa":      credStore,
			"2fa":      credStore,
		},
	}

	sessionStore := &SessionStore{DB: db}

	auth := &Authenticator{
		Credentials: credRegistry,
		Signer:      signer,
		Auditor:     auditor,
		Sessions:    sessionStore,
	}

	limiter := newRateLimiter(10, 1*time.Minute)

	http.HandleFunc("/auth", AuthHandler(auth, auditor, limiter))
	http.HandleFunc("/login", FrontendHandler(auth))
	http.HandleFunc("/logout", LogoutHandler(auth))
	http.HandleFunc("/forgot-password", FrontendForgotPasswordHandler(db))
	http.HandleFunc("/reset-password", FrontendResetPasswordHandler(db, auth))
	http.HandleFunc("/change-password", FrontendChangePasswordHandler(db, auth))
	logger.Info("Starting server", zap.String("addr", ":8080"))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
