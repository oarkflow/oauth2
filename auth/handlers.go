package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

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
