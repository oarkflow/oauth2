package main

import (
	"context"
	"log"
	"net/http"
	"strings"
)

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
