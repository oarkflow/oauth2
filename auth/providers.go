package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/coreos/go-oidc"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

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

// --- Credential Store Interface ---

type CredentialStore interface {
	Authenticate(ctx context.Context, identifier, secret string) (userID string, err error)
}

// --- Credential Type Handler Interface ---

type CredentialTypeHandler interface {
	Authenticate(ctx context.Context, db *sql.DB, identifier, secret, secretHash string, metadata sql.NullString) (string, error)
}

// --- Handlers Implementation ---

type PasswordHandler struct{}

func (h *PasswordHandler) Authenticate(ctx context.Context, db *sql.DB, identifier, secret, secretHash string, metadata sql.NullString) (string, error) {
	// Account lockout check
	failed, err := getFailedLogin(db, identifier)
	if err == nil && failed.Count >= maxFailedAttempts && time.Since(failed.LockedAt) < lockoutDuration {
		return "", errors.New("account locked due to too many failed attempts")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)); err != nil {
		_ = recordFailedLogin(db, identifier)
		failed, _ := getFailedLogin(db, identifier)
		delay := backoffBase * time.Duration(1<<failed.Count)
		if delay > backoffMax {
			delay = backoffMax
		}
		time.Sleep(delay)
		return "", errors.New("unauthorized")
	}
	_ = resetFailedLogin(db, identifier)
	rotate, _ := checkPasswordRotation(db, identifier)
	if rotate {
		return "", errors.New("password rotation required")
	}
	return identifier, nil
}

type ApiKeyHandler struct{}

func (h *ApiKeyHandler) Authenticate(ctx context.Context, db *sql.DB, identifier, secret, secretHash string, metadata sql.NullString) (string, error) {
	keyHash := sha256.Sum256([]byte(secret))
	provided := base64.StdEncoding.EncodeToString(keyHash[:])
	if subtle.ConstantTimeCompare([]byte(secretHash), []byte(provided)) != 1 {
		return "", errors.New("unauthorized")
	}
	return identifier, nil
}

type CognitoHandler struct{}

func (h *CognitoHandler) Authenticate(ctx context.Context, db *sql.DB, identifier, secret, secretHash string, metadata sql.NullString) (string, error) {
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
	getUserInput := &cognitoidentityprovider.GetUserInput{
		AccessToken: &secret,
	}
	_, err = cip.GetUser(ctx, getUserInput)
	if err != nil {
		return "", errors.New("cognito user fetch failed")
	}
	return identifier, nil
}

type Oauth2Handler struct{}

func (h *Oauth2Handler) Authenticate(ctx context.Context, db *sql.DB, identifier, secret, secretHash string, metadata sql.NullString) (string, error) {
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
	return identifier, nil
}

type TotpHandler struct{}

func (h *TotpHandler) Authenticate(ctx context.Context, db *sql.DB, identifier, secret, secretHash string, metadata sql.NullString) (string, error) {
	var meta struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal([]byte(metadata.String), &meta); err != nil {
		return "", errors.New("invalid totp metadata")
	}
	if !totp.Validate(secret, meta.Secret) {
		return "", errors.New("invalid totp code")
	}
	return identifier, nil
}

type MfaHandler struct{}

func (h *MfaHandler) Authenticate(ctx context.Context, db *sql.DB, identifier, secret, secretHash string, metadata sql.NullString) (string, error) {
	var meta map[string]interface{}
	if err := json.Unmarshal([]byte(metadata.String), &meta); err != nil {
		return "", errors.New("invalid mfa metadata")
	}
	switch meta["type"] {
	case "totp":
		if !totp.Validate(secret, meta["secret"].(string)) {
			return "", errors.New("invalid mfa totp code")
		}
		return identifier, nil
	case "sms":
		if meta["code"] != secret {
			return "", errors.New("invalid mfa sms code")
		}
		return identifier, nil
	default:
		return "", errors.New("unsupported mfa type")
	}
}

// --- Handler Registry ---

var credentialTypeHandlers = map[string]CredentialTypeHandler{
	"password": &PasswordHandler{},
	"apikey":   &ApiKeyHandler{},
	"cognito":  &CognitoHandler{},
	"oauth2":   &Oauth2Handler{},
	"google":   &Oauth2Handler{},
	"clerk":    &Oauth2Handler{},
	"totp":     &TotpHandler{},
	"mfa":      &MfaHandler{},
	"2fa":      &MfaHandler{},
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

	handler, ok := credentialTypeHandlers[typ]
	if !ok {
		return "", errors.New("unsupported credential type")
	}
	return handler.Authenticate(ctx, s.DB, userID, secret, secretHash, metadata)
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
