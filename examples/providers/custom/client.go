package custom

import (
	"crypto/sha256"
	"encoding/base64"
	"golang.org/x/oauth2"
)

type Client struct {
	BaseURL             string
	CodeVerifier        string
	CodeChallengeMethod string
	oauth2.Config
}

func Default(baseURL, clientID, secret string, scopes ...string) *Client {
	if len(scopes) == 0 {
		scopes = append(scopes, "all")
	}
	cfg := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: secret,
		Scopes:       scopes,
		RedirectURL:  "/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "/oauth/authorize",
			TokenURL: "/oauth/token",
		},
	}
	return New(baseURL, "code_verifier", cfg)
}

func New(baseURL, codeVerifier string, cfg oauth2.Config) *Client {
	return &Client{
		BaseURL:             baseURL,
		CodeVerifier:        codeVerifier,
		Config:              cfg,
		CodeChallengeMethod: "S256",
	}
}

func (c *Client) genCodeChallengeS256() string {
	hash := sha256.Sum256([]byte(c.CodeVerifier))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func (c *Client) GetAuthParams() []oauth2.AuthCodeOption {
	codeChallenge := c.genCodeChallengeS256()
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", c.CodeChallengeMethod),
	}
}

func (c *Client) GetExchangeToken() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", c.CodeVerifier),
	}
}
