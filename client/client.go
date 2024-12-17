package client

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"

	"github.com/oarkflow/oauth2/errors"
)

func New(serverURL, clientBaseURL string, config oauth2.Config) *Client {
	config.RedirectURL = AppendURL(clientBaseURL, config.RedirectURL)
	config.Endpoint.AuthURL = AppendURL(serverURL, config.Endpoint.AuthURL)
	config.Endpoint.TokenURL = AppendURL(serverURL, config.Endpoint.TokenURL)
	return &Client{
		serverURL: serverURL,
		cfg:       config,
	}
}

type Client struct {
	cfg       oauth2.Config
	serverURL string
	token     *oauth2.Token
}

// GenerateAuthURL generates the authorization URL for the Authorization Code flow
func (c *Client) GenerateAuthURL(state, codeVerifier string) string {
	codeChallenge := genCodeChallengeS256(codeVerifier)
	return c.cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
}

// ExchangeToken exchanges the authorization code for an access token
func (c *Client) ExchangeToken(ctx context.Context, code, codeVerifier string) (*oauth2.Token, error) {
	return c.cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
}

// RefreshToken refreshes the access token
func (c *Client) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	token.Expiry = time.Now()
	return c.cfg.TokenSource(ctx, token).Token()
}

// PasswordCredentialsToken retrieves a token using the Resource Owner Password Credentials flow
func (c *Client) PasswordCredentialsToken(ctx context.Context, username, password string) (*oauth2.Token, error) {
	return c.cfg.PasswordCredentialsToken(ctx, username, password)
}

// ClientCredentialsToken retrieves a token using the Client Credentials flow
func (c *Client) ClientCredentialsToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := clientcredentials.Config{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		TokenURL:     c.cfg.Endpoint.TokenURL,
	}
	return cfg.Token(ctx)
}

// Request performs a request with the specified HTTP method, headers, and body
func (c *Client) Request(ctx context.Context, method, endpoint string, headers map[string]string, body []byte) (*http.Response, error) {
	if c.token == nil {
		return nil, errors.ErrInvalidToken
	}
	if !HasScheme(endpoint) {
		endpoint = c.serverURL + endpoint
	}
	client := c.cfg.Client(ctx, c.token)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return client.Do(req)
}

// GET performs a GET request to the specified endpoint
func (c *Client) GET(ctx context.Context, endpoint string, headers map[string]string) (string, error) {
	resp, err := c.Request(ctx, http.MethodGet, endpoint, headers, nil)
	return readResponseBody(resp, err)
}

// POST performs a POST request to the specified endpoint
func (c *Client) POST(ctx context.Context, endpoint string, headers map[string]string, body []byte) (string, error) {
	resp, err := c.Request(ctx, http.MethodPost, endpoint, headers, body)
	return readResponseBody(resp, err)
}

// PUT performs a PUT request to the specified endpoint
func (c *Client) PUT(ctx context.Context, endpoint string, headers map[string]string, body []byte) (string, error) {
	resp, err := c.Request(ctx, http.MethodPut, endpoint, headers, body)
	return readResponseBody(resp, err)
}

// PATCH performs a PATCH request to the specified endpoint
func (c *Client) PATCH(ctx context.Context, endpoint string, headers map[string]string, body []byte) (string, error) {
	resp, err := c.Request(ctx, http.MethodPatch, endpoint, headers, body)
	return readResponseBody(resp, err)
}

// DELETE performs a DELETE request to the specified endpoint
func (c *Client) DELETE(ctx context.Context, endpoint string, headers map[string]string) (string, error) {
	resp, err := c.Request(ctx, http.MethodDelete, endpoint, headers, nil)
	return readResponseBody(resp, err)
}

// Helper function to read response body
func readResponseBody(resp *http.Response, err error) (string, error) {
	if err != nil {
		return "", err
	}
	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

// genCodeChallengeS256 generates a S256 code challenge
func genCodeChallengeS256(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.EncodeToString(hash[:])
}

// Token returns the stored token
func (c *Client) Token() *oauth2.Token {
	return c.token
}

// SetToken sets the stored token
func (c *Client) SetToken(token *oauth2.Token) {
	c.token = token
}

// HasScheme checks if the given URL has a valid scheme
func HasScheme(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// AppendURL ensures that URLs are joined properly and avoids multiple slashes, except in the scheme.
func AppendURL(baseURL, path string) string {
	if HasScheme(path) {
		return path
	}
	normalizedPath := strings.TrimLeft(path, "/")
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	normalizedURL := baseURL + normalizedPath
	schemeEnd := strings.Index(normalizedURL, "://")
	if schemeEnd != -1 {
		scheme := normalizedURL[:schemeEnd+3]
		body := strings.ReplaceAll(normalizedURL[schemeEnd+3:], "//", "/")
		normalizedURL = scheme + body
	}
	return normalizedURL
}
