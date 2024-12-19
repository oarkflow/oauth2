package client

import (
	"context"
	"github.com/oarkflow/oauth2/utils"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

func New(serverURL, clientBaseURL string, config oauth2.Config) *Client {
	config.RedirectURL = utils.AppendURL(clientBaseURL, config.RedirectURL)
	config.Endpoint.AuthURL = utils.AppendURL(serverURL, config.Endpoint.AuthURL)
	config.Endpoint.TokenURL = utils.AppendURL(serverURL, config.Endpoint.TokenURL)
	return &Client{
		serverURL: serverURL,
		Config:    config,
	}
}

type Client struct {
	oauth2.Config
	serverURL string
	token     *oauth2.Token
}

func (c *Client) RefreshToken(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	token.Expiry = time.Now()
	return c.TokenSource(ctx, token).Token()
}

func (c *Client) ClientCredentialsToken(ctx context.Context) (*oauth2.Token, error) {
	cfg := clientcredentials.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		TokenURL:     c.Endpoint.TokenURL,
		Scopes:       c.Scopes,
	}
	return cfg.Token(ctx)
}

func (c *Client) Token() *oauth2.Token {
	return c.token
}

func (c *Client) SetToken(token *oauth2.Token) {
	c.token = token
}
