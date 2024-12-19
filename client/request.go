package client

import (
	"bytes"
	"context"
	"github.com/oarkflow/oauth2/errors"
	"github.com/oarkflow/oauth2/utils"
	"net/http"
)

func (c *Client) Request(ctx context.Context, method, endpoint string, headers map[string]string, body []byte) (*http.Response, error) {
	if c.token == nil {
		return nil, errors.ErrInvalidToken
	}
	if !utils.HasScheme(endpoint) {
		endpoint = c.serverURL + endpoint
	}
	client := c.Client(ctx, c.token)
	req, err := http.NewRequestWithContext(ctx, method, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return client.Do(req)
}

func (c *Client) GET(ctx context.Context, endpoint string, headers map[string]string) (string, error) {
	resp, err := c.Request(ctx, http.MethodGet, endpoint, headers, nil)
	return utils.ParseResponse(resp, err)
}

func (c *Client) POST(ctx context.Context, endpoint string, headers map[string]string, body []byte) (string, error) {
	resp, err := c.Request(ctx, http.MethodPost, endpoint, headers, body)
	return utils.ParseResponse(resp, err)
}

func (c *Client) PUT(ctx context.Context, endpoint string, headers map[string]string, body []byte) (string, error) {
	resp, err := c.Request(ctx, http.MethodPut, endpoint, headers, body)
	return utils.ParseResponse(resp, err)
}

func (c *Client) PATCH(ctx context.Context, endpoint string, headers map[string]string, body []byte) (string, error) {
	resp, err := c.Request(ctx, http.MethodPatch, endpoint, headers, body)
	return utils.ParseResponse(resp, err)
}

func (c *Client) DELETE(ctx context.Context, endpoint string, headers map[string]string) (string, error) {
	resp, err := c.Request(ctx, http.MethodDelete, endpoint, headers, nil)
	return utils.ParseResponse(resp, err)
}
