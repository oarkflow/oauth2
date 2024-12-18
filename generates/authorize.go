package generates

import (
	"bytes"
	"context"

	"github.com/google/uuid"

	"github.com/oarkflow/oauth2"
)

// NewAuthorizeGenerate create to generate the authorize code instance
func NewAuthorizeGenerate() *AuthorizeGenerate {
	return &AuthorizeGenerate{}
}

// AuthorizeGenerate generate the authorize code
type AuthorizeGenerate struct{}

// Token based on the UUID generated token
func (ag *AuthorizeGenerate) Token(_ context.Context, data *oauth2.GenerateBasic) (string, error) {
	buf := bytes.NewBufferString(data.Client.GetID())
	buf.WriteString(data.UserID)
	code := generateBase64(buf.Bytes(), uuid.NewMD5)
	return code, nil
}
