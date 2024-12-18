package generates

import (
	"bytes"
	"context"
	"encoding/base64"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/oarkflow/oauth2"
)

// NewAccessGenerate create to generate the access token instance
func NewAccessGenerate() *AccessGenerate {
	return &AccessGenerate{}
}

// AccessGenerate generate the access token
type AccessGenerate struct {
}

// Token based on the UUID generated token
func (ag *AccessGenerate) Token(_ context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (string, string, error) {
	buf := bytes.NewBufferString(data.Client.GetID())
	buf.WriteString(data.UserID)
	buf.WriteString(strconv.FormatInt(data.CreateAt.UnixNano(), 10))

	access := generateBase64(buf.Bytes(), uuid.NewMD5)
	refresh := ""
	if isGenRefresh {
		refresh = generateBase64(buf.Bytes(), uuid.NewSHA1)
	}

	return access, refresh, nil
}

func generateBase64(buf []byte, hash func(uuid.UUID, []byte) uuid.UUID) string {
	data := base64.URLEncoding.EncodeToString([]byte(hash(uuid.Must(uuid.NewRandom()), buf).String()))
	return strings.ToUpper(strings.TrimRight(data, "="))
}

func init() {
	uuid.EnableRandPool()
}
