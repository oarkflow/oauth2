package models

import (
	"github.com/oarkflow/oauth2"
)

type AuthRequest struct {
	GrantType    oauth2.GrantType `json:"grant_type" form:"grant_type" query:"grant_type"`
	Code         string           `json:"code" form:"code" query:"code"`
	Scope        string           `json:"scope" form:"scope" query:"scope"`
	Username     string           `json:"username" form:"username" query:"username"`
	Password     string           `json:"password" form:"password" query:"password"`
	RefreshToken string           `json:"refresh_token" form:"refresh_token" query:"refresh_token"`
	CodeVerifier string           `json:"code_verifier" form:"code_verifier" query:"code_verifier"`
	RedirectUri  string           `json:"redirect_uri" form:"redirect_uri" query:"redirect_uri"`
}
