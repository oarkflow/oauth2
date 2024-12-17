package models

import (
	"github.com/oarkflow/oauth2"
)

type AuthResponse struct {
	RedirectUri         string                     `json:"redirect_uri" form:"redirect_uri" query:"redirect_uri"`
	State               string                     `json:"state" form:"state" query:"state"`
	Scope               string                     `json:"scope" form:"scope" query:"scope"`
	ClientID            string                     `json:"client_id" form:"client_id" query:"client_id"`
	ResponseType        oauth2.ResponseType        `json:"response_type" form:"response_type" query:"response_type"`
	CodeChallenge       string                     `json:"code_challenge" form:"code_challenge" query:"code_challenge"`
	CodeChallengeMethod oauth2.CodeChallengeMethod `json:"code_challenge_method" form:"code_challenge_method" query:"code_challenge_method"`
}
