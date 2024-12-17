package server

import (
	"context"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/oauth2"
	"github.com/oarkflow/oauth2/errors"
)

type (
	// ClientInfoHandler get client info from request
	ClientInfoHandler func(ctx *fiber.Ctx) (clientID, clientSecret string, err error)
	// ClientAuthorizedHandler check the client allows to use this authorization grant type
	ClientAuthorizedHandler func(clientID string, grant oauth2.GrantType) (allowed bool, err error)
	// ClientScopeHandler check the client allows to use scope
	ClientScopeHandler func(tgr *oauth2.TokenGenerateRequest) (allowed bool, err error)
	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(ctx *fiber.Ctx) (userID string, err error)
	// PasswordAuthorizationHandler get user id from username and password
	PasswordAuthorizationHandler func(ctx context.Context, clientID, username, password string) (userID string, err error)
	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(tgr *oauth2.TokenGenerateRequest, oldScope string) (allowed bool, err error)
	// RefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
	RefreshingValidationHandler func(ti oauth2.TokenInfo) (allowed bool, err error)
	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *errors.Response)
	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *errors.Response)
	// PreRedirectErrorHandler is used to override "redirect-on-error" behavior
	PreRedirectErrorHandler func(req *AuthorizeRequest, err error) error
	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(ctx *fiber.Ctx) (scope string, err error)
	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(ctx *fiber.Ctx) (exp time.Duration, err error)
	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti oauth2.TokenInfo) (fieldsValue map[string]interface{})
	// ResponseTokenHandler response token handing
	ResponseTokenHandler func(ctx *fiber.Ctx, data map[string]interface{}, header http.Header, statusCode ...int) error
)

type Client struct {
	ClientID     string `json:"client_id" query:"client_id" form:"client_id"`
	ClientSecret string `json:"client_secret" query:"client_secret" form:"client_secret"`
}

// ClientFormHandler get client data from form
func ClientFormHandler(ctx *fiber.Ctx) (string, string, error) {
	client, err := ParseRequest[Client](ctx)
	if err != nil {
		return "", "", err
	}
	return client.ClientID, client.ClientSecret, nil
}

func ParseRequest[T any](ctx *fiber.Ctx) (T, error) {
	var t T
	var err error
	if ctx.Method() == fiber.MethodGet {
		err = ctx.QueryParser(&t)
	} else if ctx.Method() == fiber.MethodPost {
		err = ctx.BodyParser(&t)
	}
	return t, err
}
