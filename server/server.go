package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/oarkflow/oauth2"
	"github.com/oarkflow/oauth2/errors"
	"github.com/oarkflow/oauth2/models"
)

var DefaultIssuer = "Oauth2"

// NewServer create authorization server
func NewServer(cfg *Config, manager oauth2.Manager) *Server {
	srv := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handler
	srv.ClientInfoHandler = ClientFormHandler

	srv.UserAuthorizationHandler = func(ctx *fiber.Ctx) (string, error) {
		return "", errors.ErrAccessDenied
	}

	srv.PasswordAuthorizationHandler = func(ctx context.Context, clientID, username, password string) (string, error) {
		return "", errors.ErrAccessDenied
	}
	return srv
}

// Server Provide authorization server
type Server struct {
	Config                       *Config
	Manager                      oauth2.Manager
	ClientInfoHandler            ClientInfoHandler
	ClientAuthorizedHandler      ClientAuthorizedHandler
	ClientScopeHandler           ClientScopeHandler
	UserAuthorizationHandler     UserAuthorizationHandler
	PasswordAuthorizationHandler PasswordAuthorizationHandler
	RefreshingValidationHandler  RefreshingValidationHandler
	PreRedirectErrorHandler      PreRedirectErrorHandler
	RefreshingScopeHandler       RefreshingScopeHandler
	ResponseErrorHandler         ResponseErrorHandler
	InternalErrorHandler         InternalErrorHandler
	ExtensionFieldsHandler       ExtensionFieldsHandler
	AccessTokenExpHandler        AccessTokenExpHandler
	AuthorizeScopeHandler        AuthorizeScopeHandler
	ResponseTokenHandler         ResponseTokenHandler
}

func (s *Server) handleError(req *AuthorizeRequest, err error) error {
	if fn := s.PreRedirectErrorHandler; fn != nil {
		return fn(req, err)
	}

	return s.redirectError(req, err)
}

func (s *Server) redirectError(req *AuthorizeRequest, err error) error {
	if req == nil {
		return err
	}

	data, _, _ := s.GetErrorData(err)
	return s.redirect(req, data)
}

func (s *Server) redirect(req *AuthorizeRequest, data map[string]interface{}) error {
	uri, err := s.GetRedirectURI(req, data)
	if err != nil {
		return err
	}
	return req.Request.Redirect(uri, fiber.StatusFound)
}

func (s *Server) tokenError(ctx *fiber.Ctx, err error) error {
	data, statusCode, header := s.GetErrorData(err)
	return s.token(ctx, data, header, statusCode)
}

func (s *Server) token(ctx *fiber.Ctx, data map[string]interface{}, header http.Header, statusCode ...int) error {
	if fn := s.ResponseTokenHandler; fn != nil {
		return fn(ctx, data, header, statusCode...)
	}
	ctx.Set("Content-Type", "application/json;charset=UTF-8")
	ctx.Set("Cache-Control", "no-store")
	ctx.Set("Pragma", "no-cache")

	for key := range header {
		ctx.Set(key, header.Get(key))
	}

	status := fiber.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}
	ctx.Status(status)
	return ctx.JSON(data)
}

// GetRedirectURI get redirect uri
func (s *Server) GetRedirectURI(req *AuthorizeRequest, data map[string]interface{}) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	if req.State != "" {
		q.Set("state", req.State)
	}

	for k, v := range data {
		q.Set(k, fmt.Sprint(v))
	}

	switch req.ResponseType {
	case oauth2.Code:
		u.RawQuery = q.Encode()
	case oauth2.Token:
		u.RawQuery = ""
		fragment, err := url.QueryUnescape(q.Encode())
		if err != nil {
			return "", err
		}
		u.Fragment = fragment
	}

	return u.String(), nil
}

// CheckResponseType check allows response type
func (s *Server) CheckResponseType(rt oauth2.ResponseType) bool {
	for _, art := range s.Config.AllowedResponseTypes {
		if art == rt {
			return true
		}
	}
	return false
}

// CheckCodeChallengeMethod checks for allowed code challenge method
func (s *Server) CheckCodeChallengeMethod(ccm oauth2.CodeChallengeMethod) bool {
	for _, c := range s.Config.AllowedCodeChallengeMethods {
		if c == ccm {
			return true
		}
	}
	return false
}

// ValidationAuthorizeRequest the authorization request validation
func (s *Server) ValidationAuthorizeRequest(ctx *fiber.Ctx) (*AuthorizeRequest, error) {
	data, err := ParseRequest[models.AuthResponse](ctx)
	if err != nil {
		return nil, err
	}
	if data.ResponseType.String() == "" && ctx.Body() != nil {
		err = json.Unmarshal(ctx.Body(), &data)
		if err != nil {
			return nil, err
		}
	}
	if data.ResponseType.String() == "" {
		return nil, errors.ErrUnsupportedResponseType
	} else if allowed := s.CheckResponseType(data.ResponseType); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	if data.CodeChallenge == "" && s.Config.ForcePKCE {
		return nil, errors.ErrCodeChallengeRquired
	}
	if data.CodeChallenge != "" && (len(data.CodeChallenge) < 43 || len(data.CodeChallenge) > 128) {
		return nil, errors.ErrInvalidCodeChallengeLen
	}

	// set default
	if data.CodeChallengeMethod == "" {
		data.CodeChallengeMethod = oauth2.CodeChallengePlain
	}
	if data.CodeChallengeMethod != "" && !s.CheckCodeChallengeMethod(data.CodeChallengeMethod) {
		return nil, errors.ErrUnsupportedCodeChallengeMethod
	}

	req := &AuthorizeRequest{
		RedirectURI:         data.RedirectUri,
		ResponseType:        data.ResponseType,
		ClientID:            data.ClientID,
		State:               data.State,
		Scope:               data.Scope,
		Request:             ctx,
		CodeChallenge:       data.CodeChallenge,
		CodeChallengeMethod: data.CodeChallengeMethod,
	}
	return req, nil
}

// GetAuthorizeToken get authorization token(code)
func (s *Server) GetAuthorizeToken(ctx context.Context, req *AuthorizeRequest) (oauth2.TokenInfo, error) {
	// check the client allows the grant type
	if fn := s.ClientAuthorizedHandler; fn != nil {
		gt := oauth2.AuthorizationCode
		if req.ResponseType == oauth2.Token {
			gt = oauth2.Implicit
		}

		allowed, err := fn(req.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:       req.ClientID,
		UserID:         req.UserID,
		RedirectURI:    req.RedirectURI,
		Scope:          req.Scope,
		AccessTokenExp: req.AccessTokenExp,
		Request:        req.Request,
	}

	// check the client allows the authorized scope
	if fn := s.ClientScopeHandler; fn != nil {
		allowed, err := fn(tgr)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrInvalidScope
		}
	}

	tgr.CodeChallenge = req.CodeChallenge
	tgr.CodeChallengeMethod = req.CodeChallengeMethod

	return s.Manager.GenerateAuthToken(ctx, req.ResponseType, tgr)
}

// GetAuthorizeData get authorization response data
func (s *Server) GetAuthorizeData(rt oauth2.ResponseType, ti oauth2.TokenInfo) map[string]interface{} {
	if rt == oauth2.Code {
		return map[string]interface{}{
			"code": ti.GetCode(),
		}
	}
	return s.GetTokenData(ti)
}

// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(ctx *fiber.Ctx) error {
	req, err := s.ValidationAuthorizeRequest(ctx)
	if err != nil {
		return s.handleError(req, err)
	}

	// user authorization
	userID, err := s.UserAuthorizationHandler(ctx)
	if err != nil {
		return s.handleError(req, err)
	} else if userID == "" {
		return nil
	}
	req.UserID = userID

	// specify the scope of authorization
	if fn := s.AuthorizeScopeHandler; fn != nil {
		scope, err := fn(ctx)
		if err != nil {
			return err
		} else if scope != "" {
			req.Scope = scope
		}
	}

	// specify the expiration time of access token
	if fn := s.AccessTokenExpHandler; fn != nil {
		exp, err := fn(ctx)
		if err != nil {
			return err
		}
		req.AccessTokenExp = exp
	}

	ti, err := s.GetAuthorizeToken(ctx.Context(), req)
	if err != nil {
		return s.handleError(req, err)
	}

	// If the redirect URI is empty, the default domain provided by the client is used.
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(ctx.Context(), req.ClientID)
		if err != nil {
			return err
		}
		req.RedirectURI = client.GetDomain()
	}

	return s.redirect(req, s.GetAuthorizeData(req.ResponseType, ti))
}

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(ctx *fiber.Ctx) (oauth2.GrantType, *oauth2.TokenGenerateRequest, error) {
	data, err := ParseRequest[models.AuthRequest](ctx)
	if err != nil {
		return "", nil, err
	}
	if data.GrantType.String() == "" {
		return "", nil, errors.ErrUnsupportedGrantType
	}

	clientID, clientSecret, err := s.ClientInfoHandler(ctx)
	if err != nil {
		return "", nil, err
	}

	tgr := &oauth2.TokenGenerateRequest{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Request:      ctx,
	}

	switch data.GrantType {
	case oauth2.AuthorizationCode:
		tgr.RedirectURI = data.RedirectUri
		tgr.Code = data.Code
		if tgr.RedirectURI == "" ||
			tgr.Code == "" {
			return "", nil, errors.ErrInvalidRequest
		}
		tgr.CodeVerifier = data.CodeVerifier
		if s.Config.ForcePKCE && tgr.CodeVerifier == "" {
			return "", nil, errors.ErrInvalidRequest
		}
	case oauth2.PasswordCredentials:
		tgr.Scope = data.Scope
		username, password := data.Username, data.Password
		if username == "" || password == "" {
			return "", nil, errors.ErrInvalidRequest
		}

		userID, err := s.PasswordAuthorizationHandler(ctx.Context(), clientID, username, password)
		if err != nil {
			return "", nil, err
		} else if userID == "" {
			return "", nil, errors.ErrInvalidGrant
		}
		tgr.UserID = userID
	case oauth2.ClientCredentials:
		tgr.Scope = data.Scope
		tgr.Issuer = DefaultIssuer
	case oauth2.Refreshing:
		tgr.Refresh = data.RefreshToken
		tgr.Scope = data.Scope
		if tgr.Refresh == "" {
			return "", nil, errors.ErrInvalidRequest
		}
	}
	return data.GrantType, tgr, nil
}

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt oauth2.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
}

// GetAccessToken access token
func (s *Server) GetAccessToken(ctx context.Context, gt oauth2.GrantType, tgr *oauth2.TokenGenerateRequest) (oauth2.TokenInfo,
	error) {
	if allowed := s.CheckGrantType(gt); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}
	if fn := s.ClientAuthorizedHandler; fn != nil {
		allowed, err := fn(tgr.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}
	switch gt {
	case oauth2.AuthorizationCode:
		ti, err := s.Manager.GenerateAccessToken(ctx, gt, tgr)
		if err != nil {
			switch err {
			case errors.ErrInvalidAuthorizeCode, errors.ErrInvalidCodeChallenge, errors.ErrMissingCodeChallenge:
				return nil, errors.ErrInvalidGrant
			case errors.ErrInvalidClient:
				return nil, errors.ErrInvalidClient
			default:
				return nil, err
			}
		}
		return ti, nil
	case oauth2.PasswordCredentials, oauth2.ClientCredentials:
		if fn := s.ClientScopeHandler; fn != nil {
			allowed, err := fn(tgr)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}
		return s.Manager.GenerateAccessToken(ctx, gt, tgr)
	case oauth2.Refreshing:
		if scopeFn := s.RefreshingScopeHandler; tgr.Scope != "" && scopeFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.Refresh)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}

			allowed, err := scopeFn(tgr, rti.GetScope())
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}

		if validationFn := s.RefreshingValidationHandler; validationFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.Refresh)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}
			allowed, err := validationFn(rti)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}

		ti, err := s.Manager.RefreshAccessToken(ctx, tgr)
		if err != nil {
			if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
				return nil, errors.ErrInvalidGrant
			}
			return nil, err
		}
		return ti, nil
	}

	return nil, errors.ErrUnsupportedGrantType
}

// GetTokenData token data
func (s *Server) GetTokenData(ti oauth2.TokenInfo) map[string]interface{} {
	data := map[string]interface{}{
		"access_token": ti.GetAccess(),
		"token_type":   s.Config.TokenType,
		"expires_in":   int64(ti.GetAccessExpiresIn() / time.Second),
	}
	if scope := ti.GetScope(); scope != "" {
		data["scope"] = scope
	}
	if refresh := ti.GetRefresh(); refresh != "" {
		data["refresh_token"] = refresh
	}
	if fn := s.ExtensionFieldsHandler; fn != nil {
		ext := fn(ti)
		for k, v := range ext {
			if _, ok := data[k]; ok {
				continue
			}
			data[k] = v
		}
	}
	return data
}

// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(ctx *fiber.Ctx) error {
	gt, tgr, err := s.ValidationTokenRequest(ctx)
	if err != nil {
		return s.tokenError(ctx, err)
	}
	ti, err := s.GetAccessToken(ctx.Context(), gt, tgr)
	if err != nil {
		return s.tokenError(ctx, err)
	}
	return s.token(ctx, s.GetTokenData(ti), nil)
}

// GetErrorData get error response data
func (s *Server) GetErrorData(err error) (map[string]interface{}, int, http.Header) {
	var re errors.Response
	if v, ok := errors.Descriptions[err]; ok {
		re.Error = err
		re.Description = v
		re.StatusCode = errors.StatusCodes[err]
	} else {
		if fn := s.InternalErrorHandler; fn != nil {
			if v := fn(err); v != nil {
				re = *v
			}
		}
		if re.Error == nil {
			re.Error = errors.ErrServerError
			re.Description = errors.Descriptions[errors.ErrServerError]
			re.StatusCode = errors.StatusCodes[errors.ErrServerError]
		}
	}
	if fn := s.ResponseErrorHandler; fn != nil {
		fn(&re)
	}
	data := make(map[string]interface{})
	if err := re.Error; err != nil {
		data["error"] = err.Error()
	}
	if v := re.ErrorCode; v != 0 {
		data["error_code"] = v
	}
	if v := re.Description; v != "" {
		data["error_description"] = v
	}
	if v := re.URI; v != "" {
		data["error_uri"] = v
	}
	statusCode := fiber.StatusInternalServerError
	if v := re.StatusCode; v > 0 {
		statusCode = v
	}
	return data, statusCode, re.Header
}

type AccessToken struct {
	AccessToken string `json:"access_token" form:"access_token" query:"access_token"`
}

// BearerAuth parse bearer token
func (s *Server) BearerAuth(ctx *fiber.Ctx) (string, bool) {
	auth := ctx.Get("Authorization")
	prefix := "Bearer "
	token := ""
	if auth != "" && strings.HasPrefix(auth, prefix) {
		token = auth[len(prefix):]
	} else {
		data, err := ParseRequest[AccessToken](ctx)
		if err == nil {
			token = data.AccessToken
		}
	}
	return token, token != ""
}

func (s *Server) ValidationBearerToken(ctx *fiber.Ctx) (oauth2.TokenInfo, error) {
	accessToken, ok := s.BearerAuth(ctx)
	fmt.Println(accessToken)
	if !ok {
		return nil, errors.ErrInvalidAccessToken
	}
	return s.Manager.LoadAccessToken(ctx.Context(), accessToken)
}
