package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/template/html/v2"

	"github.com/oarkflow/oauth2/errors"
	"github.com/oarkflow/oauth2/generates"
	"github.com/oarkflow/oauth2/manage"
	"github.com/oarkflow/oauth2/models"
	"github.com/oarkflow/oauth2/server"
	"github.com/oarkflow/oauth2/store"
)

var clients = map[string]*models.Client{
	"222222": {
		ID:     "222222",
		Secret: "22222222",
		Domain: "http://localhost:9094",
	},
}

var (
	port = 9096
	sess = session.New()
)

func main() {
	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	for id, client := range clients {
		clientStore.Set(id, client)
	}
	manager.MapClientStorage(clientStore)
	cfg := server.NewConfig()
	srv := server.NewServer("Oauth2", cfg, manager)
	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, clientID, username, password string) (userID string, err error) {
		if username == "test" && password == "test" {
			userID = "test"
		}
		return
	})

	srv.SetUserAuthorizationHandler(userAuthorizeHandler)

	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})

	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	engine := html.New("./views", ".html")
	engine.Reload(true)
	app := fiber.New(fiber.Config{Views: engine})
	app.Static("/", "./static")
	app.Get("/login", func(ctx *fiber.Ctx) error {
		return ctx.Render("login", fiber.Map{
			"LogoURL": srv.Config.CompanyLogoFile,
		})
	})
	app.Post("/login", func(ctx *fiber.Ctx) error {
		sessionStore, err := sess.Get(ctx)
		if err != nil {
			return err
		}
		data, err := server.ParseRequest[models.Identity](ctx)
		if err != nil {
			return err
		}
		sessionStore.Set("LoggedInUserID", data.Username)
		_ = sessionStore.Save()
		if !srv.Config.RequiredConsent {
			return handleAuthorize(ctx, srv)
		}
		return ctx.Redirect("/auth", fiber.StatusFound)
	})
	app.All("/auth", func(ctx *fiber.Ctx) error {
		sessionStore, err := sess.Get(ctx)
		if err != nil {
			return err
		}
		if _, ok := sessionStore.Get("LoggedInUserID").(string); !ok {
			return ctx.Redirect("/login", fiber.StatusFound)
		}
		return ctx.Render("auth", fiber.Map{
			"LogoURL": srv.Config.CompanyLogoFile,
		})
	})
	app.All("/oauth/authorize", func(ctx *fiber.Ctx) error {
		return handleAuthorize(ctx, srv)
	})
	app.All("/oauth/token", srv.HandleTokenRequest)

	app.Get("/test", func(ctx *fiber.Ctx) error {
		token, err := srv.ValidationBearerToken(ctx)
		if err != nil {
			return err
		}

		data := map[string]interface{}{
			"expires_in": int64(token.GetAccessCreateAt().Add(token.GetAccessExpiresIn()).Sub(time.Now()).Seconds()),
			"client_id":  token.GetClientID(),
			"user_id":    token.GetUserID(),
		}
		return ctx.JSON(data)
	})
	_ = app.Listen(fmt.Sprintf(":%d", port))
}

func handleAuthorize(ctx *fiber.Ctx, srv *server.Server) error {
	sessionStore, err := sess.Get(ctx)
	if err != nil {
		return err
	}
	v, ok := sessionStore.Get("ReturnUri").([]byte)
	if ctx.Method() == fiber.MethodPost {
		consent := ctx.FormValue("consent")
		if srv.Config.RequiredConsent && consent != "allow" {
			redirectURi := "/login"
			if v != nil {
				var mp map[string]any
				err = json.Unmarshal(v, &mp)
				if err == nil {
					redirectURi = mp["redirect_uri"].(string) + "?error=request_cancelled"
				}
			}
			return ctx.Redirect(redirectURi, fiber.StatusFound)
		}
		sessionStore.Set("consent", consent)
	}
	if ok {
		ctx.Request().SetBody(v)
	}
	sessionStore.Delete("ReturnUri")
	_ = sessionStore.Save()
	return srv.HandleAuthorizeRequest(ctx)
}

func userAuthorizeHandler(ctx *fiber.Ctx) (userID string, err error) {
	sessionStore, err := sess.Get(ctx)
	if err != nil {
		return
	}
	uid, ok := sessionStore.Get("LoggedInUserID").(string)
	if !ok {
		data, err := server.ParseRequest[models.AuthResponse](ctx)
		if err == nil {
			bt, _ := json.Marshal(data)
			sessionStore.Set("ReturnUri", bt)
			_ = sessionStore.Save()
			return "", ctx.Redirect("/login", fiber.StatusFound)
		}
	}
	userID = uid
	sessionStore.Delete("LoggedInUserID")
	_ = sessionStore.Save()
	return
}
