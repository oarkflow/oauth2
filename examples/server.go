package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"

	"github.com/oarkflow/oauth2/errors"
	"github.com/oarkflow/oauth2/generates"
	"github.com/oarkflow/oauth2/manage"
	"github.com/oarkflow/oauth2/models"
	"github.com/oarkflow/oauth2/server"
	"github.com/oarkflow/oauth2/store"
)

var (
	dumpvar   bool
	idvar     string
	secretvar string
	domainvar string
	portvar   int
	sess      = session.New()
)

func init() {
	flag.BoolVar(&dumpvar, "d", true, "Dump requests and responses")
	flag.StringVar(&idvar, "i", "222222", "The client id being passed in")
	flag.StringVar(&secretvar, "s", "22222222", "The client secret being passed in")
	flag.StringVar(&domainvar, "r", "http://localhost:9094", "The domain of the redirect url")
	flag.IntVar(&portvar, "p", 9096, "the base port for the server")
}

func main() {
	flag.Parse()

	manager := manage.NewDefaultManager()
	manager.SetAuthorizeCodeTokenCfg(manage.DefaultAuthorizeCodeTokenCfg)
	manager.MustTokenStorage(store.NewMemoryTokenStore())
	manager.MapAccessGenerate(generates.NewAccessGenerate())

	clientStore := store.NewClientStore()
	_ = clientStore.Set(idvar, &models.Client{
		ID:     idvar,
		Secret: secretvar,
		Domain: domainvar,
	})
	manager.MapClientStorage(clientStore)
	srv := server.NewServer(server.NewConfig(), manager)
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
	app := fiber.New()
	app.Get("/login", loginHandler)
	app.Post("/login", loginPostHandler)
	app.All("/auth", authHandler)
	app.All("/oauth/authorize", func(ctx *fiber.Ctx) error {
		sessionStore, err := sess.Get(ctx)
		if err != nil {
			return err
		}
		if v, ok := sessionStore.Get("ReturnUri").([]byte); ok {
			ctx.Request().SetBody(v)
		}
		sessionStore.Delete("ReturnUri")
		_ = sessionStore.Save()
		return srv.HandleAuthorizeRequest(ctx)
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

	log.Printf("Server is running at %d port.\n", portvar)
	log.Printf("Point your OAuth client Auth endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/authorize")
	log.Printf("Point your OAuth client Token endpoint to %s:%d%s", "http://localhost", portvar, "/oauth/token")
	_ = app.Listen(fmt.Sprintf(":%d", portvar))
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

func loginHandler(ctx *fiber.Ctx) error {
	return ctx.SendFile("static/login.html")
}

func loginPostHandler(ctx *fiber.Ctx) error {
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
	return ctx.Redirect("/auth", fiber.StatusFound)
}

func authHandler(ctx *fiber.Ctx) error {
	sessionStore, err := sess.Get(ctx)
	if err != nil {
		return err
	}

	if _, ok := sessionStore.Get("LoggedInUserID").(string); !ok {
		return ctx.Redirect("/login", fiber.StatusFound)
	}
	return ctx.SendFile("static/auth.html")
}
