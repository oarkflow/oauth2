package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"log"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"

	"github.com/oarkflow/oauth2/client"
)

func main() {
	app := fiber.New()
	codeVerifier := "s256example"
	clientBaseURL := "http://localhost:9094"
	oauth2Client := client.New("http://localhost:9096", clientBaseURL, oauth2.Config{
		ClientID:     "222222",
		ClientSecret: "22222222",
		Scopes:       []string{"all"},
		RedirectURL:  "/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  "/oauth/authorize",
			TokenURL: "/oauth/token",
		},
	})
	app.Get("/", func(c *fiber.Ctx) error {
		authURL := oauth2Client.AuthCodeURL("xyz", getAuthParam(codeVerifier)...)
		return c.Redirect(authURL)
	})
	app.Get("/callback", func(c *fiber.Ctx) error {
		state := c.Query("state")
		if state != "xyz" {
			return c.Status(fiber.StatusBadRequest).SendString("State invalid")
		}
		code := c.Query("code")
		if code == "" {
			return c.Status(fiber.StatusBadRequest).SendString("Code not found")
		}
		token, err := oauth2Client.Exchange(context.Background(), code, getExchangeToken(codeVerifier)...)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		oauth2Client.SetToken(token)
		return c.JSON(token)
	})
	app.Get("/refresh", func(c *fiber.Ctx) error {
		if oauth2Client.Token() == nil {
			return c.Redirect("/")
		}
		token, err := oauth2Client.RefreshToken(context.Background(), oauth2Client.Token())
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
		}
		oauth2Client.SetToken(token)
		return c.JSON(token)
	})
	app.Get("/try", func(c *fiber.Ctx) error {
		token := oauth2Client.Token()
		if token == nil {
			return c.Redirect("/")
		}
		response, err := oauth2Client.GET(context.Background(), "/test", map[string]string{})
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString(err.Error())
		}
		return c.SendString(response)
	})
	app.Get("/pwd", func(c *fiber.Ctx) error {
		token, err := oauth2Client.PasswordCredentialsToken(context.Background(), "test", "test")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
		}
		oauth2Client.SetToken(token)
		return c.JSON(token)
	})
	app.Get("/client", func(c *fiber.Ctx) error {
		token, err := oauth2Client.ClientCredentialsToken(context.Background())
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
		}
		return c.JSON(token)
	})
	log.Fatal(app.Listen(":9094"))
}

func getAuthParam(codeVerifier string) []oauth2.AuthCodeOption {
	codeChallenge := genCodeChallengeS256(codeVerifier)
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
}

// genCodeChallengeS256 generates a S256 code challenge
func genCodeChallengeS256(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func getExchangeToken(codeVerifier string) []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	}
}
