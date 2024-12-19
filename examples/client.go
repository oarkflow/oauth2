package main

import (
	"context"
	"github.com/oarkflow/oauth2/examples/providers/custom"
	"log"

	"github.com/gofiber/fiber/v2"
	"github.com/oarkflow/oauth2/client"
)

func main() {
	app := fiber.New()
	customClient := custom.Default("http://localhost:9094", "222222", "22222222")
	oauth2Client := client.New("http://localhost:9096", customClient.BaseURL, customClient.Config)
	app.Get("/", func(c *fiber.Ctx) error {
		authURL := oauth2Client.AuthCodeURL("xyz", customClient.GetAuthParams()...)
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
		token, err := oauth2Client.Exchange(context.Background(), code, customClient.GetExchangeToken()...)
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
