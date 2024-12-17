package oauth2

import "context"

type (
	// ClientStore the client information storage interface
	ClientStore interface {
		// GetByID according to the ID for the client information
		GetByID(ctx context.Context, id string) (ClientInfo, error)
	}

	// TokenStore the token information storage interface
	TokenStore interface {
		// Create - create and store the new token information
		Create(ctx context.Context, info TokenInfo) error

		// RemoveByCode delete the authorization code
		RemoveByCode(ctx context.Context, code string) error

		// RemoveByAccess use the access token to delete the token information
		RemoveByAccess(ctx context.Context, access string) error

		// RemoveByRefresh use the refresh token to delete the token information
		RemoveByRefresh(ctx context.Context, refresh string) error

		// GetByCode use the authorization code for token information data
		GetByCode(ctx context.Context, code string) (TokenInfo, error)

		// GetByAccess use the access token for token information data
		GetByAccess(ctx context.Context, access string) (TokenInfo, error)

		// GetByRefresh use the refresh token for token information data
		GetByRefresh(ctx context.Context, refresh string) (TokenInfo, error)
	}
)
