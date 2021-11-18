package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc"
)

var (
	// ErrAuthorizationHeaderMalformed indicates that 'Authorization' header is malformed
	ErrAuthorizationHeaderMalformed = errors.New("auth: malformed authorization header")
	ErrProviderURLNotSet            = errors.New("auth: provider url not set")
)

type AuthManager struct {
	verifier *oidc.IDTokenVerifier
}

type config struct {
	skipClientIDCheck bool
	skipExpiryCheck   bool
	skipIssuerCheck   bool
	providerURL       string
}

// AuthOption represents a function that can be provided as a parameter to NewAuthManager.
type AuthOption func(*config)

func WithProviderUrl(providerURL string) AuthOption {
	return func(c *config) {
		c.providerURL = providerURL
	}
}

func WithSkipClientIDCheck(skip bool) AuthOption {
	return func(c *config) {
		c.skipClientIDCheck = skip
	}
}
func WithSkipExpiryCheck(skip bool) AuthOption {
	return func(c *config) {
		c.skipExpiryCheck = skip
	}
}

func WithSkipIssuerCheck(skip bool) AuthOption {
	return func(c *config) {
		c.skipIssuerCheck = skip
	}
}

func NewAuthManager(ctx context.Context, o ...AuthOption) (*AuthManager, error) {
	var c config
	for _, o := range o {
		o(&c)
	}
	if c.providerURL == "" {
		return nil, ErrProviderURLNotSet
	}
	provider, err := oidc.NewProvider(ctx, c.providerURL)
	if err != nil {
		return nil, err
	}
	return &AuthManager{
		verifier: provider.Verifier(&oidc.Config{
			SkipClientIDCheck: c.skipClientIDCheck,
			SkipExpiryCheck:   c.skipExpiryCheck,
			SkipIssuerCheck:   c.skipIssuerCheck,
		}),
	}, nil
}

// AuthMiddleware is a middleware that extracts the JWT token from the HTTP and puts the email and the externalID in the context.
// Use the EmailFromContext and ExternalIDFromContext functions to get the email and externalID from the context.
func (a *AuthManager) AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token, err := getToken(r.Header)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
		}
		idToken, err := a.verifier.Verify(ctx, token)
		if err != nil {
			http.Error(w, fmt.Sprintf("failed to verify token: %v", err), http.StatusUnauthorized)
			return
		}
		claims := struct {
			Email      string `json:"email"`
			ExternalID string `json:"user_id"`
		}{}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, fmt.Sprintf("failed to get expected claims: %v", err), http.StatusInternalServerError)
			return
		}
		emailContext := NewEmailContext(ctx, claims.Email)
		externalIDContext := NewExternalIDContext(emailContext, claims.ExternalID)
		next.ServeHTTP(w, r.WithContext(externalIDContext))
	})
}

// getToken extracts the JWT token from the HTTP Authorisation header, expecting it
// to start with 'Bearer ', splitting it on space
func getToken(header http.Header) (string, error) {
	auth := header.Get("Authorization")
	// expecting Bearer xxx here
	parts := strings.Split(auth, " ")
	if len(parts) < 2 || len(parts[1]) == 0 {
		return "", ErrAuthorizationHeaderMalformed
	}
	return parts[1], nil
}
