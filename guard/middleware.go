package guard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

var (
	// ErrAuthorizationHeaderMalformed indicates that 'Authorization' header is malformed
	ErrAuthorizationHeaderMalformed = errors.New("guard: malformed authorization header")
	ErrProviderURLNotSet            = errors.New("guard: provider url not set")
)

type Manager struct {
	verifier         *oidc.IDTokenVerifier
	skipVerification bool
}

type config struct {
	providerURL       string
	skipClientIDCheck bool
	skipExpiryCheck   bool
	skipIssuerCheck   bool
	skipVerification  bool
}

// Option represents a function that can be provided as a parameter to NewAuthManager.
type Option func(*config)

func WithProviderUrl(providerURL string) Option {
	return func(c *config) {
		c.providerURL = providerURL
	}
}

func WithSkipClientIDCheck(skip bool) Option {
	return func(c *config) {
		c.skipClientIDCheck = skip
	}
}

func WithSkipExpiryCheck(skip bool) Option {
	return func(c *config) {
		c.skipExpiryCheck = skip
	}
}

func WithSkipIssuerCheck(skip bool) Option {
	return func(c *config) {
		c.skipIssuerCheck = skip
	}
}

func WithSkipVerification(skip bool) Option {
	return func(c *config) {
		c.skipVerification = skip
	}
}

func WithGCPProjectID(projectID string) Option {
	return func(c *config) {
		c.providerURL = "https://securetoken.google.com/" + projectID
	}
}

func NewManager(ctx context.Context, o ...Option) (*Manager, error) {
	var c config
	for _, o := range o {
		o(&c)
	}
	if c.providerURL == "" {
		return nil, ErrProviderURLNotSet
	}
	provider, err := oidc.NewProvider(ctx, c.providerURL)
	if err != nil {
		return nil, fmt.Errorf("auth: failed to created provider %w", err)
	}

	return &Manager{
		verifier: provider.Verifier(&oidc.Config{
			SkipClientIDCheck: c.skipClientIDCheck,
			SkipExpiryCheck:   c.skipExpiryCheck,
			SkipIssuerCheck:   c.skipIssuerCheck,
		}),
		skipVerification: c.skipVerification,
	}, nil
}

// Middleware extracts the JWT token from the HTTP header and puts the email and the externalID in the context.
// Use the EmailFromContext and ExternalIDFromContext functions to get the email and externalID from the context.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token, err := getToken(r.Header)
		if err != nil {
			ret(m.skipVerification, err, next, w, r)
			return
		}
		idToken, err := m.verifier.Verify(ctx, token)
		if err != nil {
			ret(m.skipVerification, err, next, w, r)
			return
		}
		claims := struct {
			Email      string `json:"email"`
			ExternalID string `json:"user_id"`
		}{}
		if err := idToken.Claims(&claims); err != nil {
			ret(m.skipVerification, err, next, w, r)
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

func ret(skipVerification bool, err error, next http.Handler, w http.ResponseWriter, r *http.Request) {
	if skipVerification {
		next.ServeHTTP(w, r)
		return
	}
	http.Error(w, err.Error(), http.StatusUnauthorized)
}
