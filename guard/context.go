package guard

import (
	"context"
)

type emailkey struct{}

var emailContextKey = emailkey{}

// NewEmailContext returns a new Context that carries the user claims
func NewEmailContext(ctx context.Context, email string) context.Context {
	return context.WithValue(ctx, emailContextKey, email)
}

// EmailFromContext returns the user claims stored in context, if any.
func EmailFromContext(ctx context.Context) (string, bool) {
	email, ok := ctx.Value(emailContextKey).(string)
	return email, ok
}

type externalIDkey struct{}

var externalIDContextKey = externalIDkey{}

// NewExternalIDContext returns a new Context that carries the user claims
func NewExternalIDContext(ctx context.Context, externalID string) context.Context {
	return context.WithValue(ctx, externalIDContextKey, externalID)
}

// ExternalIDFromContext returns the user claims stored in context, if any.
func ExternalIDFromContext(ctx context.Context) (string, bool) {
	externalID, ok := ctx.Value(externalIDContextKey).(string)
	return externalID, ok
}
