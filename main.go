package main

import (
	"context"
	"encoding/json"
	"jwt-test/auth"
	"net/http"
)

const (
	provider_url = "https://securetoken.google.com/flink-core-staging"
)

func main() {
	ctx := context.Background()
	authMgr, _ := auth.NewAuthManager(ctx, auth.WithProviderUrl(provider_url), auth.WithSkipClientIDCheck(true))
	http.Handle("/", authMgr.AuthMiddleware(http.HandlerFunc(dumpHandler)))
	http.ListenAndServe(":8080", nil)
}

func dumpHandler(w http.ResponseWriter, r *http.Request) {
	email, _ := auth.EmailFromContext(r.Context())
	externalID, _ := auth.ExternalIDFromContext(r.Context())
	b, _ := json.Marshal(struct {
		Email      string
		ExternalID string
	}{Email: email, ExternalID: externalID})
	w.Write(b)
}
