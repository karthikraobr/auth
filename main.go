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
	authMgr, err := auth.NewManager(ctx, auth.WithProviderUrl(provider_url), auth.WithSkipClientIDCheck(true))
	if err != nil {
		panic(err)
	}
	http.Handle("/", authMgr.Middleware(http.HandlerFunc(dumpHandler)))
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
