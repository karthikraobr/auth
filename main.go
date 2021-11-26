package main

import (
	"context"
	"encoding/json"
	"jwt-test/guard"
	"net/http"
)

func main() {
	ctx := context.Background()
	authMgr, err := guard.NewManager(ctx, guard.WithGCPProjectID("flink-core-staging"), guard.WithSkipClientIDCheck(true))
	if err != nil {
		panic(err)
	}
	http.Handle("/", authMgr.Middleware(http.HandlerFunc(dumpHandler)))
	http.ListenAndServe(":8080", nil)
}

func dumpHandler(w http.ResponseWriter, r *http.Request) {
	email, _ := guard.EmailFromContext(r.Context())
	externalID, _ := guard.ExternalIDFromContext(r.Context())
	b, _ := json.Marshal(struct {
		Email      string
		ExternalID string
	}{Email: email, ExternalID: externalID})
	w.Write(b)
}
