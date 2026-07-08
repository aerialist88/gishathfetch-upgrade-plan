// Package main implements a small HTTP server that exposes controller.Search
// at /api/search for use by the local Flask app in gishath-local-v2.
//
// It deliberately calls controller.Search directly rather than reusing
// handler.Search, because the Lambda handler overrides the search string to
// "Opt" (and forces a fixed store list) when ENV is not "prod"/"staging" (see
// handler/search.go) — a guardrail meant for cloud smoke tests, not local use.
//
// Wire format mirrors the upstream Lambda response so the engine looks the
// same from both call sites:
//
//	GET /api/search?s=<urlencoded card>&lgs=<optional CSV of store names>
//	200 -> { "data": [<Card>...], "errors": [<StoreError>...] }
//	400 -> if s is missing or shorter than 3 characters
//
// Health check:
//
//	GET /healthz -> 200 "ok"
//
// Port is read from GISHATH_ENGINE_PORT (default 8080). Bind address is
// 127.0.0.1 only — this is a single-user local tool, not a public service.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"mtg-price-checker-sg/controller"
	"mtg-price-checker-sg/pkg/config"

	"github.com/joho/godotenv"
)

const (
	defaultPort      = "8080"
	requestDeadline  = 30 * time.Second
	readWriteTimeout = 60 * time.Second
)

type searchResponse struct {
	Data   []controller.Card       `json:"data"`
	Errors []controller.StoreError `json:"errors"`
}

func init() {
	// .env is optional. Allows dropping in DEDICATED_PROXY_* / DYNAMIC_PROXY /
	// WEB_BOT_AUTH_* etc. later without code changes. Silent if missing.
	_ = godotenv.Load()
}

func main() {
	port := strings.TrimSpace(os.Getenv("GISHATH_ENGINE_PORT"))
	if port == "" {
		port = defaultPort
	}
	addr := "127.0.0.1:" + port

	mux := http.NewServeMux()
	mux.HandleFunc("/api/search", searchHandler)
	mux.HandleFunc("/healthz", healthzHandler)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  readWriteTimeout,
		WriteTimeout: readWriteTimeout,
	}

	log.Printf("gishath-engine listening on http://%s (PerSiteTimeout=%s)", addr, config.PerSiteTimeout)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}

func healthzHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func searchHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	searchString, err := url.QueryUnescape(strings.TrimSpace(r.URL.Query().Get("s")))
	if err != nil || searchString == "" || len(searchString) < config.MinSearchStringLength {
		http.Error(w, "missing or too-short search string (param: s, min 3 chars)", http.StatusBadRequest)
		return
	}

	var lgs []string
	if raw, err := url.QueryUnescape(strings.TrimSpace(r.URL.Query().Get("lgs"))); err == nil && raw != "" {
		for _, name := range strings.Split(raw, ",") {
			if trimmed := strings.TrimSpace(name); trimmed != "" {
				lgs = append(lgs, trimmed)
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestDeadline)
	defer cancel()

	cards, storeErrors, err := controller.Search(ctx, controller.SearchInput{
		SearchString: searchString,
		Lgs:          lgs,
	})
	if err != nil {
		log.Printf("controller.Search failed for [%s]: %v", searchString, err)
		http.Error(w, "search failed", http.StatusInternalServerError)
		return
	}

	if storeErrors == nil {
		storeErrors = []controller.StoreError{}
	}
	if cards == nil {
		cards = []controller.Card{}
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(searchResponse{Data: cards, Errors: storeErrors}); err != nil {
		log.Printf("json encode failed for [%s]: %v", searchString, err)
		http.Error(w, "encoding failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}
