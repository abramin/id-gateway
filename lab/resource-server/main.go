package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type apiResponse struct {
	Message string                 `json:"message"`
	Claims  map[string]interface{} `json:"claims,omitempty"`
	Warning string                 `json:"warning,omitempty"`
	Header  map[string]interface{} `json:"header,omitempty"`
}

func main() {
	port := getenv("PORT", "9000")
	signingKey := getenv("JWT_SIGNING_KEY", "dev-secret-key-change-in-production")

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, apiResponse{Message: "ok"})
	})
	mux.HandleFunc("/api/data", func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "missing bearer token"})
			return
		}
		header, claims, err := parseAndVerify(token, []byte(signingKey))
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, apiResponse{Message: "token rejected", Warning: err.Error(), Header: header, Claims: claims})
			return
		}

		warning := "audience not checked; token accepted for any service"
		if _, ok := header["kid"]; !ok {
			warning += " (no kid present)"
		}

		writeJSON(w, http.StatusOK, apiResponse{
			Message: "token accepted by naive resource server",
			Claims:  claims,
			Header:  header,
			Warning: warning,
		})
	})
	mux.HandleFunc("/api/debug/claims", func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			writeJSON(w, http.StatusBadRequest, apiResponse{Message: "provide Authorization: Bearer <token>"})
			return
		}
		header, claims, err := parseAndVerify(token, []byte(signingKey))
		if err != nil {
			writeJSON(w, http.StatusOK, apiResponse{Message: "parsed with warnings", Claims: claims, Header: header, Warning: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, apiResponse{Message: "claims decoded", Claims: claims, Header: header, Warning: "signature checked; audience ignored"})
	})

	addr := fmt.Sprintf(":%s", port)
	log.Printf("toy resource server listening on %s", addr)
	srv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Fatal(srv.ListenAndServe())
}

func parseAndVerify(token string, key []byte) (map[string]interface{}, map[string]interface{}, error) {
	parts := strings.Split(token, ".")
	header := map[string]interface{}{}
	claims := map[string]interface{}{}
	if len(parts) != 3 {
		return header, claims, errors.New("invalid token format")
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err == nil {
		_ = json.Unmarshal(headerBytes, &header)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err == nil {
		_ = json.Unmarshal(payloadBytes, &claims)
	}

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return header, claims, errors.New("signature mismatch")
	}

	return header, claims, nil
}

func writeJSON(w http.ResponseWriter, status int, payload apiResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func bearerToken(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
