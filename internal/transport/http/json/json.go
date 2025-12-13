package json

import (
	"encoding/json"
	"net/http"
)

func WriteJSON(w http.ResponseWriter, status int, response any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		// best-effort fallback; don’t override status for the caller
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}
