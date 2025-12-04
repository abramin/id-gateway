package httptransport

import (
	"context"
	"encoding/json"
	"net/http"

	authModel "id-gateway/internal/auth/models"
	httpErrors "id-gateway/pkg/http-errors"
)

/*
	This handler starts an auth session.

**Expected Flow:**
1. Parse JSON request body: `{ "email": "user@example.com", "client_id": "demo-client" }`
2. Find or create user by email
3. Create a session
4. Return session ID

**Hints:**
- You'll need access to `AuthService` - add it to the `Handler` struct in `router.go`
- Use `json.NewDecoder(r.Body).Decode()` to parse input
- Create a user if `FindUserByEmail` returns not found
- Save both user and session
- Return `{ "session_id": "..." }` as JSON

**Example response:**
```json

	{
	  "session_id": "sess_abc123",
	  "user_id": "user_xyz"
	}

```
*/

type AuthHandler struct {
	auth AuthService
}
type AuthService interface {
	Authorize(ctx context.Context, req *authModel.AuthorizationRequest) (*authModel.AuthorizationResult, error)
}

func NewAuthHandler(auth AuthService) *AuthHandler {
	return &AuthHandler{auth: auth}
}

func (h *AuthHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("/auth/authorize", method(http.MethodPost, h.handleAuthorize))
	mux.HandleFunc("/auth/token", method(http.MethodPost, h.handleToken))
}

func (h *AuthHandler) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	var req authModel.AuthorizationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, httpErrors.New(httpErrors.CodeInvalidInput, "invalid request body"))
		return
	}

	res, err := h.auth.Authorize(r.Context(), &req)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(map[string]string{
		"session_id":   res.SessionID,
		"redirect_uri": res.RedirectURI,
	})
	if err != nil {
		writeError(w, err)
		return
	}
}

func (h *AuthHandler) handleToken(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, "/auth/token")
}

func (h *AuthHandler) handleUserInfo(w http.ResponseWriter, r *http.Request) {
	h.notImplemented(w, "/auth/userinfo")
}

func (h *AuthHandler) notImplemented(w http.ResponseWriter, endpoint string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"message":  "TODO: implement handler",
		"endpoint": endpoint,
	})
}
