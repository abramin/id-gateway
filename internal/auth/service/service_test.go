package service

//go:generate mockgen -source=service.go -destination=mocks/mocks.go -package=mocks UserStore,SessionStoreimport
import (
	"context"
	"id-gateway/internal/auth/models"
	"id-gateway/internal/auth/service/mocks"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
)

func TestService_Authorize(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockUserStore := mocks.NewMockUserStore(ctrl)
	mockSessionStore := mocks.NewMockSessionStore(ctrl)

	service := NewService(mockUserStore, mockSessionStore)

	req := models.AuthorizationRequest{
		ClientID:    "client-123",
		Scopes:      []string{"openid", "profile"},
		RedirectURI: "https://client.app/callback",
		State:       "xyz",
		Email:       "email@test.com",
	}

	result, err := service.Authorize(context.Background(), &req)
	assert.NoError(t, err)
	assert.Equal(t, "todo-session-id", result.SessionID)
	assert.Equal(t, "user_xyz", result.UserID)
}
