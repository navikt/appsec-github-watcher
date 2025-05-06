package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/navikt/appsec-github-watcher/internal/msgraph"
	"github.com/navikt/appsec-github-watcher/internal/slack"
)

// createMockSlackClient creates a mock Slack client for testing
func createMockSlackClient() *slack.MockSlackClient {
	return &slack.MockSlackClient{
		AddedEmails:   []string{},
		RemovedEmails: []string{},
	}
}

// createMockEmailClient creates a mock Email client for testing
func createMockEmailClient() *msgraph.MockEmailClient {
	return &msgraph.MockEmailClient{
		SentEmails: []msgraph.SentEmail{},
	}
}

func generateHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestNewMemberHandler_MethodNotAllowed(t *testing.T) {
	mockSlack := createMockSlackClient()
	mockEmail := createMockEmailClient()
	ctx := HandlerContext{
		SlackClient:   mockSlack,
		EmailClient:   mockEmail,
		UserGroupID:   "test-group",
		WebhookSecret: "secret",
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	ctx.NewMemberHandler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestNewMemberHandler_MissingSignature(t *testing.T) {
	mockSlack := createMockSlackClient()
	mockEmail := createMockEmailClient()
	ctx := HandlerContext{
		SlackClient:   mockSlack,
		EmailClient:   mockEmail,
		UserGroupID:   "test-group",
		WebhookSecret: "secret",
	}

	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()

	ctx.NewMemberHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestNewMemberHandler_InvalidHMAC(t *testing.T) {
	mockSlack := createMockSlackClient()
	mockEmail := createMockEmailClient()
	ctx := HandlerContext{
		SlackClient:   mockSlack,
		EmailClient:   mockEmail,
		UserGroupID:   "test-group",
		WebhookSecret: "secret",
	}

	body := []byte(`{"action":"member_added"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256=invalidsignature")
	rr := httptest.NewRecorder()

	ctx.NewMemberHandler(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestNewMemberHandler_InvalidJSON(t *testing.T) {
	mockSlack := createMockSlackClient()
	mockEmail := createMockEmailClient()
	ctx := HandlerContext{
		SlackClient:   mockSlack,
		EmailClient:   mockEmail,
		UserGroupID:   "test-group",
		WebhookSecret: "secret",
	}

	body := []byte(`{invalid json}`)
	secret := "secret"
	signature := generateHMAC(body, secret)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", signature)
	rr := httptest.NewRecorder()

	ctx.NewMemberHandler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestClientsErrors(t *testing.T) {
	t.Run("handles Slack AddUserToUserGroup error", func(t *testing.T) {
		mockSlack := createMockSlackClient()
		mockSlack.AddUserError = errors.New("slack error")
		// We can't fully test the member_added flow without mocking the GraphQL client
	})

	t.Run("handles Slack RemoveUserFromUserGroup error", func(t *testing.T) {
		mockSlack := createMockSlackClient()
		mockSlack.RemoveUserError = errors.New("slack error")
		// We can't fully test the member_removed flow without mocking the GraphQL client
	})

	t.Run("handles Email SendWelcomeEmail error", func(t *testing.T) {
		mockEmail := createMockEmailClient()
		mockEmail.SendEmailError = errors.New("email error")
		// We can't fully test the email flow without mocking the GraphQL client
	})
}
