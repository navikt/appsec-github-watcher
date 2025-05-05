package handlers

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/navikt/appsec-github-watcher/internal/models"
)

func generateHMAC(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestNewMemberHandler_MethodNotAllowed(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	NewMemberHandler(rr, req, "secret")
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status %d, got %d", http.StatusMethodNotAllowed, rr.Code)
	}
}

func TestNewMemberHandler_MissingSignature(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rr := httptest.NewRecorder()
	NewMemberHandler(rr, req, "secret")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestNewMemberHandler_InvalidHMAC(t *testing.T) {
	body := []byte(`{"action":"member_added"}`)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", "sha256=invalidsignature")
	rr := httptest.NewRecorder()
	NewMemberHandler(rr, req, "secret")
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected status %d, got %d", http.StatusUnauthorized, rr.Code)
	}
}

func TestNewMemberHandler_InvalidJSON(t *testing.T) {
	body := []byte(`{invalid json}`)
	secret := "secret"
	signature := generateHMAC(body, secret)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
	req.Header.Set("X-Hub-Signature-256", signature)
	rr := httptest.NewRecorder()
	NewMemberHandler(rr, req, secret)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func TestNewMemberHandler_ValidMemberAdded(t *testing.T) {
	payload := models.GitHubPayload{
		Action: "member_added",
		Membership: models.GithubMembership{
			User: models.GithubUser{
				Login: "testuser",
			},
			Role: "member",
		},
	}
	body, _ := json.Marshal(payload)
	secret := "secret"
	signature := generateHMAC(body, secret)
	req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(bytes.NewReader(body)))
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("X-GitHub-Event", "membership")
	rr := httptest.NewRecorder()
	NewMemberHandler(rr, req, secret)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Body.String() != "Message received" {
		t.Errorf("expected body %q, got %q", "Message received", rr.Body.String())
	}
}

func TestNewMemberHandler_ValidOwnerAdded(t *testing.T) {
	payload := models.GitHubPayload{
		Action: "member_added",
		Membership: models.GithubMembership{
			User: models.GithubUser{
				Login: "owneruser",
			},
			Role: "owner",
		},
	}
	body, _ := json.Marshal(payload)
	secret := "secret"
	signature := generateHMAC(body, secret)
	req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(bytes.NewReader(body)))
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("X-GitHub-Event", "membership")
	rr := httptest.NewRecorder()
	NewMemberHandler(rr, req, secret)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Body.String() != "Message received" {
		t.Errorf("expected body %q, got %q", "Message received", rr.Body.String())
	}
}

func TestNewMemberHandler_ValidMemberRemoved(t *testing.T) {
	payload := models.GitHubPayload{
		Action: "member_removed",
		Membership: models.GithubMembership{
			User: models.GithubUser{
				Login: "testuser",
			},
			Role: "member",
		},
	}
	body, _ := json.Marshal(payload)
	secret := "secret"
	signature := generateHMAC(body, secret)
	req := httptest.NewRequest(http.MethodPost, "/", io.NopCloser(bytes.NewReader(body)))
	req.Header.Set("X-Hub-Signature-256", signature)
	req.Header.Set("X-GitHub-Event", "membership")
	rr := httptest.NewRecorder()
	NewMemberHandler(rr, req, secret)
	if rr.Code != http.StatusOK {
		t.Errorf("expected status %d, got %d", http.StatusOK, rr.Code)
	}
	if rr.Body.String() != "Message received" {
		t.Errorf("expected body %q, got %q", "Message received", rr.Body.String())
	}
}
