package slack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/slack-go/slack"
)

// Mock OAuth token endpoint handler
func createMockOAuthServer(t *testing.T, wantSuccess bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth.v2.access" {
			// Set headers to simulate Slack's response, including signature headers
			w.Header().Set("X-Slack-Signature", "v0=mock-signature")
			w.Header().Set("X-Slack-Request-Timestamp", "1234567890")

			if !wantSuccess {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"ok":    false,
					"error": "invalid_client_secret",
				})
				return
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":           true,
				"access_token": "xoxb-mock-token-12345",
				"token_type":   "bot",
			})
		} else {
			// Handle unexpected requests
			t.Logf("Unhandled request to mock oauth server: %s", r.URL.String())
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestAddUserToUserGroup(t *testing.T) {
	// simulate Slack server
	var (
		userEmail       = "foo@example.com"
		userID          = "U123"
		userGroupID     = "S999"
		currentMembers  = []string{"U111", "U222"}
		calledEndpoints = []string{}
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log full URL and method
		t.Logf("Request: %s %s", r.Method, r.URL.String())

		calledEndpoints = append(calledEndpoints, r.URL.Path)

		// Return a more generic response regardless of the path
		if strings.Contains(r.URL.String(), "users.lookupByEmail") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"user": map[string]string{"id": userID},
			})
			return
		}

		if strings.Contains(r.URL.String(), "usergroups.users.list") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"users": currentMembers,
			})
			return
		}

		if strings.Contains(r.URL.String(), "usergroups.users.update") {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
			return
		}

		// Fallback to log the unmatched request and serve a default response
		t.Logf("Unhandled request: %s", r.URL.String())
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer ts.Close()

	// create client pointing at test server
	api := slack.New("token",
		slack.OptionHTTPClient(ts.Client()),
		slack.OptionAPIURL(ts.URL+"/"))
	client := &slackClient{api: api}

	if err := client.AddUserToUserGroup(userEmail, userGroupID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	// verify sequence of calls
	if len(calledEndpoints) != 3 {
		t.Errorf("expected 3 API calls, got %d: %v", len(calledEndpoints), calledEndpoints)
	}
}

func TestAddUserToUserGroup_AlreadyExists(t *testing.T) {
	// simulate Slack server where user is already in the group
	var (
		userEmail       = "foo@example.com"
		userID          = "U123"
		userGroupID     = "S999"
		currentMembers  = []string{"U123", "U222"} // User is already a member
		calledEndpoints = []string{}
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledEndpoints = append(calledEndpoints, r.URL.Path)

		if strings.Contains(r.URL.String(), "users.lookupByEmail") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"user": map[string]string{"id": userID},
			})
			return
		}

		if strings.Contains(r.URL.String(), "usergroups.users.list") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"users": currentMembers,
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer ts.Close()

	api := slack.New("token",
		slack.OptionHTTPClient(ts.Client()),
		slack.OptionAPIURL(ts.URL+"/"))
	client := &slackClient{api: api}

	if err := client.AddUserToUserGroup(userEmail, userGroupID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should only see 2 calls (lookup user and get members), but no update call
	if len(calledEndpoints) != 2 {
		t.Errorf("expected 2 API calls, got %d: %v", len(calledEndpoints), calledEndpoints)
	}
}

func TestRemoveUserFromUserGroup(t *testing.T) {
	// simulate Slack server
	var (
		userEmail       = "bar@example.com"
		userID          = "U555"
		userGroupID     = "S123"
		currentMembers  = []string{"U555", "U777", "U888"}
		calledEndpoints = []string{}
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Log full URL and method
		t.Logf("Request: %s %s", r.Method, r.URL.String())

		calledEndpoints = append(calledEndpoints, r.URL.Path)

		// Return a more generic response regardless of the path
		if strings.Contains(r.URL.String(), "users.lookupByEmail") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"user": map[string]string{"id": userID},
			})
			return
		}

		if strings.Contains(r.URL.String(), "usergroups.users.list") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"users": currentMembers,
			})
			return
		}

		if strings.Contains(r.URL.String(), "usergroups.users.update") {
			json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
			return
		}

		// Fallback to log the unmatched request and serve a default response
		t.Logf("Unhandled request: %s", r.URL.String())
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer ts.Close()

	api := slack.New("token",
		slack.OptionHTTPClient(ts.Client()),
		slack.OptionAPIURL(ts.URL+"/"))
	client := &slackClient{api: api}

	if err := client.RemoveUserFromUserGroup(userEmail, userGroupID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(calledEndpoints) != 3 {
		t.Errorf("expected 3 API calls, got %d: %v", len(calledEndpoints), calledEndpoints)
	}
}

func TestRemoveUserFromUserGroup_NotFound(t *testing.T) {
	// simulate Slack server where user is not in the group
	var (
		userEmail       = "bar@example.com"
		userID          = "U555"
		userGroupID     = "S123"
		currentMembers  = []string{"U777", "U888"} // User is not a member
		calledEndpoints = []string{}
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledEndpoints = append(calledEndpoints, r.URL.Path)

		if strings.Contains(r.URL.String(), "users.lookupByEmail") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"user": map[string]string{"id": userID},
			})
			return
		}

		if strings.Contains(r.URL.String(), "usergroups.users.list") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"users": currentMembers,
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer ts.Close()

	api := slack.New("token",
		slack.OptionHTTPClient(ts.Client()),
		slack.OptionAPIURL(ts.URL+"/"))
	client := &slackClient{api: api}

	if err := client.RemoveUserFromUserGroup(userEmail, userGroupID); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should only see 2 calls (lookup user and get members), but no update call
	if len(calledEndpoints) != 2 {
		t.Errorf("expected 2 API calls, got %d: %v", len(calledEndpoints), calledEndpoints)
	}
}

func TestGetOAuthToken(t *testing.T) {
	// Save original env vars to restore later
	origClientID := os.Getenv("SLACK_APP_CLIENT_ID")
	origClientSecret := os.Getenv("SLACK_APP_CLIENT_SECRET")
	origSigningSecret := os.Getenv("SLACK_APP_SIGNING_SECRET")

	// Restore env vars after test
	defer func() {
		os.Setenv("SLACK_APP_CLIENT_ID", origClientID)
		os.Setenv("SLACK_APP_CLIENT_SECRET", origClientSecret)
		os.Setenv("SLACK_APP_SIGNING_SECRET", origSigningSecret)
		// Reset the mock endpoint after tests
		mockOAuthEndpoint = ""
	}()

	t.Run("returns error when client ID or secret missing", func(t *testing.T) {
		os.Setenv("SLACK_APP_CLIENT_ID", "")
		os.Setenv("SLACK_APP_CLIENT_SECRET", "")
		os.Setenv("SLACK_APP_SIGNING_SECRET", "")

		_, err := getOAuthToken()
		if err == nil {
			t.Fatal("expected error when credentials missing")
		}
		if !strings.Contains(err.Error(), "missing required environment variables") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("handles successful token response", func(t *testing.T) {
		// Create a mock server for the OAuth endpoint
		mockServer := createMockOAuthServer(t, true)
		defer mockServer.Close()

		// Set the mock endpoint via the package variable
		mockOAuthEndpoint = mockServer.URL + "/oauth.v2.access"

		// Set test environment variables
		os.Setenv("SLACK_APP_CLIENT_ID", "test-client-id")
		os.Setenv("SLACK_APP_CLIENT_SECRET", "test-client-secret")
		os.Setenv("SLACK_APP_SIGNING_SECRET", "test-signing-secret")

		// Call the function
		token, err := getOAuthToken()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "xoxb-mock-token-12345" {
			t.Errorf("expected mock token, got: %s", token)
		}
	})

	t.Run("handles error response from Slack", func(t *testing.T) {
		// Create a mock server that returns an error
		mockServer := createMockOAuthServer(t, false)
		defer mockServer.Close()

		// Set the mock endpoint via the package variable
		mockOAuthEndpoint = mockServer.URL + "/oauth.v2.access"

		// Set test environment variables
		os.Setenv("SLACK_APP_CLIENT_ID", "test-client-id")
		os.Setenv("SLACK_APP_CLIENT_SECRET", "invalid-secret")
		os.Setenv("SLACK_APP_SIGNING_SECRET", "test-signing-secret")

		// Call the function
		_, err := getOAuthToken()
		if err == nil {
			t.Fatal("expected error when Slack returns error response")
		}
		if !strings.Contains(err.Error(), "slack oauth error") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("skips signature verification when signing secret not provided", func(t *testing.T) {
		// Create a mock server for the OAuth endpoint
		mockServer := createMockOAuthServer(t, true)
		defer mockServer.Close()

		// Set the mock endpoint via the package variable
		mockOAuthEndpoint = mockServer.URL + "/oauth.v2.access"

		// Set test environment variables (without signing secret)
		os.Setenv("SLACK_APP_CLIENT_ID", "test-client-id")
		os.Setenv("SLACK_APP_CLIENT_SECRET", "test-client-secret")
		os.Setenv("SLACK_APP_SIGNING_SECRET", "")

		// Call the function - should still work without signing verification
		token, err := getOAuthToken()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "xoxb-mock-token-12345" {
			t.Errorf("expected mock token, got: %s", token)
		}
	})
}

func TestVerifySlackSignature(t *testing.T) {
	// Test case with valid signature
	t.Run("valid signature", func(t *testing.T) {
		// Generate a valid signature for testing
		body := "test-body"
		timestamp := "1234567890"
		secret := "test-secret"

		// Create the base string like the verification method does
		baseString := fmt.Sprintf("v0:%s:%s", timestamp, body)

		// Calculate the HMAC-SHA256 signature
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(baseString))
		expectedSignature := fmt.Sprintf("v0=%s", hex.EncodeToString(mac.Sum(nil)))

		// Verify the signature
		result := verifySlackSignature(expectedSignature, timestamp, body, secret)
		if !result {
			t.Error("Expected signature to be valid, but verification failed")
		}
	})

	// Test case with invalid signature
	t.Run("invalid signature", func(t *testing.T) {
		body := "test-body"
		timestamp := "1234567890"
		signature := "v0=invalid-signature"
		secret := "test-secret"

		result := verifySlackSignature(signature, timestamp, body, secret)
		if result {
			t.Error("Expected signature to be invalid, but verification passed")
		}
	})

	// Test case with tampered body
	t.Run("tampered body", func(t *testing.T) {
		// First generate a valid signature for "test-body"
		originalBody := "test-body"
		tamperedBody := "tampered-body"
		timestamp := "1234567890"
		secret := "test-secret"

		// Create the base string for the original body
		baseString := fmt.Sprintf("v0:%s:%s", timestamp, originalBody)

		// Calculate the signature for the original body
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(baseString))
		signature := fmt.Sprintf("v0=%s", hex.EncodeToString(mac.Sum(nil)))

		// Verify using the tampered body
		result := verifySlackSignature(signature, timestamp, tamperedBody, secret)
		if result {
			t.Error("Expected signature to be invalid for tampered body, but verification passed")
		}
	})
}
