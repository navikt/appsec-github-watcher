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
	origBotToken := os.Getenv("SLACK_BOT_TOKEN")

	// Restore env vars after test
	defer func() {
		os.Setenv("SLACK_BOT_TOKEN", origBotToken)
		// Reset the mock endpoint after tests
		mockOAuthEndpoint = ""
	}()

	t.Run("returns error when bot token is missing", func(t *testing.T) {
		os.Setenv("SLACK_BOT_TOKEN", "")

		_, err := getOAuthToken()
		if err == nil {
			t.Fatal("expected error when bot token is missing")
		}
		if !strings.Contains(err.Error(), "missing required environment variable: SLACK_BOT_TOKEN") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("returns bot token when provided", func(t *testing.T) {
		// Set test environment variables
		os.Setenv("SLACK_BOT_TOKEN", "xoxb-test-bot-token")

		// Call the function
		token, err := getOAuthToken()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if token != "xoxb-test-bot-token" {
			t.Errorf("expected bot token, got: %s", token)
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

func TestGetUsergroupMembers(t *testing.T) {
	var (
		userGroupID     = "S999"
		groupMembers    = []string{"U111", "U222", "U333"}
		calledEndpoints = []string{}
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledEndpoints = append(calledEndpoints, r.URL.Path)

		if strings.Contains(r.URL.String(), "usergroups.users.list") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"users": groupMembers,
			})
			return
		}

		// Default response for unhandled requests
		t.Logf("Unhandled request: %s", r.URL.String())
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer ts.Close()

	api := slack.New("token",
		slack.OptionHTTPClient(ts.Client()),
		slack.OptionAPIURL(ts.URL+"/"))
	client := &slackClient{api: api}

	// Test successful call
	result, err := client.GetUsergroupMembers(userGroupID)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(calledEndpoints) != 1 {
		t.Errorf("expected 1 API call, got %d: %v", len(calledEndpoints), calledEndpoints)
	}

	if len(result.Users) != len(groupMembers) {
		t.Errorf("expected %d users, got %d", len(groupMembers), len(result.Users))
	}

	// Check that all group members are included in the result
	for i, member := range groupMembers {
		if result.Users[i] != member {
			t.Errorf("expected user ID %s at position %d, got %s", member, i, result.Users[i])
		}
	}
}

func TestGetUserIDsByEmails(t *testing.T) {
	var (
		emails = []string{
			"user1@example.com",
			"user2@example.com",
			"unknown@example.com", // This one will return "not found"
			"user3@example.com",
		}
		userMap = map[string]string{
			"user1@example.com": "U111",
			"user2@example.com": "U222",
			"user3@example.com": "U333",
		}
		notFoundEmail = "unknown@example.com"
	)

	// Create a client without a mock server to test directly with our lookup function
	client := &slackClient{api: slack.New("dummy-token")}

	// Call our custom method with a mock lookup function that simulates the Slack API
	userIDs, notFound, err := client.GetUserIDsByEmailsWithLookup(emails, func(email string) (*slack.User, error) {
		if email == notFoundEmail {
			return nil, fmt.Errorf("users_not_found")
		}

		userID, exists := userMap[email]
		if exists {
			return &slack.User{ID: userID}, nil
		}

		return nil, fmt.Errorf("users_not_found")
	})

	// Test results
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Should find 3 user IDs
	expectedFoundCount := 3
	if len(userIDs) != expectedFoundCount {
		t.Errorf("expected %d user IDs, got %d", expectedFoundCount, len(userIDs))
	}

	// Should have 1 not found email
	expectedNotFoundCount := 1
	if len(notFound) != expectedNotFoundCount {
		t.Errorf("expected %d not found emails, got %d: %v", expectedNotFoundCount, len(notFound), notFound)
	}

	if len(notFound) > 0 && notFound[0] != notFoundEmail {
		t.Errorf("expected not found email to be %s, got %s", notFoundEmail, notFound[0])
	}

	// Check that all found user IDs are correct
	foundMap := make(map[string]bool)
	for _, id := range userIDs {
		foundMap[id] = true
	}

	for email, expectedID := range userMap {
		if email != notFoundEmail && !foundMap[expectedID] {
			t.Errorf("expected to find user ID %s for email %s, but it was not in the result", expectedID, email)
		}
	}
}

func TestUpdateUsergroupMembers(t *testing.T) {
	var (
		userGroupID     = "S999"
		userIDs         = []string{"U111", "U222", "U333"}
		calledEndpoints = []string{}
		requestBodies   = make(map[string]string)
	)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledEndpoints = append(calledEndpoints, r.URL.Path)

		if r.Method == http.MethodPost && strings.Contains(r.URL.String(), "usergroups.users.update") {
			// Check that the request body contains our user IDs
			if err := r.ParseForm(); err == nil {
				requestBodies[r.URL.Path] = r.Form.Get("users")
			}

			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
			})
			return
		}

		// Default response for unhandled requests
		t.Logf("Unhandled request: %s", r.URL.String())
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
	}))
	defer ts.Close()

	api := slack.New("token",
		slack.OptionHTTPClient(ts.Client()),
		slack.OptionAPIURL(ts.URL+"/"))
	client := &slackClient{api: api}

	// Test successful update
	err := client.UpdateUsergroupMembers(userGroupID, userIDs)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(calledEndpoints) != 1 {
		t.Errorf("expected 1 API call, got %d: %v", len(calledEndpoints), len(calledEndpoints))
	}

	// Check that the update request contained the right user IDs
	for path, body := range requestBodies {
		if strings.Contains(path, "usergroups.users.update") {
			expectedBody := strings.Join(userIDs, ",")
			if body != expectedBody {
				t.Errorf("expected request body to be %s, got %s", expectedBody, body)
			}
		}
	}

	// Test with empty user list (should return error)
	err = client.UpdateUsergroupMembers(userGroupID, []string{})
	if err == nil {
		t.Errorf("expected error when updating with empty user list, got nil")
	}
}
