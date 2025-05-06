package slack

import (
	"encoding/json"
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
	origClientID := os.Getenv("SLACK_APP_CLIENT_ID")
	origClientSecret := os.Getenv("SLACK_APP_SECRET")
	origRefreshToken := os.Getenv("SLACK_REFRESH_TOKEN")

	// Restore env vars after test
	defer func() {
		os.Setenv("SLACK_APP_CLIENT_ID", origClientID)
		os.Setenv("SLACK_APP_SECRET", origClientSecret)
		os.Setenv("SLACK_REFRESH_TOKEN", origRefreshToken)
	}()

	t.Run("returns error when client ID missing", func(t *testing.T) {
		os.Setenv("SLACK_APP_CLIENT_ID", "")
		os.Setenv("SLACK_APP_SECRET", "")
		os.Setenv("SLACK_REFRESH_TOKEN", "")

		_, err := GetOAuthToken()
		if err == nil {
			t.Fatal("expected error when credentials missing")
		}
	})

	t.Run("returns error when refresh token missing", func(t *testing.T) {
		os.Setenv("SLACK_APP_CLIENT_ID", "test-client-id")
		os.Setenv("SLACK_APP_SECRET", "test-client-secret")
		os.Setenv("SLACK_REFRESH_TOKEN", "")

		_, err := GetOAuthToken()
		if err == nil {
			t.Fatal("expected error when refresh token missing")
		}
		if err.Error() != "missing required environment variable: SLACK_REFRESH_TOKEN" {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	// Note: Testing the actual refresh token flow requires mocking the OAuth2 token endpoint
	// This would typically be done in an integration test or with a more complex test setup
}
