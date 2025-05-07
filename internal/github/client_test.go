// client_test.go
package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/shurcooL/githubv4"
)

// roundTripFunc allows customizing request handling for http.Client.Transport.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFetchSAMLNameID(t *testing.T) {
	t.Run("returns nameId when present", func(t *testing.T) {
		// Setup test GraphQL server
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"edges":[{"node":{"samlIdentity":{"nameId":"expected-id"}}}]}}}}}`)
		}))
		defer ts.Close()

		// Rewrite requests to test server
		httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u, _ := url.Parse(ts.URL + req.URL.Path)
			req.URL = u
			return http.DefaultTransport.RoundTrip(req)
		})}
		client := githubv4.NewClient(httpClient)

		id, err := FetchSAMLNameID(context.Background(), client, "org", "user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "expected-id" {
			t.Errorf("got %q, want %q", id, "expected-id")
		}
	})

	t.Run("returns empty when no edges", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"edges":[]}}}}}`)
		}))
		defer ts.Close()

		httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u, _ := url.Parse(ts.URL + req.URL.Path)
			req.URL = u
			return http.DefaultTransport.RoundTrip(req)
		})}
		client := githubv4.NewClient(httpClient)

		id, err := FetchSAMLNameID(context.Background(), client, "org", "user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "" {
			t.Errorf("got %q, want empty string", id)
		}
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `invalid json`)
		}))
		defer ts.Close()

		httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u, _ := url.Parse(ts.URL + req.URL.Path)
			req.URL = u
			return http.DefaultTransport.RoundTrip(req)
		})}
		client := githubv4.NewClient(httpClient)

		_, err := FetchSAMLNameID(context.Background(), client, "org", "user")
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}

func TestGetOrgAdmins(t *testing.T) {
	// Save original env vars to restore later
	originalAppID := os.Getenv("GITHUB_APP_ID")
	originalInstallID := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	originalPrivateKey := os.Getenv("GITHUB_APP_PRIVATE_KEY")

	// Set mock env vars for testing
	os.Setenv("GITHUB_APP_ID", "12345")
	os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
	os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")

	// Create a mock HTTP server that will stand in for the GitHub API
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify the request path and parameters
		if r.URL.Path != "/orgs/testorg/members" || r.URL.Query().Get("role") != "admin" {
			t.Errorf("Expected request to '/orgs/testorg/members?role=admin', got: %s", r.URL.String())
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Verify request headers
		if r.Header.Get("Accept") != "application/vnd.github.v3+json" {
			t.Errorf("Expected Accept header to be 'application/vnd.github.v3+json', got: %s", r.Header.Get("Accept"))
		}

		// Return a mock response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[
			{"login": "admin1", "id": 1001},
			{"login": "admin2", "id": 1002},
			{"login": "admin3", "id": 1003}
		]`))
	}))
	defer mockServer.Close()

	// Create a test client that uses our mock server
	client := &RestClient{
		client: mockServer.Client(),
	}

	// Override the URL to use our mock server
	originalGetOrgAdmins := getOrgAdminsURL
	getOrgAdminsURL = func(org string) string {
		return mockServer.URL + "/orgs/" + org + "/members?role=admin"
	}
	defer func() { getOrgAdminsURL = originalGetOrgAdmins }()

	// Test the GetOrgAdmins function
	admins, err := client.GetOrgAdmins("testorg")
	if err != nil {
		t.Fatalf("GetOrgAdmins returned an error: %v", err)
	}

	// Check that we got the expected admins
	expectedAdmins := []string{"admin1", "admin2", "admin3"}
	if len(admins) != len(expectedAdmins) {
		t.Fatalf("Expected %d admins, got %d", len(expectedAdmins), len(admins))
	}

	for i, admin := range admins {
		if admin != expectedAdmins[i] {
			t.Errorf("Expected admin %d to be '%s', got '%s'", i, expectedAdmins[i], admin)
		}
	}

	// Restore original env vars
	if originalAppID != "" {
		os.Setenv("GITHUB_APP_ID", originalAppID)
	} else {
		os.Unsetenv("GITHUB_APP_ID")
	}
	if originalInstallID != "" {
		os.Setenv("GITHUB_APP_INSTALLATION_ID", originalInstallID)
	} else {
		os.Unsetenv("GITHUB_APP_INSTALLATION_ID")
	}
	if originalPrivateKey != "" {
		os.Setenv("GITHUB_APP_PRIVATE_KEY", originalPrivateKey)
	} else {
		os.Unsetenv("GITHUB_APP_PRIVATE_KEY")
	}
}

func TestNewRestClient(t *testing.T) {
	// Save original env vars to restore later
	originalAppID := os.Getenv("GITHUB_APP_ID")
	originalInstallID := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	originalPrivateKey := os.Getenv("GITHUB_APP_PRIVATE_KEY")

	tests := []struct {
		name      string
		setupEnv  func()
		wantError bool
		errorMsg  string
	}{
		{
			name: "Valid configuration",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "12345")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: true, // This will error out in real testing due to invalid key, but shows the test pattern
			errorMsg:  "failed to create GitHub installation transport",
		},
		{
			name: "Missing app ID",
			setupEnv: func() {
				os.Unsetenv("GITHUB_APP_ID")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: true,
			errorMsg:  "missing required environment variable: GITHUB_APP_ID",
		},
		{
			name: "Missing installation ID",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "12345")
				os.Unsetenv("GITHUB_APP_INSTALLATION_ID")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: true,
			errorMsg:  "missing required environment variable: GITHUB_APP_INSTALLATION_ID",
		},
		{
			name: "Missing private key",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "12345")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
				os.Unsetenv("GITHUB_APP_PRIVATE_KEY")
			},
			wantError: true,
			errorMsg:  "missing required environment variable: GITHUB_APP_PRIVATE_KEY",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment for this test
			tt.setupEnv()

			// Call the function
			client, err := NewRestClient()

			// Check if we expected an error
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && err.Error() != tt.errorMsg && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("Did not expect error but got: %v", err)
			}

			// If we didn't expect an error, make sure we got a client
			if !tt.wantError && client == nil {
				t.Error("Expected a client but got nil")
			}
		})
	}

	// Restore original env vars
	if originalAppID != "" {
		os.Setenv("GITHUB_APP_ID", originalAppID)
	} else {
		os.Unsetenv("GITHUB_APP_ID")
	}
	if originalInstallID != "" {
		os.Setenv("GITHUB_APP_INSTALLATION_ID", originalInstallID)
	} else {
		os.Unsetenv("GITHUB_APP_INSTALLATION_ID")
	}
	if originalPrivateKey != "" {
		os.Setenv("GITHUB_APP_PRIVATE_KEY", originalPrivateKey)
	} else {
		os.Unsetenv("GITHUB_APP_PRIVATE_KEY")
	}
}

func TestLoadGitHubAppConfig(t *testing.T) {
	// Save original env vars to restore later
	originalAppID := os.Getenv("GITHUB_APP_ID")
	originalInstallID := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	originalPrivateKey := os.Getenv("GITHUB_APP_PRIVATE_KEY")

	tests := []struct {
		name      string
		setupEnv  func()
		wantError bool
		errorMsg  string
	}{
		{
			name: "Valid configuration",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "12345")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: false,
		},
		{
			name: "Missing app ID",
			setupEnv: func() {
				os.Unsetenv("GITHUB_APP_ID")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: true,
			errorMsg:  "missing required environment variable: GITHUB_APP_ID",
		},
		{
			name: "Missing installation ID",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "12345")
				os.Unsetenv("GITHUB_APP_INSTALLATION_ID")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: true,
			errorMsg:  "missing required environment variable: GITHUB_APP_INSTALLATION_ID",
		},
		{
			name: "Missing private key",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "12345")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
				os.Unsetenv("GITHUB_APP_PRIVATE_KEY")
			},
			wantError: true,
			errorMsg:  "missing required environment variable: GITHUB_APP_PRIVATE_KEY",
		},
		{
			name: "Invalid app ID",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "not-a-number")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "67890")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: true,
			errorMsg:  "invalid GITHUB_APP_ID",
		},
		{
			name: "Invalid installation ID",
			setupEnv: func() {
				os.Setenv("GITHUB_APP_ID", "12345")
				os.Setenv("GITHUB_APP_INSTALLATION_ID", "not-a-number")
				os.Setenv("GITHUB_APP_PRIVATE_KEY", "mock-private-key")
			},
			wantError: true,
			errorMsg:  "invalid GITHUB_APP_INSTALLATION_ID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup environment for this test
			tt.setupEnv()

			// Call the function
			config, err := LoadGitHubAppConfig()

			// Check if we expected an error
			if tt.wantError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("Did not expect error but got: %v", err)
			}

			// If we didn't expect an error, check the config values
			if !tt.wantError {
				if config == nil {
					t.Fatal("Expected config but got nil")
				}
				if config.AppID != 12345 {
					t.Errorf("Expected AppID to be 12345, got %d", config.AppID)
				}
				if config.InstallationID != 67890 {
					t.Errorf("Expected InstallationID to be 67890, got %d", config.InstallationID)
				}
				if string(config.PrivateKey) != "mock-private-key" {
					t.Errorf("Expected PrivateKey to be 'mock-private-key', got '%s'", string(config.PrivateKey))
				}
			}
		})
	}

	// Restore original env vars
	if originalAppID != "" {
		os.Setenv("GITHUB_APP_ID", originalAppID)
	} else {
		os.Unsetenv("GITHUB_APP_ID")
	}
	if originalInstallID != "" {
		os.Setenv("GITHUB_APP_INSTALLATION_ID", originalInstallID)
	} else {
		os.Unsetenv("GITHUB_APP_INSTALLATION_ID")
	}
	if originalPrivateKey != "" {
		os.Setenv("GITHUB_APP_PRIVATE_KEY", originalPrivateKey)
	} else {
		os.Unsetenv("GITHUB_APP_PRIVATE_KEY")
	}
}

// Helper function to check if a string contains another string
func contains(s, substr string) bool {
	return s != "" && substr != "" && strings.Contains(s, substr)
}
