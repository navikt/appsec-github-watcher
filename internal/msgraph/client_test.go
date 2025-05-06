package msgraph

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// MockEmailClient and SentEmail types are now defined in client.go

func TestGetOAuthToken(t *testing.T) {
	// Save original env vars to restore later
	origClientID := os.Getenv("AZURE_APP_CLIENT_ID")
	origClientSecret := os.Getenv("AZURE_APP_CLIENT_SECRET")
	origTenantID := os.Getenv("AZURE_APP_TENANT_ID")
	origTokenEndpoint := os.Getenv("AZURE_OPENID_CONFIG_TOKEN_ENDPOINT")

	// Restore env vars after test
	defer func() {
		os.Setenv("AZURE_APP_CLIENT_ID", origClientID)
		os.Setenv("AZURE_APP_CLIENT_SECRET", origClientSecret)
		os.Setenv("AZURE_APP_TENANT_ID", origTenantID)
		os.Setenv("AZURE_OPENID_CONFIG_TOKEN_ENDPOINT", origTokenEndpoint)
	}()

	t.Run("returns error when client credentials missing", func(t *testing.T) {
		os.Setenv("AZURE_APP_CLIENT_ID", "")
		os.Setenv("AZURE_APP_CLIENT_SECRET", "")
		os.Setenv("AZURE_APP_TENANT_ID", "")

		_, err := getOAuthToken()
		if err == nil {
			t.Fatal("expected error when credentials missing")
		}
	})

	// Note: We can't fully test the token acquisition without mocking the OAuth2 endpoint
	// This would require a more complex test setup with a mock HTTP server
}

func TestGenerateWelcomeEmailBody(t *testing.T) {
	testCases := []struct {
		name     string
		userName string
		wantErr  bool
	}{
		{
			name:     "valid username",
			userName: "John Doe",
			wantErr:  false,
		},
		{
			name:     "empty username",
			userName: "",
			wantErr:  false, // Template should still work with empty username
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, err := generateWelcomeEmailBody(tc.userName)
			if tc.wantErr && err == nil {
				t.Fatal("expected error but got none")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !tc.wantErr {
				if body == "" {
					t.Error("expected non-empty email body")
				}
				// Check if the username is in the body when provided
				if tc.userName != "" && !containsString(body, tc.userName) {
					t.Errorf("username %q not found in email body", tc.userName)
				}
			}
		})
	}
}

func TestSendWelcomeEmail(t *testing.T) {
	// Save original env vars
	origFromEmail := os.Getenv("EMAIL_FROM_ADDRESS")

	// Restore env vars after test
	defer func() {
		os.Setenv("EMAIL_FROM_ADDRESS", origFromEmail)
	}()

	// Set up a mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check request method and path
		if r.Method != http.MethodPost {
			t.Errorf("expected POST request, got %s", r.Method)
		}

		// Check content type
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type: application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Return a success response
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	// Create a client that will use our test server using the new factory function
	os.Setenv("EMAIL_FROM_ADDRESS", "test@example.com")
	client := newEmailClientWithHTTPClient(server.Client(), "test@example.com", server.URL)

	// Test sending an email
	err := client.SendWelcomeEmail("recipient@example.com", "Test User")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// Helper function to check if a string contains another string
func containsString(s, substr string) bool {
	return s != "" && substr != "" && len(s) >= len(substr) && contains(s, substr)
}

// Contains reports whether substr is within s.
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
