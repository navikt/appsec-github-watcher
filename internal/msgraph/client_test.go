package msgraph

import (
	"errors"
	"os"
	"testing"
)

func TestCreateEmailGraphClient(t *testing.T) {
	// Save original env vars to restore later
	origClientID := os.Getenv("AZURE_APP_CLIENT_ID")
	origClientSecret := os.Getenv("AZURE_APP_CLIENT_SECRET")
	origTenantID := os.Getenv("AZURE_APP_TENANT_ID")
	origFromEmail := os.Getenv("EMAIL_FROM_ADDRESS")

	// Restore env vars after test
	defer func() {
		os.Setenv("AZURE_APP_CLIENT_ID", origClientID)
		os.Setenv("AZURE_APP_CLIENT_SECRET", origClientSecret)
		os.Setenv("AZURE_APP_TENANT_ID", origTenantID)
		os.Setenv("EMAIL_FROM_ADDRESS", origFromEmail)
	}()

	t.Run("returns error when client credentials missing", func(t *testing.T) {
		os.Setenv("AZURE_APP_CLIENT_ID", "")
		os.Setenv("AZURE_APP_CLIENT_SECRET", "")
		os.Setenv("AZURE_APP_TENANT_ID", "")

		client, err := CreateEmailGraphClient()
		if err == nil {
			t.Fatal("expected error when credentials missing")
		}
		if client != nil {
			t.Fatal("expected nil client when credentials are missing")
		}
	})

	// We can't fully test the actual client creation without valid credentials
}

func TestGenerateWelcomeEmailBody(t *testing.T) {
	body, err := generateWelcomeEmailBody()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if body == "" {
		t.Error("expected non-empty email body")
	}
}

func TestSendWelcomeEmail(t *testing.T) {
	// Create a mock client for testing
	mockClient := &MockEmailClient{}

	// Test sending an email successfully
	t.Run("successful email send", func(t *testing.T) {
		err := mockClient.SendWelcomeEmail("recipient@example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify the email was "sent"
		if len(mockClient.SentEmails) != 1 {
			t.Fatalf("expected 1 sent email, got %d", len(mockClient.SentEmails))
		}

		sentEmail := mockClient.SentEmails[0]
		if sentEmail.Email != "recipient@example.com" {
			t.Errorf("expected recipient email to be recipient@example.com, got %s", sentEmail.Email)
		}
	})

	// Test sending an email with error
	t.Run("failed email send", func(t *testing.T) {
		// Create a new mock client with an error
		errorMockClient := &MockEmailClient{
			SendEmailError: errors.New("sending email failed"),
		}

		err := errorMockClient.SendWelcomeEmail("recipient@example.com")
		if err == nil {
			t.Fatal("expected error but got none")
		}
	})
}
