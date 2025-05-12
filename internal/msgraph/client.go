// Package msgraph provides integration with Microsoft Graph API
package msgraph

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"log/slog"
	"os"
	"text/template"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	graph "github.com/microsoftgraph/msgraph-sdk-go"
	graphmodels "github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/users"
)

const (
	defaultGraphAPIBaseURL = "https://graph.microsoft.com/v1.0"
	maxRetries             = 3
	baseDelay              = 100 * time.Millisecond
)

//go:embed templates/*.html templates/*.md
var templateFS embed.FS

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

// EmailClient handles sending emails via Microsoft Graph API
type EmailClient interface {
	SendWelcomeEmail(userEmail string) error
}

// SentEmail represents an email that was sent for testing
type SentEmail struct {
	Email string
}

// MockEmailClient implements the EmailClient interface for testing
type MockEmailClient struct {
	SendEmailError error
	SentEmails     []SentEmail
}

// SendWelcomeEmail mocks sending a welcome email for testing
func (m *MockEmailClient) SendWelcomeEmail(userEmail string) error {
	if m.SendEmailError != nil {
		return m.SendEmailError
	}
	m.SentEmails = append(m.SentEmails, SentEmail{
		Email: userEmail,
	})
	return nil
}

// GraphSDKClient implements EmailClient interface using the Microsoft Graph SDK
type graphSDKClient struct {
	graphClient *graph.GraphServiceClient
	fromEmail   string
}

// CreateEmailGraphClient creates a new MS Graph API client for sending emails using the official SDK
func CreateEmailGraphClient() (EmailClient, error) {
	// Get environment variables
	tenantID := os.Getenv("AZURE_APP_TENANT_ID")
	clientID := os.Getenv("AZURE_APP_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_APP_CLIENT_SECRET")

	if tenantID == "" || clientID == "" || clientSecret == "" {
		return nil, fmt.Errorf("missing required environment variables: AZURE_APP_CLIENT_ID, AZURE_APP_CLIENT_SECRET, or AZURE_APP_TENANT_ID")
	}

	fromEmail := os.Getenv("EMAIL_FROM_ADDRESS")
	if fromEmail == "" {
		fromEmail = "appsec@nav.no" // Default sender address
		log.Info("Using default sender email address", slog.String("email", fromEmail))
	}

	// Create credential using environment variables
	credential, err := azidentity.NewClientSecretCredential(
		tenantID,
		clientID,
		clientSecret,
		&azidentity.ClientSecretCredentialOptions{})

	if err != nil {
		log.Error("Failed to create credential", slog.Any("error", err))
		return nil, fmt.Errorf("failed to create Azure credential: %w", err)
	}

	// Create Graph service client with permissions for sending mail
	graphClient, err := graph.NewGraphServiceClientWithCredentials(
		credential,
		[]string{"https://graph.microsoft.com/.default"},
	)

	if err != nil {
		log.Error("Failed to create MS Graph client", slog.Any("error", err))
		return nil, fmt.Errorf("failed to create MS Graph client: %w", err)
	}

	log.Info("Successfully created MS Graph email client using the SDK")
	return &graphSDKClient{
		graphClient: graphClient,
		fromEmail:   fromEmail,
	}, nil
}

// SendWelcomeEmail sends a welcome email to a new GitHub organization member using the Graph SDK
func (g *graphSDKClient) SendWelcomeEmail(userEmail string) error {
	log.Info("Sending welcome email using Graph SDK",
		slog.String("to", userEmail))

	// Generate email body from template
	emailBody, err := generateWelcomeEmailBody()
	if err != nil {
		log.Error("Failed to generate email body", slog.Any("error", err))
		return fmt.Errorf("failed to generate email body: %w", err)
	}

	// Create message
	message := graphmodels.NewMessage()
	message.SetSubject(ptr("Velkommen til Navs GitHub-organisasjon!"))

	// Create body
	itemBody := graphmodels.NewItemBody()
	contentType := graphmodels.TEXT_BODYTYPE
	itemBody.SetContentType(&contentType)
	itemBody.SetContent(&emailBody)
	message.SetBody(itemBody)

	// Add recipient
	toRecipient := graphmodels.NewRecipient()
	emailAddress := graphmodels.NewEmailAddress()
	emailAddress.SetAddress(&userEmail)
	toRecipient.SetEmailAddress(emailAddress)

	recipients := []graphmodels.Recipientable{toRecipient}
	message.SetToRecipients(recipients)

	// Create send mail request
	requestBody := users.NewItemSendMailPostRequestBody()
	requestBody.SetMessage(message)
	requestBody.SetSaveToSentItems(boolPtr(false))

	// Create request with context
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Send the email
	err = g.graphClient.Users().ByUserId(g.fromEmail).SendMail().Post(ctx, requestBody, nil)
	if err != nil {
		log.Error("Failed to send welcome email",
			slog.String("to", userEmail),
			slog.Any("error", err))
		return fmt.Errorf("failed to send email: %w", err)
	}

	log.Info("Successfully sent welcome email using Graph SDK",
		slog.String("to", userEmail))
	return nil
}

// generateWelcomeEmailBody creates the markdown body for the welcome email
func generateWelcomeEmailBody() (string, error) {
	// Load the template from the embedded file system
	tmplFile, err := templateFS.ReadFile("templates/welcome_email.md")
	if err != nil {
		return "", fmt.Errorf("failed to read email template file: %w", err)
	}

	// Parse the template
	tmpl, err := template.New("welcomeEmail").Parse(string(tmplFile))
	if err != nil {
		return "", fmt.Errorf("failed to parse email template: %w", err)
	}

	// Execute the template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, nil); err != nil {
		return "", fmt.Errorf("failed to execute email template: %w", err)
	}

	return buf.String(), nil
}

// Helper function to create string pointers
func ptr(s string) *string {
	return &s
}

// Helper function to create bool pointers
func boolPtr(b bool) *bool {
	return &b
}
