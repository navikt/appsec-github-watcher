// Package msgraph provides integration with Microsoft Graph API
package msgraph

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"text/template"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	defaultGraphAPIBaseURL = "https://graph.microsoft.com/v1.0"
	maxRetries             = 3
	baseDelay              = 100 * time.Millisecond
)

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

// EmailClient handles sending emails via Microsoft Graph API
type EmailClient interface {
	SendWelcomeEmail(userEmail, userName string) error
}

// SentEmail represents an email that was sent for testing
type SentEmail struct {
	Email    string
	UserName string
}

// MockEmailClient implements the EmailClient interface for testing
type MockEmailClient struct {
	SendEmailError error
	SentEmails     []SentEmail
}

// SendWelcomeEmail mocks sending a welcome email for testing
func (m *MockEmailClient) SendWelcomeEmail(userEmail, userName string) error {
	if m.SendEmailError != nil {
		return m.SendEmailError
	}
	m.SentEmails = append(m.SentEmails, SentEmail{
		Email:    userEmail,
		UserName: userName,
	})
	return nil
}

// graphClient implements EmailClient interface
type graphClient struct {
	httpClient *http.Client
	fromEmail  string
	baseURL    string // Added to make testing easier
}

// NewEmailClient creates a new MS Graph API client for sending emails
func NewEmailClient() (EmailClient, error) {
	token, err := getOAuthToken()
	if err != nil {
		log.Error("Failed to get OAuth token for MS Graph", slog.Any("error", err))
		return nil, fmt.Errorf("unable to get MS Graph token: %w", err)
	}

	fromEmail := os.Getenv("EMAIL_FROM_ADDRESS")
	if fromEmail == "" {
		fromEmail = "noreply@nav.no" // Default sender address
		log.Info("Using default sender email address", slog.String("email", fromEmail))
	}

	client := &graphClient{
		httpClient: &http.Client{
			Transport: &oauth2.Transport{
				Source: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}),
				Base:   http.DefaultTransport,
			},
		},
		fromEmail: fromEmail,
		baseURL:   defaultGraphAPIBaseURL,
	}

	log.Info("Created MS Graph email client")
	return client, nil
}

// For testing purposes
func newEmailClientWithHTTPClient(httpClient *http.Client, fromEmail, baseURL string) EmailClient {
	if baseURL == "" {
		baseURL = defaultGraphAPIBaseURL
	}
	return &graphClient{
		httpClient: httpClient,
		fromEmail:  fromEmail,
		baseURL:    baseURL,
	}
}

// getOAuthToken retrieves a token using OAuth2 client credentials flow
func getOAuthToken() (string, error) {
	clientID := os.Getenv("AZURE_APP_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_APP_CLIENT_SECRET")
	tenantID := os.Getenv("AZURE_APP_TENANT_ID")

	if clientID == "" || clientSecret == "" || tenantID == "" {
		return "", fmt.Errorf("missing required environment variables: AZURE_APP_CLIENT_ID, AZURE_APP_CLIENT_SECRET, or AZURE_APP_TENANT_ID")
	}

	tokenEndpoint := os.Getenv("AZURE_OPENID_CONFIG_TOKEN_ENDPOINT")
	if tokenEndpoint == "" {
		tokenEndpoint = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)
		log.Info("Using default token endpoint", slog.String("endpoint", tokenEndpoint))
	}

	config := &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenEndpoint,
		Scopes:       []string{"https://graph.microsoft.com/.default"},
	}

	ctx := context.Background()
	token, err := config.Token(ctx)
	if err != nil {
		log.Error("Failed to get MS Graph token", slog.Any("error", err))
		return "", fmt.Errorf("failed to get token: %w", err)
	}

	return token.AccessToken, nil
}

// doWithRetry retries the provided function with exponential backoff
func (g *graphClient) doWithRetry(fn func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		backoffDuration := baseDelay * (1 << i)
		log.Info("Retrying MS Graph operation after error",
			slog.Int("attempt", i+1),
			slog.Int("maxRetries", maxRetries),
			slog.Duration("backoff", backoffDuration),
			slog.Any("error", err))
		time.Sleep(backoffDuration)
	}
	return fmt.Errorf("after %d retries, last error: %w", maxRetries, err)
}

// Email represents the JSON structure for sending an email via MS Graph API
type Email struct {
	Message struct {
		Subject      string `json:"subject"`
		Body         Body   `json:"body"`
		ToRecipients []struct {
			EmailAddress struct {
				Address string `json:"address"`
			} `json:"emailAddress"`
		} `json:"toRecipients"`
	} `json:"message"`
	SaveToSentItems bool `json:"saveToSentItems"`
}

// Body represents the email body content
type Body struct {
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
}

// SendWelcomeEmail sends a welcome email to a new GitHub organization member
func (g *graphClient) SendWelcomeEmail(userEmail, userName string) error {
	log.Info("Sending welcome email", slog.String("to", userEmail), slog.String("userName", userName))

	// Prepare email content
	subject := "Welcome to the GitHub Organization"
	emailBody, err := generateWelcomeEmailBody(userName)
	if err != nil {
		log.Error("Failed to generate email body", slog.Any("error", err))
		return fmt.Errorf("failed to generate email body: %w", err)
	}

	// Construct the email payload
	email := Email{}
	email.Message.Subject = subject
	email.Message.Body.ContentType = "HTML"
	email.Message.Body.Content = emailBody
	email.Message.ToRecipients = []struct {
		EmailAddress struct {
			Address string `json:"address"`
		} `json:"emailAddress"`
	}{
		{
			EmailAddress: struct {
				Address string `json:"address"`
			}{
				Address: userEmail,
			},
		},
	}
	email.SaveToSentItems = true

	// Convert to JSON
	payload, err := json.Marshal(email)
	if err != nil {
		log.Error("Failed to marshal email JSON", slog.Any("error", err))
		return fmt.Errorf("failed to marshal email JSON: %w", err)
	}

	// Send the email with retry
	endpoint := fmt.Sprintf("%s/users/%s/sendMail", g.baseURL, g.fromEmail)
	err = g.doWithRetry(func() error {
		req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewBuffer(payload))
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := g.httpClient.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send email request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 400 {
			return fmt.Errorf("email send failed with status code: %d", resp.StatusCode)
		}
		return nil
	})

	if err != nil {
		log.Error("Failed to send welcome email",
			slog.String("to", userEmail),
			slog.Any("error", err))
		return err
	}

	log.Info("Successfully sent welcome email",
		slog.String("to", userEmail),
		slog.String("userName", userName))
	return nil
}

// generateWelcomeEmailBody creates the HTML body for the welcome email
func generateWelcomeEmailBody(userName string) (string, error) {
	// Email template with GitHub security etiquette information
	const emailTemplate = `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to Our GitHub Organization</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="text-align: center; margin-bottom: 20px;">
        <h1 style="color: #24292e;">Welcome to Our GitHub Organization!</h1>
    </div>
    
    <p>Hello {{.UserName}},</p>
    
    <p>We're excited to welcome you to our GitHub organization. As a new member, we want to make sure you're familiar with our security best practices.</p>
    
    <h2 style="color: #24292e; margin-top: 20px;">GitHub Security Best Practices</h2>
    
    <ul style="padding-left: 20px;">
        <li><strong>Enable Two-Factor Authentication:</strong> 2FA is required for all members. Please ensure it's set up on your GitHub account.</li>
        <li><strong>Use SSH keys:</strong> For repository access, use SSH keys instead of passwords whenever possible.</li>
        <li><strong>Be careful with secrets:</strong> Never commit API keys, passwords, or other secrets to repositories.</li>
        <li><strong>Keep dependencies updated:</strong> Regularly update dependencies to avoid security vulnerabilities.</li>
        <li><strong>Review code changes:</strong> All code should be peer-reviewed before merging to main branches.</li>
        <li><strong>Understand repository permissions:</strong> Only request access to repositories you need to work with.</li>
    </ul>
    
    <h2 style="color: #24292e; margin-top: 20px;">Useful Resources</h2>
    
    <ul style="padding-left: 20px;">
        <li><a href="https://docs.github.com/en/authentication/securing-your-account-with-two-factor-authentication-2fa" style="color: #0366d6;">Setting up 2FA</a></li>
        <li><a href="https://docs.github.com/en/authentication/connecting-to-github-with-ssh" style="color: #0366d6;">Using SSH with GitHub</a></li>
        <li><a href="https://docs.github.com/en/github/administering-a-repository/configuration-options-for-dependency-updates" style="color: #0366d6;">Dependabot configuration</a></li>
    </ul>
    
    <p style="margin-top: 30px;">If you have any questions about our GitHub security policies or need assistance, please don't hesitate to reach out to the security team.</p>
    
    <p>Best regards,<br>
    The AppSec Team</p>
    
    <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; font-size: 12px; color: #6a737d; text-align: center;">
        <p>This is an automated message. Please do not reply to this email.</p>
    </div>
</body>
</html>
`

	// Parse the template
	tmpl, err := template.New("welcomeEmail").Parse(emailTemplate)
	if err != nil {
		return "", fmt.Errorf("failed to parse email template: %w", err)
	}

	// Add template data
	data := struct {
		UserName string
	}{
		UserName: userName,
	}

	// Execute the template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute email template: %w", err)
	}

	return buf.String(), nil
}
