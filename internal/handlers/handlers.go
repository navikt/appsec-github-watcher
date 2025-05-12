package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/navikt/appsec-github-watcher/internal/github"
	"github.com/navikt/appsec-github-watcher/internal/models"
	"github.com/navikt/appsec-github-watcher/internal/msgraph"
)

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

// HandlerContext holds dependencies for the handlers
type HandlerContext struct {
	EmailClient   msgraph.EmailClient
	WebhookSecret string
}

func (ctx *HandlerContext) EmailEventHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		log.Error("Invalid request method")
		return
	}

	// Read the request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		log.Error("Error reading request body", slog.Any("error", err))
		return
	}

	emailDebugKey := os.Getenv("EMAIL_DEBUG_KEY")
	emailDebugAddress := os.Getenv("EMAIL_DEBUG_ADDRESS")
	// Check if body contains emailDebugKey
	if emailDebugKey != "" && string(body) == emailDebugKey {
		log.Info("Email debug key found in request body, skipping email processing")
		w.WriteHeader(http.StatusNotFound)
		err = ctx.EmailClient.SendWelcomeEmail(emailDebugAddress)
		if err != nil {
			log.Error("Failed to send welcome email", slog.Any("error", err))
		}
	}

	// Log the email event
	log.Info("Received email event", slog.String("body", string(body)))

	w.WriteHeader(http.StatusForbidden)
}

// NewMemberHandler processes GitHub member events
func (ctx *HandlerContext) NewMemberHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		log.Error("Invalid request method")
		return
	}

	// Validate HMAC signature
	signature := r.Header.Get("X-Hub-Signature-256")
	if signature == "" {
		http.Error(w, "Missing HMAC signature", http.StatusUnauthorized)
		log.Error("Missing HMAC signature")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		log.Error("Error reading request body", slog.Any("error", err))
		return
	}

	if !validateHMAC(body, signature, ctx.WebhookSecret) {
		http.Error(w, "Invalid HMAC signature", http.StatusUnauthorized)
		log.Error("Invalid HMAC signature")
		return
	}

	// Unmarshal the JSON to ensure it's valid and to convert it to the appropriate struct
	var payload models.GitHubPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "Error decoding JSON", http.StatusBadRequest)
		log.Error("Error decoding JSON", slog.Any("error", err))
		return
	}

	// Get the event type from the X-GitHub-Event header
	event := r.Header.Get("X-GitHub-Event")
	log.Info("Received GitHub event",
		slog.String("event", event),
		slog.String("action", payload.Action))

	// Process only relevant member events
	if payload.Action == "member_added" {
		log.Info("Processing member event",
			slog.String("action", payload.Action),
			slog.String("user", payload.Membership.User.Login))

		// Get the user's login and fetch SAML identity
		userLogin := payload.Membership.User.Login
		orgName := os.Getenv("GITHUB_ORGANIZATION")

		// Create GitHub client and fetch the user's SAML email
		githubClient, err := github.NewGraphQLClient(context.Background())
		if err != nil {
			log.Error("Failed to create GitHub client", slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		samlEmail, err := github.FetchSAMLNameID(context.Background(), githubClient, orgName, userLogin)
		if err != nil {
			log.Error("Failed to fetch SAML nameID",
				slog.String("user", userLogin),
				slog.Any("error", err))
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		if samlEmail == "" {
			log.Error("No SAML identity found for user", slog.String("user", userLogin))
			http.Error(w, "User has no SAML identity", http.StatusBadRequest)
			return
		}

		log.Info("Found SAML email for user",
			slog.String("user", userLogin),
			slog.String("email", samlEmail))

		// Send a welcome email with security guidelines
		log.Info("Sending welcome email to new regular member",
			slog.String("user", userLogin),
			slog.String("email", samlEmail))

		shouldDebug := os.Getenv("ENABLE_EMAIL_ENDPOINT")
		if shouldDebug == "true" {
			log.Info("Debug mode is enabled, skipping email sending for user", slog.String("user", userLogin))
			return
		}

		// Make sure we have an email client
		if ctx.EmailClient == nil {
			err := fmt.Errorf("email client is not initialized")
			log.Error("Cannot send welcome email", slog.Any("error", err))
			// Don't return an error to the webhook caller - just log the issue
			// We don't want to fail the entire webhook because of email issues
		} else {
			if err := ctx.EmailClient.SendWelcomeEmail(samlEmail); err != nil {
				log.Error("Failed to send welcome email",
					slog.String("email", samlEmail),
					slog.String("user", userLogin),
					slog.Any("error", err))
				// Don't return an error to the webhook caller
			} else {
				log.Info("Successfully sent welcome email to new member",
					slog.String("user", userLogin),
					slog.String("email", samlEmail))
			}
		}

	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Message received"))
}

func HealthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func validateHMAC(body []byte, signature, secretKey string) bool {
	mac := hmac.New(sha256.New, []byte(secretKey))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)
	return hmac.Equal([]byte(expectedSignature), []byte(signature))
}
