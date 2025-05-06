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
	"github.com/navikt/appsec-github-watcher/internal/slack"
)

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

// HandlerContext holds dependencies for the handlers
type HandlerContext struct {
	SlackClient   slack.SlackClient
	EmailClient   msgraph.EmailClient
	UserGroupID   string
	WebhookSecret string
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
	if payload.Action == "member_added" || payload.Action == "member_removed" || payload.Action == "deleted" {
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

		// Handle owners differently than regular members
		if payload.Membership.Role == "owner" {
			if payload.Action == "member_added" {
				// Add the user to the Slack user group
				log.Info("Adding user to Slack user group",
					slog.String("email", samlEmail),
					slog.String("userGroup", ctx.UserGroupID))

				if err := ctx.SlackClient.AddUserToUserGroup(samlEmail, ctx.UserGroupID); err != nil {
					log.Error("Failed to add user to Slack user group",
						slog.String("email", samlEmail),
						slog.Any("error", err))
					http.Error(w, "Failed to update Slack user group", http.StatusInternalServerError)
					return
				}

				log.Info("Successfully added user to Slack user group",
					slog.String("email", samlEmail),
					slog.String("userGroup", ctx.UserGroupID))
			} else if payload.Action == "member_removed" || payload.Action == "deleted" {
				// Remove the user from the Slack user group
				log.Info("Removing user from Slack user group",
					slog.String("email", samlEmail),
					slog.String("userGroup", ctx.UserGroupID))

				if err := ctx.SlackClient.RemoveUserFromUserGroup(samlEmail, ctx.UserGroupID); err != nil {
					log.Error("Failed to remove user from Slack user group",
						slog.String("email", samlEmail),
						slog.Any("error", err))
					http.Error(w, "Failed to update Slack user group", http.StatusInternalServerError)
					return
				}

				log.Info("Successfully removed user from Slack user group",
					slog.String("email", samlEmail),
					slog.String("userGroup", ctx.UserGroupID))
			}
		} else if payload.Action == "member_added" {
			// For regular members, send a welcome email with security guidelines
			log.Info("Sending welcome email to new regular member",
				slog.String("user", userLogin),
				slog.String("email", samlEmail))

			// Make sure we have an email client
			if ctx.EmailClient == nil {
				err := fmt.Errorf("email client is not initialized")
				log.Error("Cannot send welcome email", slog.Any("error", err))
				// Don't return an error to the webhook caller - just log the issue
				// We don't want to fail the entire webhook because of email issues
			} else {
				if err := ctx.EmailClient.SendWelcomeEmail(samlEmail, userLogin); err != nil {
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
	} else if payload.Action == "member_invited" {
		// For invited members, we could potentially send an email to the invitation email
		if payload.Invitation.Email != "" {
			log.Info("User was invited, could send welcome email to invitation address",
				slog.String("email", payload.Invitation.Email))

			// We might choose to send a welcome email to the invitation address
			// For now, we're just logging and not sending
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
