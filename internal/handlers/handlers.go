package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"

	"github.com/navikt/appsec-github-watcher/internal/models"
)

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

func NewMemberHandler(w http.ResponseWriter, r *http.Request, webhookSecretKey string) {
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
		log.Error("Error reading request body", slog.Any("err", err))
		return
	}

	if !validateHMAC(body, signature, webhookSecretKey) {
		http.Error(w, "Invalid HMAC signature", http.StatusUnauthorized)
		log.Error("Invalid HMAC signature")
		return
	}

	// Unmarshal the JSON to ensure it's valid and to convert it to the appropriate struct
	var m models.GitHubPayload
	if err := json.Unmarshal(body, &m); err != nil {
		http.Error(w, "Error decoding JSON", http.StatusBadRequest)
		log.Error("Error decoding JSON", slog.Any("err", err))
		return
	}

	// Set the Event field from the X-GitHub-Event header
	event := r.Header.Get("X-GitHub-Event")
	log.Info("Received GitHub event", slog.String("event", event))

	if m.Action == "member_added" || m.Action == "member_removed" || m.Action == "deleted" {
		log.Info("Received member event", slog.String("action", m.Action), slog.String("user", m.Membership.User.Login))
		// Handle the member event by checking if action is one of member_added, member_removed, deleted.
		// If the member event is added, check if it is an owner.
		/*slackUser, err := slackClient.GetUserByEmail(m.Membership.User.Email)
		if err != nil {
			http.Error(w, "Error fetching Slack user", http.StatusInternalServerError)
			utils.logError("Error fetching Slack user", err)
			return
		}*/
		if m.Membership.Role == "owner" {
			log.Info("User is an owner, fetch all users in the slack usergroup")
			// Fetch all users in the github-owners usergroup with usersgroups.users.list method
			/*slackUserGroupMembers, err := slackClient.GetUserGroupMembers(os.Getenv("SLACK_USER_GROUP_ID"))
			if err != nil {
				http.Error(w, "Error fetching Slack user group", http.StatusInternalServerError)
				utils.logError("Error fetching Slack user group", err)
				return
			}*/

			if m.Action == "member_added" {
				log.Info("Adding user to slackUserGroup")
				// Check if slackUser is already in the slackUserGroup
				// If so, do nothing else add the user to the slackUserGroup

			}
			if m.Action == "member_removed" || m.Action == "deleted" {
				log.Info("Removing user from slackUserGroup")
				// Remove the user from the slackUserGroup
			}

		}

		// Else, if the user is a regular member, send a welcome email to the user.
		if m.Action == "member_added" {
			log.Info("Send welcome email to new user", slog.String("user", m.Membership.User.Login))
			// Send welcome email to the user
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
