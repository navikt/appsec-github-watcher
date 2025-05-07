package slack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/navikt/appsec-github-watcher/internal/models"
	"github.com/slack-go/slack"
)

const (
	maxRetries    = 3
	baseDelay     = 100 * time.Millisecond
	slackEndPoint = "https://slack.com/api/"
	tokenEndpoint = "https://slack.com/api/oauth.v2.access"
)

// MockOAuthEndpoint allows tests to override the endpoint
var mockOAuthEndpoint string

var log = slog.New(slog.NewJSONHandler(os.Stdout, nil))

type SlackClient interface {
	AddUserToUserGroup(userEmail string, userGroupID string) error
	RemoveUserFromUserGroup(userEmail string, userGroupID string) error
	GetUsergroupMembers(usergroupID string) (*models.SlackGroupUsers, error)
	GetUserIDsByEmails(emails []string) ([]string, []string, error)
	UpdateUsergroupMembers(usergroupID string, userIDs []string) error
}

// MockSlackClient implements the SlackClient interface for testing
type MockSlackClient struct {
	AddUserError                error
	RemoveUserError             error
	GetUsergroupMembersError    error
	GetUserIDsByEmailsError     error
	UpdateUsergroupMembersError error
	AddedEmails                 []string
	RemovedEmails               []string
	MockUsers                   *models.SlackGroupUsers
	MockUserIDs                 []string
	MockNotFoundEmails          []string
}

func (m *MockSlackClient) AddUserToUserGroup(userEmail string, userGroupID string) error {
	if m.AddUserError != nil {
		return m.AddUserError
	}
	m.AddedEmails = append(m.AddedEmails, userEmail)
	return nil
}

func (m *MockSlackClient) RemoveUserFromUserGroup(userEmail string, userGroupID string) error {
	if m.RemoveUserError != nil {
		return m.RemoveUserError
	}
	m.RemovedEmails = append(m.RemovedEmails, userEmail)
	return nil
}

func (m *MockSlackClient) GetUsergroupMembers(usergroupID string) (*models.SlackGroupUsers, error) {
	if m.GetUsergroupMembersError != nil {
		return nil, m.GetUsergroupMembersError
	}

	if m.MockUsers == nil {
		return &models.SlackGroupUsers{Users: []string{}}, nil
	}

	return m.MockUsers, nil
}

func (m *MockSlackClient) GetUserIDsByEmails(emails []string) ([]string, []string, error) {
	if m.GetUserIDsByEmailsError != nil {
		return nil, nil, m.GetUserIDsByEmailsError
	}

	if m.MockUserIDs == nil {
		// Return dummy user IDs that match the input emails (for simple testing)
		ids := make([]string, len(emails))
		for i, email := range emails {
			ids[i] = "U" + strings.Replace(email, "@", "_", -1)
		}
		return ids, m.MockNotFoundEmails, nil
	}

	return m.MockUserIDs, m.MockNotFoundEmails, nil
}

func (m *MockSlackClient) UpdateUsergroupMembers(usergroupID string, userIDs []string) error {
	if m.UpdateUsergroupMembersError != nil {
		return m.UpdateUsergroupMembersError
	}

	// Store the updated userIDs for testing
	if m.MockUsers == nil {
		m.MockUsers = &models.SlackGroupUsers{}
	}
	m.MockUsers.Users = userIDs

	return nil
}

type slackClient struct {
	api *slack.Client
}

// SlackTokenResponse represents the response from Slack OAuth token endpoint
type SlackTokenResponse struct {
	OK          bool   `json:"ok"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Error       string `json:"error"`
}

// NewSlackClient creates a SlackClient with a real API client
func NewSlackClient() (SlackClient, error) {
	token, err := getOAuthToken()
	if err != nil {
		log.Error("Failed to get OAuth token", slog.Any("error", err))
		return nil, fmt.Errorf("unable to fetch slack token: %w", err)
	}
	if token == "" {
		err := fmt.Errorf("empty token received from OAuth provider")
		log.Error("Empty token received", slog.Any("error", err))
		return nil, err
	}

	client := &slackClient{
		api: slack.New(
			token,
			slack.OptionAPIURL(slackEndPoint),
			slack.OptionHTTPClient(http.DefaultClient),
		),
	}

	log.Info("Created Slack client", slog.String("endpoint", slackEndPoint))
	return client, nil
}

// getOAuthTokenWithEndpoint is a test-friendly version that allows specifying the endpoint
func getOAuthTokenWithEndpoint(endpoint string) (string, error) {
	slackBotToken := os.Getenv("SLACK_BOT_TOKEN")

	// Check if we have a direct bot token
	if slackBotToken != "" {
		log.Info("Using provided SLACK_BOT_TOKEN")
		return slackBotToken, nil
	}

	// No bot token available
	return "", fmt.Errorf("missing required environment variable: SLACK_BOT_TOKEN")
}

// getOAuthToken retrieves a token using client credentials and verifies the response
func getOAuthToken() (string, error) {
	// Use the mock endpoint for testing if set
	endpoint := tokenEndpoint
	if mockOAuthEndpoint != "" {
		endpoint = mockOAuthEndpoint
	}
	return getOAuthTokenWithEndpoint(endpoint)
}

// verifySlackSignature verifies that the response came from Slack
func verifySlackSignature(signature, timestamp, body, signingSecret string) bool {
	// The signature base string is created by concatenating the version, timestamp, and body
	baseString := fmt.Sprintf("v0:%s:%s", timestamp, body)

	// Create a new HMAC with SHA256
	mac := hmac.New(sha256.New, []byte(signingSecret))
	mac.Write([]byte(baseString))

	// Get the computed signature
	computedSignature := fmt.Sprintf("v0=%s", hex.EncodeToString(mac.Sum(nil)))

	// Compare the computed signature with the provided signature
	return hmac.Equal([]byte(computedSignature), []byte(signature))
}

// doWithRetry retries the provided function with exponential backoff
func (s *slackClient) doWithRetry(fn func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		backoffDuration := baseDelay * (1 << i)
		log.Info("Retrying operation after error",
			slog.Int("attempt", i+1),
			slog.Int("maxRetries", maxRetries),
			slog.Duration("backoff", backoffDuration),
			slog.Any("error", err))
		time.Sleep(backoffDuration)
	}
	return fmt.Errorf("after %d retries, last error: %w", maxRetries, err)
}

func (s *slackClient) AddUserToUserGroup(userEmail string, userGroupID string) error {
	var userID string

	log.Info("Adding user to user group",
		slog.String("email", userEmail),
		slog.String("userGroupID", userGroupID))

	// Fetch user by email from slack api with retry
	err := s.doWithRetry(func() error {
		user, err := s.api.GetUserByEmail(userEmail)
		if err != nil {
			return fmt.Errorf("failed to get user by email: %w", err)
		}
		userID = user.ID
		return nil
	})
	if err != nil {
		log.Error("Failed to fetch user by email",
			slog.String("email", userEmail),
			slog.Any("error", err))
		return err
	}

	// Fetch all users in the user group from slack api with retry
	var userGroupMembers []string
	err = s.doWithRetry(func() error {
		var err error
		userGroupMembers, err = s.api.GetUserGroupMembers(userGroupID)
		if err != nil {
			return fmt.Errorf("failed to get user group members: %w", err)
		}
		return nil
	})
	if err != nil {
		log.Error("Failed to fetch user group members",
			slog.String("userGroupID", userGroupID),
			slog.Any("error", err))
		return err
	}

	// Check if user is already in the group
	for _, member := range userGroupMembers {
		if member == userID {
			log.Info("User already in user group, skipping add operation",
				slog.String("email", userEmail),
				slog.String("userID", userID),
				slog.String("userGroupID", userGroupID))
			return nil
		}
	}

	// Add user to user group in list
	newMembers := append(userGroupMembers, userID)
	newMembersStr := ""
	if len(newMembers) > 0 {
		newMembersStr = newMembers[0]
		for _, id := range newMembers[1:] {
			newMembersStr += "," + id
		}
	}

	// Send update to slack api with retry
	err = s.doWithRetry(func() error {
		_, err := s.api.UpdateUserGroupMembers(userGroupID, newMembersStr)
		if err != nil {
			return fmt.Errorf("failed to update user group members: %w", err)
		}
		return nil
	})

	if err != nil {
		log.Error("Failed to add user to user group",
			slog.String("email", userEmail),
			slog.String("userID", userID),
			slog.String("userGroupID", userGroupID),
			slog.Any("error", err))
		return err
	}

	log.Info("Successfully added user to user group",
		slog.String("email", userEmail),
		slog.String("userID", userID),
		slog.String("userGroupID", userGroupID))
	return nil
}

func (s *slackClient) RemoveUserFromUserGroup(userEmail string, userGroupID string) error {
	var userID string

	log.Info("Removing user from user group",
		slog.String("email", userEmail),
		slog.String("userGroupID", userGroupID))

	// Fetch user by email from slack api with retry
	err := s.doWithRetry(func() error {
		user, err := s.api.GetUserByEmail(userEmail)
		if err != nil {
			return fmt.Errorf("failed to get user by email: %w", err)
		}
		userID = user.ID
		return nil
	})
	if err != nil {
		log.Error("Failed to fetch user by email",
			slog.String("email", userEmail),
			slog.Any("error", err))
		return err
	}

	// Fetch all users in the user group from slack api with retry
	var userGroupMembers []string
	err = s.doWithRetry(func() error {
		var err error
		userGroupMembers, err = s.api.GetUserGroupMembers(userGroupID)
		if err != nil {
			return fmt.Errorf("failed to get user group members: %w", err)
		}
		return nil
	})
	if err != nil {
		log.Error("Failed to fetch user group members",
			slog.String("userGroupID", userGroupID),
			slog.Any("error", err))
		return err
	}

	// Check if user is even in the group
	userFound := false
	for _, id := range userGroupMembers {
		if id == userID {
			userFound = true
			break
		}
	}

	if !userFound {
		log.Info("User not found in user group, skipping remove operation",
			slog.String("email", userEmail),
			slog.String("userID", userID),
			slog.String("userGroupID", userGroupID))
		return nil
	}

	// Remove user from user group in list
	newMembers := []string{}
	for _, id := range userGroupMembers {
		if id != userID {
			newMembers = append(newMembers, id)
		}
	}
	newMembersStr := ""
	if len(newMembers) > 0 {
		newMembersStr = newMembers[0]
		for _, id := range newMembers[1:] {
			newMembersStr += "," + id
		}
	}

	// Send update to slack api with retry
	err = s.doWithRetry(func() error {
		_, err := s.api.UpdateUserGroupMembers(userGroupID, newMembersStr)
		if err != nil {
			return fmt.Errorf("failed to update user group members: %w", err)
		}
		return nil
	})

	if err != nil {
		log.Error("Failed to remove user from user group",
			slog.String("email", userEmail),
			slog.String("userID", userID),
			slog.String("userGroupID", userGroupID),
			slog.Any("error", err))
		return err
	}

	log.Info("Successfully removed user from user group",
		slog.String("email", userEmail),
		slog.String("userID", userID),
		slog.String("userGroupID", userGroupID))
	return nil
}

// GetUsergroupMembers gets all members of a Slack user group
func (s *slackClient) GetUsergroupMembers(usergroupID string) (*models.SlackGroupUsers, error) {
	var members []string

	log.Info("Fetching members of Slack user group", slog.String("usergroupID", usergroupID))

	err := s.doWithRetry(func() error {
		var err error
		members, err = s.api.GetUserGroupMembers(usergroupID)
		if err != nil {
			return fmt.Errorf("failed to get user group members: %w", err)
		}
		return nil
	})

	if err != nil {
		log.Error("Failed to fetch user group members",
			slog.String("usergroupID", usergroupID),
			slog.Any("error", err))
		return nil, err
	}

	log.Info("Successfully fetched user group members",
		slog.String("usergroupID", usergroupID),
		slog.Int("memberCount", len(members)))

	return &models.SlackGroupUsers{Users: members}, nil
}

// For test use - allows replacing the default user lookup function
type userLookupFunc func(email string) (*slack.User, error)

// GetUserIDsByEmailsWithLookup allows custom user lookup for testing
func (s *slackClient) GetUserIDsByEmailsWithLookup(emails []string, lookupFn userLookupFunc) ([]string, []string, error) {
	userIDs := make([]string, 0, len(emails))
	notFound := make([]string, 0)

	log.Info("Converting emails to Slack user IDs", slog.Int("emailCount", len(emails)))

	for _, email := range emails {
		user, err := lookupFn(email)

		if err != nil {
			// Check if this is a user not found error
			if strings.Contains(err.Error(), "users_not_found") ||
				strings.Contains(err.Error(), "user_not_found") {
				log.Warn("User not found in Slack", slog.String("email", email))
				notFound = append(notFound, email)
				continue
			}

			// Any other error
			log.Error("Error fetching user by email",
				slog.String("email", email),
				slog.Any("error", err))
			continue
		}

		if user != nil {
			userIDs = append(userIDs, user.ID)
			log.Debug("Mapped email to Slack user ID",
				slog.String("email", email),
				slog.String("userID", user.ID))
		} else {
			log.Warn("User lookup returned nil for", slog.String("email", email))
			notFound = append(notFound, email)
		}
	}

	log.Info("Completed mapping emails to Slack user IDs",
		slog.Int("totalEmails", len(emails)),
		slog.Int("foundUsers", len(userIDs)),
		slog.Int("notFoundUsers", len(notFound)))

	return userIDs, notFound, nil
}

// GetUserIDsByEmails converts a list of email addresses to Slack user IDs
func (s *slackClient) GetUserIDsByEmails(emails []string) ([]string, []string, error) {
	return s.GetUserIDsByEmailsWithLookup(emails, func(email string) (*slack.User, error) {
		var user *slack.User
		var err error

		err = s.doWithRetry(func() error {
			user, err = s.api.GetUserByEmail(email)
			if err != nil {
				// Check if it's a "user_not_found" error from Slack
				if strings.Contains(err.Error(), "users_not_found") ||
					strings.Contains(err.Error(), "user_not_found") {
					return nil // Not a retry-able error, but we'll handle it in the outer function
				}
				return fmt.Errorf("failed to get user by email: %w", err)
			}
			return nil
		})

		return user, err
	})
}

// UpdateUsergroupMembers updates a Slack user group with a new list of members
func (s *slackClient) UpdateUsergroupMembers(usergroupID string, userIDs []string) error {
	if len(userIDs) == 0 {
		log.Warn("Attempted to update user group with empty user list",
			slog.String("usergroupID", usergroupID))
		return fmt.Errorf("cannot update user group with empty user list")
	}

	log.Info("Updating Slack user group members",
		slog.String("usergroupID", usergroupID),
		slog.Int("userCount", len(userIDs)))

	// Convert the user IDs to a comma-separated string
	userIDsStr := strings.Join(userIDs, ",")

	// Send update to Slack API with retry
	err := s.doWithRetry(func() error {
		_, err := s.api.UpdateUserGroupMembers(usergroupID, userIDsStr)
		if err != nil {
			return fmt.Errorf("failed to update user group members: %w", err)
		}
		return nil
	})

	if err != nil {
		log.Error("Failed to update user group members",
			slog.String("usergroupID", usergroupID),
			slog.Int("userCount", len(userIDs)),
			slog.Any("error", err))
		return err
	}

	log.Info("Successfully updated user group members",
		slog.String("usergroupID", usergroupID),
		slog.Int("userCount", len(userIDs)))

	return nil
}
