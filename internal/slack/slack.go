package slack

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/slack-go/slack"
)

const (
	maxRetries = 3
	baseDelay  = time.Second
)

// SlackClient is a wrapper around the slack.Client to provide a mockable interface
// for testing purposes & to handle token expiration

type SlackClient struct {
	client *slack.Client
}

func NewSlackClient(token string) *SlackClient {
	token, err := GetOAuthToken()
	if err != nil {
		panic(err)
	}
	if token == "" {
		panic("Unable to fetch slack token")
	}
	client := slack.New(token)
	return &SlackClient{client: client}
}

func GetOAuthToken() (string, error) {
	slackClientID := os.Getenv("SLACK_CLIENT_ID")
	slackClientSecret := os.Getenv("SLACK_CLIENT_SECRET")
	slackCode := os.Getenv("SLACK_CODE")
	redirect_uri := os.Getenv("SLACK_REDIRECT_URI")
	token, _, err := slack.GetOAuthToken(http.DefaultClient, slackClientID, slackClientSecret, slackCode, redirect_uri)
	if err != nil {
		return "", err
	}
	return token, nil
}

// doWithRetry retries the provided function with exponential backoff
func (s *SlackClient) doWithRetry(fn func() error) error {
	var err error
	for i := 0; i < maxRetries; i++ {
		err = fn()
		if err == nil {
			return nil
		}
		time.Sleep(baseDelay * (1 << i))
	}
	return fmt.Errorf("after %d retries, last error: %w", maxRetries, err)
}

// Add user to user group
func (s *SlackClient) AddUserToUserGroup(userID string, userGroupID string) error {
	// Fetch all users in the user group from slack api with retry
	var userGroupMembers []string
	err := s.doWithRetry(func() error {
		var err error
		userGroupMembers, err = s.client.GetUserGroupMembers(userGroupID)
		return err
	})
	if err != nil {
		return err
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
		_, err := s.client.UpdateUserGroupMembers(userGroupID, newMembersStr)
		return err
	})
	return err
}
