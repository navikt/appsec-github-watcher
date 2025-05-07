package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/navikt/appsec-github-watcher/internal/github"
	"github.com/navikt/appsec-github-watcher/internal/slack"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Info("Starting appsec-slack-updater")

	// Check required environment variables
	slackUserGroupId := os.Getenv("SLACK_USER_GROUP_ID")
	if slackUserGroupId == "" {
		log.Error("Missing required environment variable: SLACK_USER_GROUP_ID")
		os.Exit(1)
	}

	githubOrg := os.Getenv("GITHUB_ORGANIZATION")
	if githubOrg == "" {
		log.Error("Missing required environment variable: GITHUB_ORGANIZATION")
		os.Exit(1)
	}

	// Initialize Slack client
	slackClient, err := slack.NewSlackClient()
	if err != nil {
		log.Error("Failed to initialize Slack client", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize GitHub client that uses the GitHub App installation to make calls to the GitHub REST API
	githubRestClient, err := github.NewRestClient()
	if err != nil {
		log.Error("Failed to initialize GitHub client", slog.Any("error", err))
		os.Exit(1)
	}

	// Create a context for the GraphQL client
	ctx := context.Background()

	// Initialize GitHub GraphQL client
	githubGraphQLClient, err := github.NewGraphQLClient(ctx)
	if err != nil {
		log.Error("Failed to initialize GitHub GraphQL client", slog.Any("error", err))
		os.Exit(1)
	}

	// Fetch org administrators from GitHub REST API
	orgAdmins, err := githubRestClient.GetOrgAdmins(githubOrg)
	if err != nil {
		log.Error("Failed to fetch org administrators", slog.Any("error", err))
		os.Exit(1)
	}
	log.Info("Fetched GitHub org administrators", slog.Int("count", len(orgAdmins)))

	// For each org admin, fetch their SSO email address from GitHub GraphQL
	adminEmails := make([]string, 0, len(orgAdmins))
	for _, admin := range orgAdmins {
		ssoNameID, err := github.FetchSAMLNameID(ctx, githubGraphQLClient, githubOrg, admin)
		if err != nil {
			log.Warn("Failed to fetch SAML nameID for user",
				slog.String("user", admin),
				slog.Any("error", err))
			continue
		}

		if ssoNameID == "" {
			log.Warn("User has no SAML identity", slog.String("user", admin))
			continue
		}

		adminEmails = append(adminEmails, ssoNameID)
		log.Debug("Fetched SAML nameID for user",
			slog.String("user", admin),
			slog.String("email", ssoNameID))
	}

	log.Info("Fetched SAML email addresses for administrators",
		slog.Int("adminCount", len(orgAdmins)),
		slog.Int("emailCount", len(adminEmails)))

	// Fetch the current members of the Slack user group
	currentGroupUsers, err := slackClient.GetUsergroupMembers(slackUserGroupId)
	if err != nil {
		log.Error("Failed to fetch Slack user group members", slog.Any("error", err))
		os.Exit(1)
	}
	log.Info("Fetched current Slack user group members", slog.Int("count", len(currentGroupUsers.Users)))

	// Convert admin emails to Slack user IDs
	adminSlackIDs, notFoundEmails, err := slackClient.GetUserIDsByEmails(adminEmails)
	if err != nil {
		log.Error("Failed to convert emails to Slack user IDs", slog.Any("error", err))
		os.Exit(1)
	}

	if len(notFoundEmails) > 0 {
		log.Warn("Some administrator emails were not found in Slack",
			slog.Any("emails", notFoundEmails))
	}

	log.Info("Converted admin emails to Slack user IDs",
		slog.Int("totalAdmins", len(adminEmails)),
		slog.Int("foundInSlack", len(adminSlackIDs)),
		slog.Int("notFoundInSlack", len(notFoundEmails)))

	// Compare the two lists to see if an update is needed
	needsUpdate := false

	// Check if the lengths are different
	if len(adminSlackIDs) != len(currentGroupUsers.Users) {
		needsUpdate = true
		log.Info("Number of users in Slack group does not match number of GitHub admins",
			slog.Int("slackGroupSize", len(currentGroupUsers.Users)),
			slog.Int("githubAdminsSize", len(adminSlackIDs)))
	} else {
		// Even if the lengths match, check if the contents are different
		// Create a map for O(1) lookups
		currentMap := make(map[string]bool)
		for _, userID := range currentGroupUsers.Users {
			currentMap[userID] = true
		}

		// Check if all admin IDs are in the current group
		for _, adminID := range adminSlackIDs {
			if !currentMap[adminID] {
				needsUpdate = true
				log.Info("Found admin not in Slack group", slog.String("slackUserID", adminID))
				break
			}
		}

		// If we haven't found a difference yet, check if all current users are admins
		if !needsUpdate {
			adminMap := make(map[string]bool)
			for _, adminID := range adminSlackIDs {
				adminMap[adminID] = true
			}

			for _, userID := range currentGroupUsers.Users {
				if !adminMap[userID] {
					needsUpdate = true
					log.Info("Found Slack group member who is not a GitHub admin", slog.String("slackUserID", userID))
					break
				}
			}
		}
	}

	// Update the Slack user group if necessary
	if needsUpdate {
		log.Info("Updating Slack user group with GitHub admin list", slog.Int("userCount", len(adminSlackIDs)))
		err = slackClient.UpdateUsergroupMembers(slackUserGroupId, adminSlackIDs)
		if err != nil {
			log.Error("Failed to update Slack user group members", slog.Any("error", err))
			os.Exit(1)
		}
		log.Info("Successfully updated Slack user group with GitHub admins")
	} else {
		log.Info("Slack user group already matches GitHub admins, no update needed")
	}
}
