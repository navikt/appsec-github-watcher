package models

// GitHubPayload represents the payload received from GitHub webhooks for organization events.
// See: https://docs.github.com/en/webhooks/webhook-events-and-payloads?actionType=member_added#organization
type GitHubPayload struct {
	// Action is the type of event that triggered the webhook.
	Action string `json:"action"`

	// Membership contains information about the user's membership
	Membership *GitHubMembership `json:"membership,omitempty"`
}

// GitHubMembership represents a user's membership in an organization.
type GitHubMembership struct {
	// User contains information about the GitHub user.
	User GitHubUser `json:"user"`
}

// GitHubUser contains information about a GitHub user.
type GitHubUser struct {
	// Login is the user's username on GitHub.
	Login string `json:"login"`
}

// SlackGroupUsers represents the users in a Slack usergroup.
type SlackGroupUsers struct {
	// Users contains a list of Slack user IDs that belong to the usergroup.
	Users []string `json:"users"`
}
