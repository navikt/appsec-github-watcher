package models

// https://docs.github.com/en/webhooks/webhook-events-and-payloads?actionType=member_added#organization
type GitHubPayload struct {
	Action     string           `json:"action"` // member_added, member_removed, deleted
	Membership GithubMembership `json:"membership"`
	Invitation GithubInvitation `json:"invitation"`
}

type GithubMembership struct {
	Role  string     `json:"role"`
	State string     `json:"state"`
	User  GithubUser `json:"user"`
}

type GithubInvitation struct {
	Email            string `json:"email"`
	InvitationSource string `json:"invitation_source"`
}

type GithubUser struct {
	Login string `json:"login"`
	Email string `json:"email"`
}

type SlackGroupUsers struct {
	Users []string `json:"users"`
}
