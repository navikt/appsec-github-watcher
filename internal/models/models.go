package models

import (
	"errors"
	"fmt"
)

// Error definitions for validation
var (
	ErrMissingMembership = errors.New("membership field is required for member_added/member_removed actions")
	ErrMissingInvitation = errors.New("invitation field is required for member_invited actions")
	ErrUnsupportedAction = errors.New("unsupported action type")
)

// Action types for organization membership events
const (
	ActionMemberAdded   = "member_added"
	ActionMemberRemoved = "member_removed"
	ActionMemberInvited = "member_invited"
)

// Role types for organization members
const (
	RoleAdmin  = "admin"  // Organization owners
	RoleMember = "member" // Regular members
)

// GitHubPayload represents the payload received from GitHub webhooks for organization events.
// See: https://docs.github.com/en/webhooks/webhook-events-and-payloads?actionType=member_added#organization
type GitHubPayload struct {
	// Action is the type of event that triggered the webhook.
	Action string `json:"action"`

	// Organization contains information about the GitHub organization.
	Organization *GitHubOrganization `json:"organization,omitempty"`

	// Membership contains information about the user's membership when
	// the action is related to existing members (member_added, member_removed).
	Membership *GitHubMembership `json:"membership,omitempty"`

	// Invitation contains information about the invitation when the
	// action is related to inviting members (member_invited).
	Invitation *GitHubInvitation `json:"invitation,omitempty"`
}

// GitHubOrganization contains information about a GitHub organization.
type GitHubOrganization struct {
	// Login is the organization's username on GitHub.
	Login string `json:"login"`

	// ID is the unique identifier of the organization.
	ID int64 `json:"id"`

	// URL is the API URL for the organization.
	URL string `json:"url"`
}

// String returns a string representation of the organization.
func (o *GitHubOrganization) String() string {
	if o == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s (ID: %d)", o.Login, o.ID)
}

// GitHubMembership represents a user's membership in an organization.
type GitHubMembership struct {
	// Role is the user's role in the organization.
	// Common values: "admin" (for owners), "member" (for regular members)
	Role string `json:"role"`

	// State is the state of the membership.
	// Common values: "active", "pending"
	State string `json:"state"`

	// User contains information about the GitHub user.
	User GitHubUser `json:"user"`
}

// String returns a string representation of the membership.
func (m *GitHubMembership) String() string {
	if m == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%s as %s (state: %s)", m.User.String(), m.Role, m.State)
}

// GitHubInvitation contains information about an invitation to join the organization.
type GitHubInvitation struct {
	// Email is the email address of the invited user (if available).
	Email string `json:"email,omitempty"`

	// InvitationSource indicates how the invitation was created.
	InvitationSource string `json:"invitation_source"`

	// Inviter contains information about the GitHub user who created the invitation (if available).
	Inviter *GitHubUser `json:"inviter,omitempty"`
}

// String returns a string representation of the invitation.
func (i *GitHubInvitation) String() string {
	if i == nil {
		return "<nil>"
	}
	inviter := "<unknown>"
	if i.Inviter != nil {
		inviter = i.Inviter.Login
	}
	email := i.Email
	if email == "" {
		email = "<no email>"
	}
	return fmt.Sprintf("Invitation to %s by %s (source: %s)", email, inviter, i.InvitationSource)
}

// GitHubUser contains information about a GitHub user.
type GitHubUser struct {
	// Login is the user's username on GitHub.
	Login string `json:"login"`

	// Email is the user's email address, if publicly available.
	// Note: This is often empty, as most users don't make their email public.
	// The application typically needs to fetch this using the SSO email from GraphQL.
	Email string `json:"email,omitempty"`

	// ID is the unique identifier of the user.
	ID int64 `json:"id"`

	// AvatarURL is the URL to the user's profile picture.
	AvatarURL string `json:"avatar_url,omitempty"`
}

// String returns a string representation of the user.
func (u *GitHubUser) String() string {
	return fmt.Sprintf("%s (ID: %d)", u.Login, u.ID)
}

// SlackGroupUsers represents the users in a Slack usergroup.
type SlackGroupUsers struct {
	// Users contains a list of Slack user IDs that belong to the usergroup.
	Users []string `json:"users"`
}

// IsOwner returns true if the membership represents an organization owner.
func (m *GitHubMembership) IsOwner() bool {
	return m != nil && m.Role == RoleAdmin
}

// IsMember returns true if the membership represents a regular organization member.
func (m *GitHubMembership) IsMember() bool {
	return m != nil && m.Role == RoleMember
}

// GetUser returns the GitHub user from the payload based on the action type.
// For member_added and member_removed, it returns the user from the membership.
// For member_invited, it returns nil as we don't have the user object directly.
func (p *GitHubPayload) GetUser() *GitHubUser {
	if p.Membership != nil {
		return &p.Membership.User
	}
	return nil
}

// Validate validates the webhook payload has the expected format based on its action.
func (p *GitHubPayload) Validate() error {
	if p.Organization == nil {
		return errors.New("missing organization information")
	}

	switch p.Action {
	case ActionMemberAdded, ActionMemberRemoved:
		if p.Membership == nil {
			return ErrMissingMembership
		}
	case ActionMemberInvited:
		if p.Invitation == nil {
			return ErrMissingInvitation
		}
	default:
		return fmt.Errorf("%w: %s", ErrUnsupportedAction, p.Action)
	}
	return nil
}
