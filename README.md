# appsec-github-watcher

## Description

The appsec-github-watcher is a Go-based application that monitors GitHub organization membership changes through webhooks and automates security-related tasks. It provides the following key features:

- **GitHub Organization Monitoring**: Listens to webhooks for member additions, removals, and invitations in a GitHub organization
- **GitHub Owners Management**: Automatically adds organization owners to a dedicated Slack usergroup for improved communication and coordination
- **User Onboarding**: Sends welcome emails to new organization members with security best practices and guidelines
- **Security Compliance**: Helps maintain organizational security standards by ensuring all owners have proper Slack access and new members receive security guidance

The application integrates with GitHub's API (including GraphQL for SSO email retrieval), Slack's API for usergroup management, and Microsoft Graph API for sending emails. It's designed to run as a standalone service or within a container.

## Environment variables required at runtime:

### General Configuration
- `ENABLE_EMAIL_FUNCTIONALITY` - Feature toggle for email functionality. Set to "true", "yes", "1", or "on" to enable welcome emails (optional, default: disabled)

### GitHub Application
- `GITHUB_WEBHOOK_SECRET_KEY` Generated secret we use to verify that the payload is sent from our webhook.
- `GITHUB_APP_ID` The GitHub App ID used for authentication.
- `GITHUB_INSTALLATION_ID` The GitHub App installation ID used for authentication.
- `GITHUB_APP_PRIVATE_KEY` The private key used for GitHub App authentication.
- `GITHUB_ORGANIZATION` The GitHub organization name to fetch SAML identity information.

#### Required GitHub Permissions
- **Organization**:
  - `members`: `read` - To receive webhooks for membership changes
  - `administration`: `read` - To access organization information
- **Repository**:
  - `metadata`: `read` - Basic repository access
- **Account**:
  - `email`: `read` - To read user email information

#### Webhook Events
- `organization.member_added`
- `organization.member_removed`
- `organization.member_invited`

### Slack Integration
- `SLACK_APP_CLIENT_ID` The Slack application client ID
- `SLACK_APP_CLIENT_SECRET` The Slack application client secret
- `SLACK_APP_SIGNING_SECRET` The Slack signing secret used to verify responses from Slack API

#### Required Slack Scopes
- `usergroups:read` - To read the list of users in a user group
- `usergroups:write` - To update user group memberships
- `users:read` - To read user information
- `users:read.email` - To look up users by email address

### Azure (for Email Service)
- `AZURE_APP_CLIENT_ID` - Azure AD application client ID
- `AZURE_APP_TENANT_ID` - Azure AD tenant ID
- `AZURE_APP_CLIENT_SECRET` - Azure AD client secret
- `AZURE_OPENID_CONFIG_TOKEN_ENDPOINT` - Azure AD token endpoint (optional, defaults to standard endpoint)
- `EMAIL_FROM_ADDRESS` - The email address to send welcome emails from (optional, defaults to appsec@nav.no)

#### Required Microsoft Graph API Permissions
- `Mail.Send` - To send welcome emails
- `User.Read` - To read user information

## Development Setup

1. Install dependencies: `go mod tidy`
2. Configure environment variables as listed above
3. Run the application: `go run cmd/appsec-github-watcher/main.go`
4. Build the Docker image: `docker build .`

## Testing

Run tests with: `go test ./...`

## Contact
- Internal: Either our slack channel [#appsec](https://nav-it.slack.com/archives/C06P91VN27M) or contact a [team member](https://teamkatalogen.nav.no/team/02ed767d-ce01-49b5-9350-ee4c984fd78f) directly via slack/teams/mail.
- External: [Open GitHub Issue](https://github.com/navikt/appsec-github-watcher/issues/new/choose)