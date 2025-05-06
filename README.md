# appsec-github-watcher

## Environment variables required at runtime:

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
- `SLACK_APP_CLIENT_ID` The Slack application client ID for OAuth.
- `SLACK_APP_SECRET` The Slack application client secret for OAuth.
- `SLACK_REFRESH_TOKEN` The refresh token used for Slack API OAuth flow.

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
- `EMAIL_FROM_ADDRESS` - The email address to send welcome emails from (optional, defaults to noreply@nav.no)

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