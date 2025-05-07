This repository consists of two applications: appsec-github-watcher and appsec-slack-updater. 
Appsec-github-watcher is a go-based web api that receives information from a github app webhook on member changes in a github organization. This information contains membership information, we then used that to fetch SSO-email from the github graphql. Then we send a 'welcome to slack'-email with some github security etiquette.

Appsec-slack-update runs as a cron job and fetches a list of member with admin role in a github organization. It then fetches the SSO-emails from the github graphql and makes sure those are in a specific slack usergroup. If not, we update the group with the new list of admins.

## Code Standards

## Required Before Each Commit
- Run `go fmt ./...` to ensure our code is formatted correctly.
- Make sure we follow best practices from effective go on go.dev.
- When adding or changing functionality, make sure you update the README.
- Make sure that the repository structure documentation is correct and accurate in the Copilot Instructions file
- Make sure all tests pass by running `go test ./...` in the terminal

## Development Flow
- Install dependencies: `go mod tidy`
- Run the application `go run cmd/appsec-github-watcher/main.go`
- Build the dockerfile: `docker build .`

## Repository Structure
We follow the server project module layout from go.dev: Server projects typically won’t have packages for export, since a server is usually a self-contained binary (or a group of binaries). Therefore, it’s recommended to keep the Go packages implementing the server’s logic in the internal directory. Moreover, since the project is likely to have many other directories with non-Go files, it’s a good idea to keep all Go commands together in a cmd directory.

## Key Guidelines
1. Make sure we verify all functionality by writing both positive and negative tests.
2. We don't have to worry about integration tests.
3. We use mocks in test in order to keep tests as fast as possible.
4. Always follow best practices from go.dev.
5. Make sure we handle and log all errors in order to make debugging easier.
6. We use OIDC/Oauth2 in all external calls. Required environment variables will be described in the README.
7. We use supplied Azure environment variables to send email using the microsoft graph api.
8. As much as possible we use the go standard library. If we need to use a third party library, make sure it is well maintained and has a good reputation.
9. We will use the go embed package to include email templates directly in the compiled binary.
10. We keep code as clean as possible and avoid code duplication, unnecessary complexity and long functions.
11. We always clean up code that is not used.