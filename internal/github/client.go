package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/navikt/appsec-github-watcher/internal/models"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// Configuration for GitHub API clients
type GitHubAppConfig struct {
	AppID          int64
	InstallationID int64
	PrivateKey     []byte
}

// LoadGitHubAppConfig loads configuration from environment variables
func LoadGitHubAppConfig() (*GitHubAppConfig, error) {
	// Get installation ID from env
	installationID := os.Getenv("GITHUB_APP_INSTALLATION_ID")
	if installationID == "" {
		return nil, fmt.Errorf("missing required environment variable: GITHUB_APP_INSTALLATION_ID")
	}

	// Get app ID from env (only required for REST client)
	appID := os.Getenv("GITHUB_APP_ID")
	if appID == "" {
		return nil, fmt.Errorf("missing required environment variable: GITHUB_APP_ID")
	}

	// Load private key from env
	privateKeyPEM := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	if privateKeyPEM == "" {
		return nil, fmt.Errorf("missing required environment variable: GITHUB_APP_PRIVATE_KEY")
	}
	privateKey := []byte(privateKeyPEM)

	// Parse installation ID
	installationIDInt, err := strconv.ParseInt(installationID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid GITHUB_APP_INSTALLATION_ID: %w", err)
	}

	// Parse app ID
	appIDInt, err := strconv.ParseInt(appID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid GITHUB_APP_ID: %w", err)
	}

	return &GitHubAppConfig{
		AppID:          appIDInt,
		InstallationID: installationIDInt,
		PrivateKey:     privateKey,
	}, nil
}

// CreateGitHubAppTransport creates a transport for the GitHub App
func CreateGitHubAppTransport(config *GitHubAppConfig) (http.RoundTripper, error) {
	tr, err := ghinstallation.New(
		http.DefaultTransport,
		config.AppID,
		config.InstallationID,
		config.PrivateKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create GitHub installation transport: %w", err)
	}
	return tr, nil
}

// CreateGitHubAppToken creates an access token for GitHub API using the provided transport
func CreateGitHubAppToken(ctx context.Context, config *GitHubAppConfig) (string, error) {
	tr := http.DefaultTransport
	// Fix: Use AppID instead of InstallationID for the second parameter
	appsTransport, err := ghinstallation.NewAppsTransport(tr, config.AppID, config.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create GitHub apps transport: %w", err)
	}
	itr := ghinstallation.NewFromAppsTransport(appsTransport, config.InstallationID)
	token, err := itr.Token(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get installation token: %w", err)
	}
	return token, nil
}

// RestClient is a client for the GitHub REST API
type RestClient struct {
	client *http.Client
}

// Function to generate GitHub org members URL - extracted for testing
var getOrgAdminsURL = func(org string) string {
	return fmt.Sprintf("https://api.github.com/orgs/%s/members?role=admin", org)
}

// NewRestClient creates a GitHub REST client authenticated as your App installation.
func NewRestClient() (*RestClient, error) {
	config, err := LoadGitHubAppConfig()
	if err != nil {
		return nil, err
	}

	// Create transport for REST client
	tr, err := CreateGitHubAppTransport(config)
	if err != nil {
		return nil, err
	}

	// Create HTTP client with the transport
	httpClient := &http.Client{Transport: tr}

	return &RestClient{client: httpClient}, nil
}

// GetOrgAdmins fetches all administrators of the specified GitHub organization.
func (c *RestClient) GetOrgAdmins(org string) ([]string, error) {
	// GitHub REST API endpoint for org members with role filter
	url := getOrgAdminsURL(org)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request to fetch org admins: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching org admins: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API returned non-OK status: %d, body: %s", resp.StatusCode, string(body))
	}

	var users []models.GitHubUser
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, fmt.Errorf("error decoding response: %w", err)
	}

	// Extract login names from the user objects
	admins := make([]string, len(users))
	for i, user := range users {
		admins[i] = user.Login
	}

	return admins, nil
}

// NewGraphQLClient creates a GitHub-v4 client authenticated as your App installation.
func NewGraphQLClient(ctx context.Context) (*githubv4.Client, error) {
	config, err := LoadGitHubAppConfig()
	if err != nil {
		return nil, err
	}

	// Get token for GraphQL client
	token, err := CreateGitHubAppToken(ctx, config)
	if err != nil {
		return nil, err
	}

	// Wrap into oauth2.Transport so it sets Authorization header
	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token}))
	return githubv4.NewClient(tc), nil
}

// ExternalIdentity holds the externalIdentity fragment
type ExternalIdentity struct {
	Login            string
	ExternalIdentity struct {
		Type string
		GUID string
	}
}

// FetchSAMLNameID fetches the SAML nameId for a user in an organization.
func FetchSAMLNameID(ctx context.Context, client *githubv4.Client, orgLogin, userLogin string) (string, error) {
	var q struct {
		Organization struct {
			SamlIdentityProvider struct {
				ExternalIdentities struct {
					Edges []struct {
						Node struct {
							SamlIdentity struct {
								NameID string `graphql:"nameId"`
							} `graphql:"samlIdentity"`
						}
					} `graphql:"edges"`
				} `graphql:"externalIdentities(login: $login, first: 1)"`
			} `graphql:"samlIdentityProvider"`
		} `graphql:"organization(login: $orgLogin)"`
	}
	variables := map[string]interface{}{
		"orgLogin": githubv4.String(orgLogin),
		"login":    githubv4.String(userLogin),
	}
	if err := client.Query(ctx, &q, variables); err != nil {
		return "", err
	}
	edges := q.Organization.SamlIdentityProvider.ExternalIdentities.Edges
	if len(edges) == 0 {
		return "", nil
	}
	return edges[0].Node.SamlIdentity.NameID, nil
}
