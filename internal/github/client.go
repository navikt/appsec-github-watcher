package github

import (
	"context"
	"net/http"
	"os"
	"strconv"

	"github.com/bradleyfalzon/ghinstallation/v2"
	"github.com/shurcooL/githubv4"
	"golang.org/x/oauth2"
)

// NewGraphQLClient creates a GitHub-v4 client authenticated as your App installation.
func NewGraphQLClient(ctx context.Context) (*githubv4.Client, error) {
	installationID := os.Getenv("GITHUB_INSTALLATION_ID")

	// load private key from env
	privateKeyPEM := os.Getenv("GITHUB_APP_PRIVATE_KEY")
	privateKey := []byte(privateKeyPEM)

	// parse installation IDs
	installationIDInt, err := strconv.ParseInt(installationID, 10, 64)
	if err != nil {
		return nil, err
	}
	// build transport that handles App JWT + installation token
	tr := http.DefaultTransport
	appsTransport, err := ghinstallation.NewAppsTransport(tr, installationIDInt, privateKey)
	if err != nil {
		return nil, err
	}
	itr := ghinstallation.NewFromAppsTransport(appsTransport, installationIDInt)
	token, err := itr.Token(ctx)
	if err != nil {
		return nil, err
	}

	// wrap into oauth2.Transport so it sets Authorization header
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
