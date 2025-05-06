// client_test.go
package github

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/shurcooL/githubv4"
)

// roundTripFunc allows customizing request handling for http.Client.Transport.
type roundTripFunc func(req *http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestFetchSAMLNameID(t *testing.T) {
	t.Run("returns nameId when present", func(t *testing.T) {
		// Setup test GraphQL server
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"edges":[{"node":{"samlIdentity":{"nameId":"expected-id"}}}]}}}}}`)
		}))
		defer ts.Close()

		// Rewrite requests to test server
		httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u, _ := url.Parse(ts.URL + req.URL.Path)
			req.URL = u
			return http.DefaultTransport.RoundTrip(req)
		})}
		client := githubv4.NewClient(httpClient)

		id, err := FetchSAMLNameID(context.Background(), client, "org", "user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "expected-id" {
			t.Errorf("got %q, want %q", id, "expected-id")
		}
	})

	t.Run("returns empty when no edges", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"data":{"organization":{"samlIdentityProvider":{"externalIdentities":{"edges":[]}}}}}`)
		}))
		defer ts.Close()

		httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u, _ := url.Parse(ts.URL + req.URL.Path)
			req.URL = u
			return http.DefaultTransport.RoundTrip(req)
		})}
		client := githubv4.NewClient(httpClient)

		id, err := FetchSAMLNameID(context.Background(), client, "org", "user")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "" {
			t.Errorf("got %q, want empty string", id)
		}
	})

	t.Run("returns error on invalid JSON", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, `invalid json`)
		}))
		defer ts.Close()

		httpClient := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			u, _ := url.Parse(ts.URL + req.URL.Path)
			req.URL = u
			return http.DefaultTransport.RoundTrip(req)
		})}
		client := githubv4.NewClient(httpClient)

		_, err := FetchSAMLNameID(context.Background(), client, "org", "user")
		if err == nil {
			t.Fatal("expected error for invalid JSON, got nil")
		}
	})
}
