package main

import (
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/navikt/appsec-github-watcher/internal/handlers"
	"github.com/navikt/appsec-github-watcher/internal/msgraph"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Info("Starting appsec-github-watcher")

	webhookSecretKey := os.Getenv("GITHUB_WEBHOOK_SECRET_KEY")
	if webhookSecretKey == "" {
		log.Error("Missing required environment variable: GITHUB_WEBHOOK_SECRET_KEY")
		os.Exit(1)
	}

	// Check feature toggle for email functionality
	var emailClient msgraph.EmailClient
	enableEmail := isFeatureEnabled("ENABLE_EMAIL_FUNCTIONALITY")

	if enableEmail {
		log.Info("Email functionality is enabled, initializing MS Graph client")
		// Initialize MS Graph email client
		var err error
		emailClient, err = msgraph.CreateEmailGraphClient()
		if err != nil {
			log.Error("Failed to initialize MS Graph email client", slog.Any("error", err))
			// Continue without email functionality rather than failing the application
			log.Warn("Email functionality will be disabled despite being enabled in configuration")
		}
	} else {
		log.Info("Email functionality is disabled by feature toggle")
	}

	// Create a handler context with dependencies
	handlerCtx := handlers.HandlerContext{
		EmailClient:   emailClient, // Will be nil if feature is disabled
		WebhookSecret: webhookSecretKey,
	}

	// Set up HTTP routes
	http.HandleFunc("/isready", handlers.HealthCheckHandler)
	http.HandleFunc("/isalive", handlers.HealthCheckHandler)
	http.HandleFunc("/memberEvent", func(w http.ResponseWriter, r *http.Request) {
		handlerCtx.NewMemberHandler(w, r)
	})
	if isFeatureEnabled("ENABLE_EMAIL_ENDPOINT") {
		http.HandleFunc("/emailEvent", func(w http.ResponseWriter, r *http.Request) {
			handlerCtx.EmailEventHandler(w, r)
		})
	}

	// Start the server
	log.Info("Server listening on port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}
}

// isFeatureEnabled checks if a feature toggle is enabled via environment variable
// Returns true if the environment variable is set to "true", "yes", "1", or "on" (case insensitive)
func isFeatureEnabled(envVarName string) bool {
	value := strings.ToLower(os.Getenv(envVarName))
	return value == "true" || value == "yes" || value == "1" || value == "on"
}
