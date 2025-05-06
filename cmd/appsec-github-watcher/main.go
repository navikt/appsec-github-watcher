package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/navikt/appsec-github-watcher/internal/handlers"
	"github.com/navikt/appsec-github-watcher/internal/msgraph"
	"github.com/navikt/appsec-github-watcher/internal/slack"
)

const (
	slackUserGroupId = "S0604QSJC"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Info("Starting appsec-github-watcher")

	webhookSecretKey := os.Getenv("GITHUB_WEBHOOK_SECRET_KEY")
	if webhookSecretKey == "" {
		log.Error("Missing required environment variable: GITHUB_WEBHOOK_SECRET_KEY")
		os.Exit(1)
	}

	// Initialize Slack client
	slackClient, err := slack.NewSlackClient()
	if err != nil {
		log.Error("Failed to initialize Slack client", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize MS Graph email client
	emailClient, err := msgraph.NewEmailClient()
	if err != nil {
		log.Error("Failed to initialize MS Graph email client", slog.Any("error", err))
		// Continue without email functionality rather than failing the application
		log.Warn("Email functionality will be disabled")
	}

	// Create a handler context with dependencies
	handlerCtx := handlers.HandlerContext{
		SlackClient:   slackClient,
		EmailClient:   emailClient,
		UserGroupID:   slackUserGroupId,
		WebhookSecret: webhookSecretKey,
	}

	// Set up HTTP routes
	http.HandleFunc("/isready", handlers.HealthCheckHandler)
	http.HandleFunc("/isalive", handlers.HealthCheckHandler)
	http.HandleFunc("/memberEvent", func(w http.ResponseWriter, r *http.Request) {
		handlerCtx.NewMemberHandler(w, r)
	})

	// Start the server
	log.Info("Server listening on port 8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Error("Failed to start server", slog.Any("error", err))
		os.Exit(1)
	}
}
