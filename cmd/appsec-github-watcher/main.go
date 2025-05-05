package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/navikt/appsec-github-watcher/internal/handlers"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	log.Info(fmt.Sprintf("Starting appsec-github-watcher"))

	webhookSecretKey := os.Getenv("GITHUB_WEBHOOK_SECRET_KEY")

	http.HandleFunc("/isready", handlers.HealthCheckHandler)
	http.HandleFunc("/isalive", handlers.HealthCheckHandler)
	http.HandleFunc("/memberEvent", func(w http.ResponseWriter, r *http.Request) {
		handlers.NewMemberHandler(w, r, webhookSecretKey)
	})

	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Error("Failed to start server", "error", err)
		panic(err)
	}
}
