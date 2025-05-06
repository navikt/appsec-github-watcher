package main

import (
	"os"
	"testing"
)

func TestIsFeatureEnabled(t *testing.T) {
	testCases := []struct {
		name          string
		envValue      string
		expectEnabled bool
	}{
		{"empty value", "", false},
		{"value true", "true", true},
		{"value TRUE (uppercase)", "TRUE", true},
		{"value True (mixed case)", "True", true},
		{"value yes", "yes", true},
		{"value 1", "1", true},
		{"value on", "on", true},
		{"value false", "false", false},
		{"value no", "no", false},
		{"value 0", "0", false},
		{"value off", "off", false},
		{"invalid value", "invalid", false},
	}

	const testEnvVar = "TEST_FEATURE_TOGGLE"

	// Save original env var to restore later
	origValue := os.Getenv(testEnvVar)
	defer os.Setenv(testEnvVar, origValue)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable for this test case
			os.Setenv(testEnvVar, tc.envValue)

			// Test the feature toggle function
			result := isFeatureEnabled(testEnvVar)

			if result != tc.expectEnabled {
				t.Errorf("isFeatureEnabled(%q) = %v, want %v", tc.envValue, result, tc.expectEnabled)
			}
		})
	}
}
