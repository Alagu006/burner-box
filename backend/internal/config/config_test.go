package config

import (
	"os"
	"testing"
)

// TestIsProductionLikeEnvironmentWithLookup validates environment classification
// using deterministic lookup tables without mutating global process state.
func TestIsProductionLikeEnvironmentWithLookup(t *testing.T) {
	cloudVars := []string{
		"FLY_APP_NAME",
		"KUBERNETES_SERVICE_HOST",
		"RENDER",
		"RAILWAY_ENVIRONMENT",
		"AWS_EXECUTION_ENV",
		"HEROKU_APP_ID",
		"DYNO",
		"GAE_APPLICATION",
		"K_SERVICE",
	}

	// 1. Explicit production-like labels without cloud indicators
	prodLabels := []string{
		"production", "Production", "PRODUCTION", " prod ",
		"staging", "Staging", "STAGE", "stage",
		"preview", "PREVIEW", "live", "LIVE",
	}
	emptyLookup := func(key string) (string, bool) { return "", false }
	for _, env := range prodLabels {
		if !IsProductionLikeEnvironmentWithLookup(env, emptyLookup) {
			t.Errorf("Expected IsProductionLikeEnvironmentWithLookup(%q) to be true", env)
		}
	}

	// 2. Local development labels without cloud indicators
	devLabels := []string{
		"development", "Development", "dev", "DEV",
		"testing", "test", "local", "", "   ",
	}
	for _, env := range devLabels {
		if IsProductionLikeEnvironmentWithLookup(env, emptyLookup) {
			t.Errorf("Expected IsProductionLikeEnvironmentWithLookup(%q) to be false", env)
		}
	}

	// 3. Regression Invariant: Every cloud indicator overrides ENVIRONMENT=development
	for _, cloudVar := range cloudVars {
		cloudLookup := func(key string) (string, bool) {
			if key == cloudVar {
				return "active-cloud-cluster", true
			}
			return "", false
		}

		// Cloud indicator with ENVIRONMENT=development -> MUST be production-like
		if !IsProductionLikeEnvironmentWithLookup("development", cloudLookup) {
			t.Errorf("SECURITY REGRESSION: Cloud indicator %s with ENVIRONMENT=development was downgraded", cloudVar)
		}
		// Cloud indicator with ENVIRONMENT=dev -> MUST be production-like
		if !IsProductionLikeEnvironmentWithLookup("dev", cloudLookup) {
			t.Errorf("SECURITY REGRESSION: Cloud indicator %s with ENVIRONMENT=dev was downgraded", cloudVar)
		}
		// Cloud indicator with ENVIRONMENT=local -> MUST be production-like
		if !IsProductionLikeEnvironmentWithLookup("local", cloudLookup) {
			t.Errorf("SECURITY REGRESSION: Cloud indicator %s with ENVIRONMENT=local was downgraded", cloudVar)
		}
		// Cloud indicator with ENVIRONMENT unset -> MUST be production-like
		if !IsProductionLikeEnvironmentWithLookup("", cloudLookup) {
			t.Errorf("SECURITY REGRESSION: Cloud indicator %s with unset ENVIRONMENT was downgraded", cloudVar)
		}
		// Cloud indicator with production label -> remains production-like
		if !IsProductionLikeEnvironmentWithLookup("production", cloudLookup) {
			t.Errorf("Expected cloud indicator %s with ENVIRONMENT=production to be true", cloudVar)
		}
	}
}

// TestIsProductionLikeEnvironment_ProcessEnv validates the process environment integration
// ensuring meticulous restoration of original environment state (including unset variables).
func TestIsProductionLikeEnvironment_ProcessEnv(t *testing.T) {
	cloudVars := []string{
		"FLY_APP_NAME",
		"KUBERNETES_SERVICE_HOST",
		"RENDER",
		"RAILWAY_ENVIRONMENT",
		"AWS_EXECUTION_ENV",
		"HEROKU_APP_ID",
		"DYNO",
		"GAE_APPLICATION",
		"K_SERVICE",
	}

	// Snapshot original process environment
	type envState struct {
		val   string
		isSet bool
	}
	savedState := make(map[string]envState)
	for _, v := range cloudVars {
		val, isSet := os.LookupEnv(v)
		savedState[v] = envState{val: val, isSet: isSet}
		os.Unsetenv(v)
	}

	// Defer rigorous restoration
	defer func() {
		for v, state := range savedState {
			if state.isSet {
				os.Setenv(v, state.val)
			} else {
				os.Unsetenv(v)
			}
		}
	}()

	// Verify local development with clean environment
	if IsProductionLikeEnvironment("development") {
		t.Errorf("Clean local development must not be classified as production-like")
	}
	if IsProductionLikeEnvironment("") {
		t.Errorf("Clean unset environment must not be classified as production-like")
	}

	// Verify each cloud indicator prevents downgrade
	for _, v := range cloudVars {
		os.Setenv(v, "active-cloud-marker")

		// Cloud indicator must override development label
		if !IsProductionLikeEnvironment("development") {
			t.Errorf("SECURITY REGRESSION: OS environment indicator %s did not override development", v)
		}
		if !IsProductionLikeEnvironment("dev") {
			t.Errorf("SECURITY REGRESSION: OS environment indicator %s did not override dev", v)
		}
		if !IsProductionLikeEnvironment("") {
			t.Errorf("SECURITY REGRESSION: OS environment indicator %s was not detected when env was empty", v)
		}

		os.Unsetenv(v)
	}
}
