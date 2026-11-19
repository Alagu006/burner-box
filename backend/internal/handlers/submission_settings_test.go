package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"burner-box-backend/internal/middleware"
	"burner-box-backend/internal/models"

	"github.com/google/uuid"
)

func TestCustomizationSettings_GetAndUpdate(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Customizable Press Org",
		Email:          "custom@press.test",
		SubmissionSlug: "custom-press-slug",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
		WelcomeMessage: "Default welcome message",
	}
	models.DB.Create(&org)

	token := CreateTestSessionToken(org.ID, org.Email)

	protected := app.Group("/api/v1/dashboard", middleware.Protected())
	protected.Get("/customization", GetCustomizationSettings)
	protected.Put("/customization", UpdateCustomizationSettings)

	app.Get("/api/v1/submit/:slug/public-key", GetOrganizationPublicKey)

	// 1. Get initial customization settings
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard/customization", nil)
	reqGet.Header.Set("Authorization", "Bearer "+token)
	respGet, err := app.Test(reqGet, 5000)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	if respGet.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", respGet.StatusCode)
	}

	// 2. Update customization with LogoURL and CustomFields
	updatePayload := map[string]interface{}{
		"welcome_message": "Welcome to our secure whistleblower inbox. Please provide your evidence below.",
		"logo_url":        "https://cdn.outlet.test/logos/whistleblower-desk.png",
		"custom_fields": []map[string]interface{}{
			{
				"id":         "field-1",
				"label":      "What department does this allegation involve?",
				"field_type": "text",
				"required":   true,
			},
			{
				"id":         "field-2",
				"label":      "Urgency Level",
				"field_type": "select",
				"options":    []string{"Low", "Medium", "High", "Critical Threat to Safety"},
				"required":   false,
			},
		},
	}
	body, _ := json.Marshal(updatePayload)

	reqPut := httptest.NewRequest(http.MethodPut, "/api/v1/dashboard/customization", bytes.NewReader(body))
	reqPut.Header.Set("Authorization", "Bearer "+token)
	reqPut.Header.Set("Content-Type", "application/json")
	respPut, err := app.Test(reqPut, 5000)
	if err != nil {
		t.Fatalf("PUT failed: %v", err)
	}
	if respPut.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK on update, got %d", respPut.StatusCode)
	}

	// 3. Verify public portal returns the customized fields
	reqPublic := httptest.NewRequest(http.MethodGet, "/api/v1/submit/custom-press-slug/public-key", nil)
	respPublic, _ := app.Test(reqPublic, 5000)
	if respPublic.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK on public endpoint, got %d", respPublic.StatusCode)
	}

	var pubData map[string]interface{}
	json.NewDecoder(respPublic.Body).Decode(&pubData)

	if pubData["welcome_message"] != "Welcome to our secure whistleblower inbox. Please provide your evidence below." {
		t.Errorf("Expected customized welcome message")
	}
	if pubData["logo_url"] != "https://cdn.outlet.test/logos/whistleblower-desk.png" {
		t.Errorf("Expected customized logo URL")
	}
	fields, ok := pubData["custom_fields"].([]interface{})
	if !ok || len(fields) != 2 {
		t.Fatalf("Expected 2 custom fields in public endpoint, got %v", fields)
	}
}

func TestCustomizationSettings_ValidatesLogoURLAndFieldTypes(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()

	org := models.Organization{
		ID:    uuid.New(),
		Name:  "Validation Org",
		Email: "validation@org.test",
	}
	models.DB.Create(&org)

	token := CreateTestSessionToken(org.ID, org.Email)

	protected := app.Group("/api/v1/dashboard", middleware.Protected())
	protected.Put("/customization", UpdateCustomizationSettings)

	// 1. Invalid Logo URL (javascript: or invalid scheme)
	badLogo := map[string]interface{}{
		"logo_url": "javascript:alert(1)",
	}
	body1, _ := json.Marshal(badLogo)
	req1 := httptest.NewRequest(http.MethodPut, "/api/v1/dashboard/customization", bytes.NewReader(body1))
	req1.Header.Set("Authorization", "Bearer "+token)
	req1.Header.Set("Content-Type", "application/json")
	resp1, _ := app.Test(req1, 5000)
	if resp1.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for javascript: logo URL, got %d", resp1.StatusCode)
	}

	// 2. Invalid Custom Field Type
	badType := map[string]interface{}{
		"custom_fields": []map[string]interface{}{
			{
				"label":      "Credit Card Number",
				"field_type": "dangerous_raw_input",
			},
		},
	}
	body2, _ := json.Marshal(badType)
	req2 := httptest.NewRequest(http.MethodPut, "/api/v1/dashboard/customization", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := app.Test(req2, 5000)
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request for invalid field_type, got %d", resp2.StatusCode)
	}
}
