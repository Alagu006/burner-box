package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"burner-box-backend/internal/middleware"
	"burner-box-backend/internal/models"

	"github.com/google/uuid"
)

func buildRBACApp() (*models.Organization, map[string]string) {
	orgID := uuid.New()
	org := &models.Organization{
		ID:             orgID,
		Name:           "RBAC Test Org",
		Email:          "admin@rbac.test",
		SubmissionSlug: "rbac-portal",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(org)

	// Create team members for reader and responder
	readerMember := models.TeamMember{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Email:          "reader@rbac.test",
		Role:           "reader",
		InvitedAt:      time.Now(),
	}
	models.DB.Create(&readerMember)

	responderMember := models.TeamMember{
		ID:             uuid.New(),
		OrganizationID: orgID,
		Email:          "responder@rbac.test",
		Role:           "responder",
		InvitedAt:      time.Now(),
	}
	models.DB.Create(&responderMember)

	// Generate session-backed JWT tokens for each role
	adminToken := CreateTestSessionToken(orgID, "admin@rbac.test")
	responderToken := CreateTestSessionToken(orgID, "responder@rbac.test")
	readerToken := CreateTestSessionToken(orgID, "reader@rbac.test")

	tokens := map[string]string{
		"admin":     adminToken,
		"responder": responderToken,
		"reader":    readerToken,
	}

	return org, tokens
}

func setupRBACRoutes() (*models.Organization, map[string]string, func(*http.Request) (*http.Response, error)) {
	org, tokens := buildRBACApp()
	app := setupTestApp()

	api := app.Group("/api/v1")
	protected := api.Group("/dashboard")
	protected.Use(middleware.Protected())
	protected.Use(middleware.ResolveRole())

	// Admin routes
	adminRole := middleware.RequireRole("admin")
	team := protected.Group("/team", adminRole)
	team.Post("/invite", InviteTeamMember)
	team.Delete("/:id", RemoveTeamMember)

	// Responder routes
	responderRole := middleware.RequireRole("responder")
	submissions := protected.Group("/submissions", responderRole)
	submissions.Put("/:id", UpdateSubmissionStatus)
	submissions.Post("/:id/reply", ReplyToSubmission)
	submissions.Get("/:id", GetSubmission)

	tester := func(req *http.Request) (*http.Response, error) {
		return app.Test(req, 5000)
	}

	return org, tokens, tester
}

func TestRBAC_ReaderRole_ForbiddenOnReply(t *testing.T) {
	setupTestDB(t)
	org, tokens, testClient := setupRBACRoutes()

	sub := models.Submission{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		AnonymousName:  "Crimson Fox-1111",
		ReplyPublicKey: "c3VibWl0dGVyLXJlcGx5LXB1YmxpYy1rZXk=",
		HasReplyKey:    true,
	}
	models.DB.Create(&sub)

	payload, _ := json.Marshal(map[string]string{
		"encrypted_message": "ZW5jcnlwdGVkLXJlcGx5",
		"encryption_meta":   `{"nonce":"1"}`,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/submissions/"+sub.ID.String()+"/reply", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tokens["reader"])
	req.Header.Set("Content-Type", "application/json")

	resp, err := testClient(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Security Assertion: Reader must be rejected with 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: Reader role was not forbidden from replying (got HTTP %d)", resp.StatusCode)
	}
}

func TestRBAC_ReaderRole_ForbiddenOnStatusUpdate(t *testing.T) {
	setupTestDB(t)
	org, tokens, testClient := setupRBACRoutes()

	sub := models.Submission{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		AnonymousName:  "Green Wolf-2222",
		Status:         "unread",
	}
	models.DB.Create(&sub)

	payload, _ := json.Marshal(map[string]string{
		"status": "actioned",
	})

	req := httptest.NewRequest(http.MethodPut, "/api/v1/dashboard/submissions/"+sub.ID.String(), bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tokens["reader"])
	req.Header.Set("Content-Type", "application/json")

	resp, err := testClient(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Security Assertion: Reader must be rejected with 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: Reader role was not forbidden from updating status (got HTTP %d)", resp.StatusCode)
	}
}

func TestRBAC_ReaderRole_ForbiddenOnTeamInvite(t *testing.T) {
	setupTestDB(t)
	_, tokens, testClient := setupRBACRoutes()

	payload, _ := json.Marshal(map[string]string{
		"email": "newuser@test.org",
		"role":  "reader",
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/team/invite", bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+tokens["reader"])
	req.Header.Set("Content-Type", "application/json")

	resp, err := testClient(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}

	// Security Assertion: Reader must be rejected with 403 Forbidden
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: Reader role was not forbidden from inviting team members (got HTTP %d)", resp.StatusCode)
	}
}

func TestRBAC_ResponderRole_AllowedOnStatusUpdateAndReply(t *testing.T) {
	setupTestDB(t)
	org, tokens, testClient := setupRBACRoutes()

	sub := models.Submission{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		AnonymousName:  "Amber Bear-3333",
		Status:         "unread",
		ReplyPublicKey: "c3VibWl0dGVyLXJlcGx5LXB1YmxpYy1rZXk=",
		HasReplyKey:    true,
	}
	models.DB.Create(&sub)

	// Status update should succeed (HTTP 200)
	statusPayload, _ := json.Marshal(map[string]string{"status": "read"})
	req1 := httptest.NewRequest(http.MethodPut, "/api/v1/dashboard/submissions/"+sub.ID.String(), bytes.NewReader(statusPayload))
	req1.Header.Set("Authorization", "Bearer "+tokens["responder"])
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := testClient(req1)
	if err != nil || resp1.StatusCode != http.StatusOK {
		t.Fatalf("Expected responder to be allowed to update status (got HTTP %d, err %v)", resp1.StatusCode, err)
	}

	// Reply should succeed (HTTP 201)
	replyPayload, _ := json.Marshal(map[string]string{
		"encrypted_message": "ZW5jcnlwdGVkLXJlcGx5",
		"encryption_meta":   `{"nonce":"1"}`,
	})
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/submissions/"+sub.ID.String()+"/reply", bytes.NewReader(replyPayload))
	req2.Header.Set("Authorization", "Bearer "+tokens["responder"])
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := testClient(req2)
	if err != nil || resp2.StatusCode != http.StatusCreated {
		t.Fatalf("Expected responder to be allowed to send encrypted reply (got HTTP %d, err %v)", resp2.StatusCode, err)
	}
}

func TestRBAC_ResponderRole_ForbiddenOnTeamManagement(t *testing.T) {
	setupTestDB(t)
	org, tokens, testClient := setupRBACRoutes()

	// Invite team member should be 403
	invitePayload, _ := json.Marshal(map[string]string{
		"email": "hacker@test.org",
		"role":  "admin",
	})
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/team/invite", bytes.NewReader(invitePayload))
	req1.Header.Set("Authorization", "Bearer "+tokens["responder"])
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := testClient(req1)
	if err != nil || resp1.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: Responder role was not forbidden from team invite (got HTTP %d)", resp1.StatusCode)
	}

	// Delete team member should be 403
	member := models.TeamMember{
		ID:             uuid.New(),
		OrganizationID: org.ID,
		Email:          "victim@test.org",
		Role:           "reader",
	}
	models.DB.Create(&member)

	req2 := httptest.NewRequest(http.MethodDelete, "/api/v1/dashboard/team/"+member.ID.String(), nil)
	req2.Header.Set("Authorization", "Bearer "+tokens["responder"])

	resp2, err := testClient(req2)
	if err != nil || resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("SECURITY VIOLATION: Responder role was not forbidden from deleting team members (got HTTP %d)", resp2.StatusCode)
	}
}

func TestRBAC_AdminRole_AllowedOnAllOperations(t *testing.T) {
	setupTestDB(t)
	_, tokens, testClient := setupRBACRoutes()

	// Admin invite team member should succeed (201)
	invitePayload, _ := json.Marshal(map[string]string{
		"email": "newmember@test.org",
		"role":  "responder",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/dashboard/team/invite", bytes.NewReader(invitePayload))
	req.Header.Set("Authorization", "Bearer "+tokens["admin"])
	req.Header.Set("Content-Type", "application/json")

	resp, err := testClient(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected admin to be allowed on team invite (got HTTP %d, err %v)", resp.StatusCode, err)
	}
}
