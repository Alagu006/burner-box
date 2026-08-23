package handlers

import (
	"burner-box-backend/internal/models"

	"github.com/google/uuid"
)

// logActivity records a mutation event on a submission.
// It never stores submission content — only actor, action, and a short detail string.
func logActivity(submissionID, orgID uuid.UUID, actorEmail, actorRole, actionType, detail string) {
	activity := models.Activity{
		SubmissionID:   submissionID,
		OrganizationID: orgID,
		ActorEmail:     actorEmail,
		ActorRole:      actorRole,
		ActionType:     actionType,
		Detail:         detail,
	}
	models.DB.Create(&activity)
}
