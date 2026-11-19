package models

import (
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func ConnectDatabase(databaseURL string) {
	var err error

	DB, err = gorm.Open(postgres.Open(databaseURL), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info), // Log SQL queries in development
	})

	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	log.Println("✅ Connected to PostgreSQL database")

	// Auto-migrate tables (creates tables if they don't exist)
	err = DB.AutoMigrate(
		&Organization{},
		&Session{},
		&TeamMember{},
		&Submission{},
		&SubmissionFile{},
		&Reply{},
		&SubmissionMessage{},
		&InternalNote{},
		&Activity{},
		&Room{},
		&RoomMessage{},
		&RoomFile{},
		&RoomReaction{},
		&DeadMansSwitch{},
		&MerkleBatch{},
		&MerkleLeaf{},
	)
	if err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	log.Println("✅ Database tables migrated")
}
