package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JWTClaims struct {
	OrganizationID string `json:"org_id"`
	Email          string `json:"email"`
	SessionID      string `json:"session_id,omitempty"`
	Pending2FA     bool   `json:"pending_2fa,omitempty"`
	jwt.RegisteredClaims
}

// HashToken calculates the SHA-256 hex string of a raw JWT token
// Storing only the hash prevents raw token exposure in the database.
func HashToken(tokenString string) string {
	h := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(h[:])
}

// GenerateTokenWithSession creates a full session JWT embedding a specific session ID
func GenerateTokenWithSession(orgID uuid.UUID, email string, sessionID uuid.UUID, secret string) (string, error) {
	claims := JWTClaims{
		OrganizationID: orgID.String(),
		Email:          email,
		SessionID:      sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "burnerbox",
			Subject:   orgID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// GenerateToken creates a full session JWT for an organization
func GenerateToken(orgID uuid.UUID, email string, secret string) (string, error) {
	return GenerateTokenWithSession(orgID, email, uuid.New(), secret)
}

// GeneratePendingToken creates a short-lived scoped token for 2FA verification
func GeneratePendingToken(orgID uuid.UUID, email string, secret string) (string, error) {
	claims := JWTClaims{
		OrganizationID: orgID.String(),
		Email:          email,
		Pending2FA:     true,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "burnerbox",
			Subject:   orgID.String(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

// ValidateToken parses and validates a full session JWT (rejects pending 2FA tokens)
func ValidateToken(tokenString string, secret string) (*JWTClaims, error) {
	claims, err := parseToken(tokenString, secret)
	if err != nil {
		return nil, err
	}
	if claims.Pending2FA {
		return nil, errors.New("pending 2FA token is not a session token")
	}
	return claims, nil
}

// ValidatePendingToken validates a pending 2FA token specifically
func ValidatePendingToken(tokenString string, secret string) (*JWTClaims, error) {
	claims, err := parseToken(tokenString, secret)
	if err != nil {
		return nil, err
	}
	if !claims.Pending2FA {
		return nil, errors.New("token is not a pending 2FA token")
	}
	return claims, nil
}

func parseToken(tokenString string, secret string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})

	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
