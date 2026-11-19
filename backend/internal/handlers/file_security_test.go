package handlers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"burner-box-backend/internal/models"

	"github.com/google/uuid"
)

func TestFileUpload_RejectsMismatchedExtensionContent_ExeDisguisedAsJpg(t *testing.T) {
	// MZ header for Windows executable / DLL
	fakeExeBytes := []byte{0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00}
	fakeExeBytes = append(fakeExeBytes, bytes.Repeat([]byte{0x00}, 500)...)

	// Claiming extension is .jpg
	_, err := validateFileType(fakeExeBytes, ".jpg")

	// Security Assertion: Must reject with error
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: Executable disguised as .jpg was accepted by validateFileType!")
	}
}

func TestFileUpload_RejectsMismatchedExtensionContent_HtmlDisguisedAsPdf(t *testing.T) {
	// HTML / JavaScript payload disguised as PDF
	fakeHtmlBytes := []byte("<!DOCTYPE html><html><head><script>alert('xss');</script></head><body>evil</body></html>")

	_, err := validateFileType(fakeHtmlBytes, ".pdf")

	// Security Assertion: Must reject with error
	if err == nil {
		t.Fatalf("SECURITY VIOLATION: HTML/Script disguised as .pdf was accepted by validateFileType!")
	}
}

func TestFileUpload_AcceptsValidMagicBytes_Jpeg(t *testing.T) {
	// Valid JPEG magic header (FF D8 FF E0 00 10 4A 46 49 46)
	validJpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x60}
	validJpeg = append(validJpeg, bytes.Repeat([]byte{0xAA}, 600)...)

	mime, err := validateFileType(validJpeg, ".jpg")
	if err != nil {
		t.Fatalf("Expected valid JPEG to be accepted, got error: %v", err)
	}
	if mime != "image/jpeg" {
		t.Errorf("Expected mime 'image/jpeg', got %s", mime)
	}
}

func TestFileUpload_AcceptsValidMagicBytes_Png(t *testing.T) {
	// Valid PNG magic header (89 50 4E 47 0D 0A 1A 0A)
	validPng := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 0x49, 0x48, 0x44, 0x52}
	validPng = append(validPng, bytes.Repeat([]byte{0xBB}, 600)...)

	mime, err := validateFileType(validPng, ".png")
	if err != nil {
		t.Fatalf("Expected valid PNG to be accepted, got error: %v", err)
	}
	if mime != "image/png" {
		t.Errorf("Expected mime 'image/png', got %s", mime)
	}
}

func TestFileUpload_AcceptsValidMagicBytes_Pdf(t *testing.T) {
	// Valid PDF header (%PDF-1.4)
	validPdf := []byte("%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n")
	validPdf = append(validPdf, bytes.Repeat([]byte{0x20}, 500)...)

	mime, err := validateFileType(validPdf, ".pdf")
	if err != nil {
		t.Fatalf("Expected valid PDF to be accepted, got error: %v", err)
	}
	if mime != "application/pdf" {
		t.Errorf("Expected mime 'application/pdf', got %s", mime)
	}
}

func TestFileUpload_AcceptsValidMagicBytes_Wav(t *testing.T) {
	// Valid RIFF WAVE header (RIFF....WAVEfmt )
	validWav := []byte("RIFF\x24\x00\x00\x00WAVEfmt \x10\x00\x00\x00\x01\x00\x01\x00\x44\xAC\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00data\x00\x00\x00\x00")
	validWav = append(validWav, bytes.Repeat([]byte{0x00}, 500)...)

	mime, err := validateFileType(validWav, ".wav")
	if err != nil {
		t.Fatalf("Expected valid WAV to be accepted, got error: %v", err)
	}
	if mime != "audio/wave" && mime != "audio/wav" && mime != "audio/x-wav" {
		t.Errorf("Expected wave mime type, got %s", mime)
	}
}

func TestFileUpload_RejectsDisguisedFileInMultipartUpload(t *testing.T) {
	setupTestDB(t)
	app := setupTestApp()
	app.Post("/api/v1/submit/:slug", SubmitAnonymousTip)

	org := models.Organization{
		ID:             uuid.New(),
		Name:           "Upload Audit Org",
		Email:          "upload@audit.test",
		SubmissionSlug: "upload-portal",
		PublicKey:      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA",
	}
	models.DB.Create(&org)

	// Create multipart form with an encrypted message AND a disguised file
	var b bytes.Buffer
	w := multipart.NewWriter(&b)

	w.WriteField("encrypted_message", "dGVzdC1jaXBoZXJ0ZXh0")
	w.WriteField("encryption_meta", `{"nonce":"123"}`)

	// Add file: name says .jpg, but content is HTML
	fw, err := w.CreateFormFile("files", "malicious_script.jpg")
	if err != nil {
		t.Fatalf("CreateFormFile failed: %v", err)
	}
	fw.Write([]byte("<!DOCTYPE html><html><script>alert('exploit')</script></html>"))
	w.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/submit/upload-portal", &b)
	req.Header.Set("Content-Type", w.FormDataContentType())

	resp, err := app.Test(req, 5000)
	if err != nil {
		t.Fatalf("Multipart request failed: %v", err)
	}

	// Security Assertion: Disguised file upload must be rejected with 400 Bad Request
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("SECURITY VIOLATION: Expected 400 Bad Request for mismatched magic bytes in upload, got %d", resp.StatusCode)
	}
}
