package handlers

import (
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"

	"github.com/ghostsecurity/reaper/internal/database/models"
	"github.com/ghostsecurity/reaper/internal/types"
)

// CreateWebSecurityScan initiates a comprehensive web security scan
func (h *Handler) CreateWebSecurityScan(c *fiber.Ctx) error {
	var req struct {
		TargetURL    string   `json:"target_url"`
		ScanTypes    []string `json:"scan_types"` // xss, sqli, csrf, ssrf, auth, crypto
		Scope        string   `json:"scope"`      // url, domain, subdomain
		MaxDepth     int      `json:"max_depth"`
		SessionToken string   `json:"session_token,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Create web security scan record
	scan := models.WebSecurityScan{
		TargetURL:    req.TargetURL,
		ScanTypes:    req.ScanTypes,
		Scope:        req.Scope,
		MaxDepth:     req.MaxDepth,
		SessionToken: req.SessionToken,
		Status:       "pending",
	}

	result := h.db.Create(&scan)
	if result.Error != nil {
		slog.Error("Failed to create web security scan", "error", result.Error)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create scan"})
	}

	// Broadcast scan start message
	message := &types.WebSecurityMessage{
		Type:   types.MessageTypeWebSecurityScanStart,
		ScanID: scan.ID,
		Status: "started",
	}
	h.pool.Broadcast <- message

	return c.JSON(fiber.Map{
		"scan_id": scan.ID,
		"status":  "started",
		"message": "Web security scan initiated",
	})
}

// GetWebSecurityResults retrieves results from a web security scan
func (h *Handler) GetWebSecurityResults(c *fiber.Ctx) error {
	scanID := c.Params("id")

	var scan models.WebSecurityScan
	result := h.db.Preload("Vulnerabilities").First(&scan, scanID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return c.Status(404).JSON(fiber.Map{"error": "Scan not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(scan)
}

// GetWebVulnerabilities retrieves all web vulnerabilities found
func (h *Handler) GetWebVulnerabilities(c *fiber.Ctx) error {
	var vulnerabilities []models.WebVulnerability

	query := h.db.Order("created_at DESC")

	// Apply filters
	if severity := c.Query("severity"); severity != "" {
		query = query.Where("severity = ?", severity)
	}
	if vulnType := c.Query("type"); vulnType != "" {
		query = query.Where("type = ?", vulnType)
	}
	if domain := c.Query("domain"); domain != "" {
		query = query.Where("url LIKE ?", "%"+domain+"%")
	}

	result := query.Find(&vulnerabilities)
	if result.Error != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(vulnerabilities)
}

// CreateBinaryAnalysis initiates binary security analysis
func (h *Handler) CreateBinaryAnalysis(c *fiber.Ctx) error {
	var req struct {
		BinaryPath   string   `json:"binary_path"`
		AnalysisType []string `json:"analysis_type"` // memory, binary, exploit
		SourcePath   string   `json:"source_path,omitempty"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Create binary analysis record
	analysis := models.BinaryAnalysis{
		BinaryPath:   req.BinaryPath,
		AnalysisType: req.AnalysisType,
		SourcePath:   req.SourcePath,
		Status:       "pending",
	}

	result := h.db.Create(&analysis)
	if result.Error != nil {
		slog.Error("Failed to create binary analysis", "error", result.Error)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create analysis"})
	}

	// Broadcast analysis start message
	message := &types.BinaryAnalysisMessage{
		Type:       types.MessageTypeBinaryAnalysisStart,
		AnalysisID: analysis.ID,
		Status:     "started",
	}
	h.pool.Broadcast <- message

	return c.JSON(fiber.Map{
		"analysis_id": analysis.ID,
		"status":      "started",
		"message":     "Binary analysis initiated",
	})
}

// GetBinaryResults retrieves results from binary analysis
func (h *Handler) GetBinaryResults(c *fiber.Ctx) error {
	analysisID := c.Params("id")

	var analysis models.BinaryAnalysis
	result := h.db.Preload("Vulnerabilities").First(&analysis, analysisID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return c.Status(404).JSON(fiber.Map{"error": "Analysis not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(analysis)
}

// UploadBinary handles binary file uploads for analysis
func (h *Handler) UploadBinary(c *fiber.Ctx) error {
	file, err := c.FormFile("binary")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "No file uploaded"})
	}

	// Save uploaded file
	uploadPath := "./uploads/binaries/" + file.Filename
	if err := c.SaveFile(file, uploadPath); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "Failed to save file"})
	}

	return c.JSON(fiber.Map{
		"filename": file.Filename,
		"path":     uploadPath,
		"size":     file.Size,
		"message":  "Binary uploaded successfully",
	})
}

// CreateCodeReview initiates AI-powered code security review
func (h *Handler) CreateCodeReview(c *fiber.Ctx) error {
	var req struct {
		Repository   string `json:"repository"`
		FromCommit   string `json:"from_commit"`
		ToCommit     string `json:"to_commit"`
		PullRequest  int    `json:"pull_request,omitempty"`
		ReviewType   string `json:"review_type"` // security, full
		MaxCommits   int    `json:"max_commits"`
	}

	if err := c.BodyParser(&req); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "Invalid request body"})
	}

	// Create code review record
	review := models.CodeReview{
		Repository:  req.Repository,
		FromCommit:  req.FromCommit,
		ToCommit:    req.ToCommit,
		PullRequest: req.PullRequest,
		ReviewType:  req.ReviewType,
		MaxCommits:  req.MaxCommits,
		Status:      "pending",
	}

	result := h.db.Create(&review)
	if result.Error != nil {
		slog.Error("Failed to create code review", "error", result.Error)
		return c.Status(500).JSON(fiber.Map{"error": "Failed to create review"})
	}

	// Broadcast review start message
	message := &types.CodeReviewMessage{
		Type:     types.MessageTypeCodeReviewStart,
		ReviewID: review.ID,
		Status:   "started",
	}
	h.pool.Broadcast <- message

	return c.JSON(fiber.Map{
		"review_id": review.ID,
		"status":    "started",
		"message":   "Code review initiated",
	})
}

// GetCodeReviewResults retrieves results from code security review
func (h *Handler) GetCodeReviewResults(c *fiber.Ctx) error {
	reviewID := c.Params("id")

	var review models.CodeReview
	result := h.db.Preload("Findings").First(&review, reviewID)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return c.Status(404).JSON(fiber.Map{"error": "Review not found"})
		}
		return c.Status(500).JSON(fiber.Map{"error": "Database error"})
	}

	return c.JSON(review)
}