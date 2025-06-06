package models

import (
	"time"

	"gorm.io/gorm"
)

// WebSecurityScan represents a comprehensive web security assessment
type WebSecurityScan struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	TargetURL    string    `gorm:"not null" json:"target_url"`
	ScanTypes    []string  `gorm:"type:text" json:"scan_types"` // Stored as JSON array
	Scope        string    `json:"scope"`                       // url, domain, subdomain
	MaxDepth     int       `json:"max_depth"`
	SessionToken string    `json:"session_token,omitempty"`
	Status       string    `gorm:"default:pending" json:"status"` // pending, running, completed, failed
	Progress     int       `gorm:"default:0" json:"progress"`      // 0-100
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	
	// Relationships
	Vulnerabilities []WebVulnerability `gorm:"foreignKey:ScanID" json:"vulnerabilities,omitempty"`
}

// WebVulnerability represents a discovered web application vulnerability
type WebVulnerability struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ScanID      uint      `gorm:"not null" json:"scan_id"`
	Type        string    `gorm:"not null" json:"type"`        // xss, sqli, csrf, ssrf, auth, crypto
	Severity    string    `gorm:"not null" json:"severity"`    // critical, high, medium, low, info
	Title       string    `gorm:"not null" json:"title"`
	Description string    `gorm:"type:text" json:"description"`
	URL         string    `gorm:"not null" json:"url"`
	Method      string    `json:"method"`                      // GET, POST, PUT, DELETE, etc.
	Parameter   string    `json:"parameter,omitempty"`         // Vulnerable parameter name
	Payload     string    `gorm:"type:text" json:"payload,omitempty"`     // Attack payload used
	Evidence    string    `gorm:"type:text" json:"evidence,omitempty"`    // Proof of vulnerability
	Impact      string    `gorm:"type:text" json:"impact,omitempty"`      // Potential impact
	Remediation string    `gorm:"type:text" json:"remediation,omitempty"` // Fix recommendations
	CVSS        float64   `json:"cvss,omitempty"`              // CVSS score
	CWE         string    `json:"cwe,omitempty"`               // CWE identifier
	OWASP       string    `json:"owasp,omitempty"`             // OWASP Top 10 category
	Verified    bool      `gorm:"default:false" json:"verified"` // Manual verification status
	FalsePositive bool    `gorm:"default:false" json:"false_positive"`
	
	// Relationships
	Scan WebSecurityScan `gorm:"foreignKey:ScanID" json:"scan,omitempty"`
}

// BinaryAnalysis represents a binary security analysis session
type BinaryAnalysis struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	BinaryPath   string    `gorm:"not null" json:"binary_path"`
	AnalysisType []string  `gorm:"type:text" json:"analysis_type"` // memory, binary, exploit
	SourcePath   string    `json:"source_path,omitempty"`
	Architecture string    `json:"architecture,omitempty"` // x86, x64, ARM, etc.
	Platform     string    `json:"platform,omitempty"`     // Linux, Windows, macOS
	Compiler     string    `json:"compiler,omitempty"`     // GCC, Clang, MSVC
	Status       string    `gorm:"default:pending" json:"status"` // pending, running, completed, failed
	Progress     int       `gorm:"default:0" json:"progress"`      // 0-100
	StartedAt    *time.Time `json:"started_at,omitempty"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	
	// Security Features Analysis
	ASLR         bool `json:"aslr"`          // Address Space Layout Randomization
	DEP          bool `json:"dep"`           // Data Execution Prevention
	StackCanary  bool `json:"stack_canary"`  // Stack canaries/cookies
	RELRO        bool `json:"relro"`         // Relocation Read-Only
	PIE          bool `json:"pie"`           // Position Independent Executable
	Fortify      bool `json:"fortify"`       // Fortify Source
	
	// Relationships
	Vulnerabilities []BinaryVulnerability `gorm:"foreignKey:AnalysisID" json:"vulnerabilities,omitempty"`
	Exploits        []ExploitCode         `gorm:"foreignKey:AnalysisID" json:"exploits,omitempty"`
}

// BinaryVulnerability represents a discovered binary vulnerability
type BinaryVulnerability struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	AnalysisID  uint      `gorm:"not null" json:"analysis_id"`
	Type        string    `gorm:"not null" json:"type"`        // buffer_overflow, use_after_free, etc.
	Severity    string    `gorm:"not null" json:"severity"`    // critical, high, medium, low
	Title       string    `gorm:"not null" json:"title"`
	Description string    `gorm:"type:text" json:"description"`
	Function    string    `json:"function,omitempty"`          // Vulnerable function name
	Address     string    `json:"address,omitempty"`           // Memory address
	SourceFile  string    `json:"source_file,omitempty"`       // Source file location
	LineNumber  int       `json:"line_number,omitempty"`       // Line number in source
	Evidence    string    `gorm:"type:text" json:"evidence,omitempty"`    // Debugging evidence
	Impact      string    `gorm:"type:text" json:"impact,omitempty"`      // Potential impact
	Remediation string    `gorm:"type:text" json:"remediation,omitempty"` // Fix recommendations
	Exploitable bool      `gorm:"default:false" json:"exploitable"`       // Can be exploited
	
	// Relationships
	Analysis BinaryAnalysis `gorm:"foreignKey:AnalysisID" json:"analysis,omitempty"`
}

// ExploitCode represents developed proof-of-concept exploits
type ExploitCode struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	AnalysisID  uint      `gorm:"not null" json:"analysis_id"`
	VulnID      uint      `json:"vuln_id,omitempty"`           // Related vulnerability
	Type        string    `gorm:"not null" json:"type"`        // buffer_overflow, rop_chain, etc.
	Language    string    `json:"language"`                    // C, Python, Assembly, etc.
	Code        string    `gorm:"type:text" json:"code"`       // Exploit source code
	Compiled    string    `json:"compiled,omitempty"`          // Path to compiled exploit
	Reliability float64   `json:"reliability"`                 // Success rate (0.0-1.0)
	Tested      bool      `gorm:"default:false" json:"tested"` // Has been tested
	Working     bool      `gorm:"default:false" json:"working"` // Confirmed working
	Notes       string    `gorm:"type:text" json:"notes,omitempty"`
	
	// Relationships
	Analysis      BinaryAnalysis       `gorm:"foreignKey:AnalysisID" json:"analysis,omitempty"`
	Vulnerability BinaryVulnerability  `gorm:"foreignKey:VulnID" json:"vulnerability,omitempty"`
}

// CodeReview represents an AI-powered security code review
type CodeReview struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Repository  string    `gorm:"not null" json:"repository"`
	FromCommit  string    `gorm:"not null" json:"from_commit"`
	ToCommit    string    `gorm:"not null" json:"to_commit"`
	PullRequest int       `json:"pull_request,omitempty"`
	ReviewType  string    `json:"review_type"`                    // security, full
	MaxCommits  int       `json:"max_commits"`
	Status      string    `gorm:"default:pending" json:"status"`  // pending, running, completed, failed
	Progress    int       `gorm:"default:0" json:"progress"`      // 0-100
	StartedAt   *time.Time `json:"started_at,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	
	// Review Results
	TotalCommits    int `json:"total_commits"`
	ReviewedCommits int `json:"reviewed_commits"`
	HighRiskChanges int `json:"high_risk_changes"`
	
	// Relationships
	Findings []CodeReviewFinding `gorm:"foreignKey:ReviewID" json:"findings,omitempty"`
}

// CodeReviewFinding represents a security finding from code review
type CodeReviewFinding struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	ReviewID    uint      `gorm:"not null" json:"review_id"`
	CommitHash  string    `gorm:"not null" json:"commit_hash"`
	FilePath    string    `gorm:"not null" json:"file_path"`
	LineNumber  int       `json:"line_number,omitempty"`
	RiskLevel   string    `gorm:"not null" json:"risk_level"`     // critical, high, medium, low
	Category    string    `gorm:"not null" json:"category"`       // auth, input_validation, crypto, etc.
	Title       string    `gorm:"not null" json:"title"`
	Description string    `gorm:"type:text" json:"description"`
	CodeSnippet string    `gorm:"type:text" json:"code_snippet"`
	Impact      string    `gorm:"type:text" json:"impact,omitempty"`
	Remediation string    `gorm:"type:text" json:"remediation,omitempty"`
	TestPlan    string    `gorm:"type:text" json:"test_plan,omitempty"` // Recommended security tests
	Reviewed    bool      `gorm:"default:false" json:"reviewed"`        // Manual review completed
	Dismissed   bool      `gorm:"default:false" json:"dismissed"`       // Finding dismissed
	
	// Relationships
	Review CodeReview `gorm:"foreignKey:ReviewID" json:"review,omitempty"`
}

// PayloadTest represents dynamic payload testing results
type PayloadTest struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	TargetURL   string    `gorm:"not null" json:"target_url"`
	PayloadType string    `gorm:"not null" json:"payload_type"` // xss, sqli, csrf, etc.
	Payload     string    `gorm:"type:text" json:"payload"`
	Method      string    `json:"method"`                       // GET, POST, etc.
	Parameter   string    `json:"parameter,omitempty"`
	Success     bool      `gorm:"default:false" json:"success"`
	ResponseCode int      `json:"response_code"`
	ResponseTime int      `json:"response_time"` // milliseconds
	Response     string   `gorm:"type:text" json:"response,omitempty"`
	Evidence     string   `gorm:"type:text" json:"evidence,omitempty"`
	Notes        string   `gorm:"type:text" json:"notes,omitempty"`
}

// Auto-migrate function for new models
func MigrateSecurityModels(db *gorm.DB) error {
	return db.AutoMigrate(
		&WebSecurityScan{},
		&WebVulnerability{},
		&BinaryAnalysis{},
		&BinaryVulnerability{},
		&ExploitCode{},
		&CodeReview{},
		&CodeReviewFinding{},
		&PayloadTest{},
	)
}