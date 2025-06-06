package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

// SwarmHandler handles swarm-related API endpoints
type SwarmHandler struct {
	db *gorm.DB
}

// NewSwarmHandler creates a new swarm handler
func NewSwarmHandler(db *gorm.DB) *SwarmHandler {
	return &SwarmHandler{db: db}
}

// SwarmEvent represents an event from the Python swarm coordinator
type SwarmEvent struct {
	EventType string                 `json:"event_type"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// SwarmAgent represents an agent in the swarm
type SwarmAgent struct {
	ID           uint      `json:"id" gorm:"primaryKey"`
	AgentID      string    `json:"agent_id" gorm:"uniqueIndex"`
	AgentType    string    `json:"agent_type"`
	Codename     string    `json:"codename"`
	Status       string    `json:"status"`
	Capabilities []string  `json:"capabilities" gorm:"serializer:json"`
	CurrentTask  *string   `json:"current_task"`
	LastSeen     time.Time `json:"last_seen"`
	Metadata     string    `json:"metadata" gorm:"type:jsonb"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// SwarmTask represents a task in the swarm
type SwarmTask struct {
	ID          uint                   `json:"id" gorm:"primaryKey"`
	TaskID      string                 `json:"task_id" gorm:"uniqueIndex"`
	AgentType   string                 `json:"agent_type"`
	TaskType    string                 `json:"task_type"`
	Target      string                 `json:"target"`
	Parameters  map[string]interface{} `json:"parameters" gorm:"serializer:json"`
	Priority    string                 `json:"priority"`
	Status      string                 `json:"status"`
	Result      string                 `json:"result" gorm:"type:jsonb"`
	Error       *string                `json:"error"`
	CreatedAt   time.Time              `json:"created_at"`
	AssignedAt  *time.Time             `json:"assigned_at"`
	CompletedAt *time.Time             `json:"completed_at"`
}

// SwarmVulnerability represents a vulnerability found by the swarm
type SwarmVulnerability struct {
	ID               uint                   `json:"id" gorm:"primaryKey"`
	VulnID           string                 `json:"vuln_id" gorm:"uniqueIndex"`
	Discoverer       string                 `json:"discoverer"`
	VulnerabilityType string                `json:"vulnerability_type"`
	Severity         string                 `json:"severity"`
	Target           string                 `json:"target"`
	Description      string                 `json:"description"`
	Evidence         map[string]interface{} `json:"evidence" gorm:"serializer:json"`
	Remediation      string                 `json:"remediation"`
	Confidence       float64                `json:"confidence"`
	Verified         bool                   `json:"verified"`
	Exploitable      bool                   `json:"exploitable"`
	DiscoveredAt     time.Time              `json:"discovered_at"`
	CreatedAt        time.Time              `json:"created_at"`
	UpdatedAt        time.Time              `json:"updated_at"`
}

// SwarmMetrics represents swarm performance metrics
type SwarmMetrics struct {
	ID                  uint      `json:"id" gorm:"primaryKey"`
	TotalAgents         int       `json:"total_agents"`
	ActiveAgents        int       `json:"active_agents"`
	TasksCompleted      int       `json:"tasks_completed"`
	VulnerabilitiesFound int      `json:"vulnerabilities_found"`
	AverageResponseTime float64   `json:"average_response_time"`
	SuccessRate         float64   `json:"success_rate"`
	Uptime              float64   `json:"uptime"`
	Timestamp           time.Time `json:"timestamp"`
	CreatedAt           time.Time `json:"created_at"`
}

// RegisterSwarmRoutes registers all swarm-related routes
func (h *SwarmHandler) RegisterSwarmRoutes(app *fiber.App) {
	swarm := app.Group("/api/swarm")

	// Event handling
	swarm.Post("/events", h.HandleSwarmEvent)
	
	// Agent management
	swarm.Get("/agents", h.GetAgents)
	swarm.Get("/agents/:id", h.GetAgent)
	swarm.Post("/agents", h.CreateAgent)
	swarm.Put("/agents/:id", h.UpdateAgent)
	swarm.Delete("/agents/:id", h.DeleteAgent)
	
	// Task management
	swarm.Get("/tasks", h.GetTasks)
	swarm.Get("/tasks/:id", h.GetTask)
	swarm.Post("/tasks", h.CreateTask)
	swarm.Put("/tasks/:id", h.UpdateTask)
	swarm.Delete("/tasks/:id", h.DeleteTask)
	
	// Vulnerability management
	swarm.Get("/vulnerabilities", h.GetVulnerabilities)
	swarm.Get("/vulnerabilities/:id", h.GetVulnerability)
	swarm.Post("/vulnerabilities", h.CreateVulnerability)
	swarm.Put("/vulnerabilities/:id", h.UpdateVulnerability)
	
	// Metrics and monitoring
	swarm.Get("/metrics", h.GetMetrics)
	swarm.Get("/status", h.GetSwarmStatus)
	
	// WebSocket for real-time updates
	swarm.Get("/ws", h.HandleWebSocket)
}

// HandleSwarmEvent processes events from the Python swarm coordinator
func (h *SwarmHandler) HandleSwarmEvent(c *fiber.Ctx) error {
	var event SwarmEvent
	if err := c.BodyParser(&event); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid event format",
		})
	}

	// Process different event types
	switch event.EventType {
	case "agent_registered":
		return h.handleAgentRegistered(c, event.Data)
	case "swarm_message":
		return h.handleSwarmMessage(c, event.Data)
	case "swarm_metrics":
		return h.handleSwarmMetrics(c, event.Data)
	case "swarm_state":
		return h.handleSwarmState(c, event.Data)
	default:
		// Log unknown event type but don't error
		return c.JSON(fiber.Map{"status": "received"})
	}
}

func (h *SwarmHandler) handleAgentRegistered(c *fiber.Ctx, data map[string]interface{}) error {
	agentID, ok := data["agent_id"].(string)
	if !ok {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "Invalid agent_id"})
	}

	agentType, _ := data["agent_type"].(string)
	codename, _ := data["codename"].(string)
	capabilities, _ := data["capabilities"].([]interface{})

	// Convert capabilities to string slice
	capStrings := make([]string, len(capabilities))
	for i, cap := range capabilities {
		if capStr, ok := cap.(string); ok {
			capStrings[i] = capStr
		}
	}

	agent := SwarmAgent{
		AgentID:      agentID,
		AgentType:    agentType,
		Codename:     codename,
		Status:       "idle",
		Capabilities: capStrings,
		LastSeen:     time.Now(),
		Metadata:     "{}",
	}

	// Upsert agent
	result := h.db.Where("agent_id = ?", agentID).FirstOrCreate(&agent)
	if result.Error != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to register agent",
		})
	}

	return c.JSON(fiber.Map{"status": "registered", "agent": agent})
}

func (h *SwarmHandler) handleSwarmMessage(c *fiber.Ctx, data map[string]interface{}) error {
	// Store swarm messages for audit trail
	messageJSON, _ := json.Marshal(data)
	
	// You could store this in a messages table if needed
	// For now, just acknowledge receipt
	
	return c.JSON(fiber.Map{"status": "message_received"})
}

func (h *SwarmHandler) handleSwarmMetrics(c *fiber.Ctx, data map[string]interface{}) error {
	metrics := SwarmMetrics{
		TotalAgents:         int(data["total_agents"].(float64)),
		ActiveAgents:        int(data["active_agents"].(float64)),
		TasksCompleted:      int(data["tasks_completed"].(float64)),
		VulnerabilitiesFound: int(data["vulnerabilities_found"].(float64)),
		AverageResponseTime: data["average_response_time"].(float64),
		SuccessRate:         data["success_rate"].(float64),
		Uptime:              data["uptime"].(float64),
		Timestamp:           time.Now(),
	}

	if err := h.db.Create(&metrics).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to store metrics",
		})
	}

	return c.JSON(fiber.Map{"status": "metrics_stored"})
}

func (h *SwarmHandler) handleSwarmState(c *fiber.Ctx, data map[string]interface{}) error {
	// Update agents, tasks, and vulnerabilities from swarm state
	
	// Update agents
	if agents, ok := data["agents"].([]interface{}); ok {
		for _, agentData := range agents {
			if agentMap, ok := agentData.(map[string]interface{}); ok {
				h.updateAgentFromState(agentMap)
			}
		}
	}

	// Update tasks
	if tasks, ok := data["tasks"].([]interface{}); ok {
		for _, taskData := range tasks {
			if taskMap, ok := taskData.(map[string]interface{}); ok {
				h.updateTaskFromState(taskMap)
			}
		}
	}

	// Update vulnerabilities
	if vulns, ok := data["vulnerabilities"].([]interface{}); ok {
		for _, vulnData := range vulns {
			if vulnMap, ok := vulnData.(map[string]interface{}); ok {
				h.updateVulnerabilityFromState(vulnMap)
			}
		}
	}

	return c.JSON(fiber.Map{"status": "state_updated"})
}

func (h *SwarmHandler) updateAgentFromState(data map[string]interface{}) {
	agentID, ok := data["agent_id"].(string)
	if !ok {
		return
	}

	var agent SwarmAgent
	if err := h.db.Where("agent_id = ?", agentID).First(&agent).Error; err != nil {
		return
	}

	// Update agent fields
	if status, ok := data["status"].(string); ok {
		agent.Status = status
	}
	if currentTask, ok := data["current_task"].(string); ok {
		agent.CurrentTask = &currentTask
	}
	agent.LastSeen = time.Now()

	h.db.Save(&agent)
}

func (h *SwarmHandler) updateTaskFromState(data map[string]interface{}) {
	taskID, ok := data["id"].(string)
	if !ok {
		return
	}

	task := SwarmTask{
		TaskID:    taskID,
		AgentType: data["agent_type"].(string),
		TaskType:  data["task_type"].(string),
		Target:    data["target"].(string),
		Priority:  data["priority"].(string),
		Status:    data["status"].(string),
	}

	if params, ok := data["parameters"].(map[string]interface{}); ok {
		task.Parameters = params
	}

	h.db.Where("task_id = ?", taskID).FirstOrCreate(&task)
}

func (h *SwarmHandler) updateVulnerabilityFromState(data map[string]interface{}) {
	vulnID, ok := data["id"].(string)
	if !ok {
		return
	}

	vuln := SwarmVulnerability{
		VulnID:            vulnID,
		Discoverer:        data["discoverer"].(string),
		VulnerabilityType: data["vulnerability_type"].(string),
		Severity:          data["severity"].(string),
		Target:            data["target"].(string),
		Description:       data["description"].(string),
		Remediation:       data["remediation"].(string),
		Confidence:        data["confidence"].(float64),
		Verified:          data["verified"].(bool),
		Exploitable:       data["exploitable"].(bool),
	}

	if evidence, ok := data["evidence"].(map[string]interface{}); ok {
		vuln.Evidence = evidence
	}

	h.db.Where("vuln_id = ?", vulnID).FirstOrCreate(&vuln)
}

// CRUD operations for agents
func (h *SwarmHandler) GetAgents(c *fiber.Ctx) error {
	var agents []SwarmAgent
	if err := h.db.Find(&agents).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch agents",
		})
	}
	return c.JSON(agents)
}

func (h *SwarmHandler) GetAgent(c *fiber.Ctx) error {
	id := c.Params("id")
	var agent SwarmAgent
	if err := h.db.Where("agent_id = ?", id).First(&agent).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Agent not found",
		})
	}
	return c.JSON(agent)
}

func (h *SwarmHandler) CreateAgent(c *fiber.Ctx) error {
	var agent SwarmAgent
	if err := c.BodyParser(&agent); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid agent data",
		})
	}

	if err := h.db.Create(&agent).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create agent",
		})
	}

	return c.Status(http.StatusCreated).JSON(agent)
}

func (h *SwarmHandler) UpdateAgent(c *fiber.Ctx) error {
	id := c.Params("id")
	var agent SwarmAgent
	if err := h.db.Where("agent_id = ?", id).First(&agent).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Agent not found",
		})
	}

	if err := c.BodyParser(&agent); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid agent data",
		})
	}

	if err := h.db.Save(&agent).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update agent",
		})
	}

	return c.JSON(agent)
}

func (h *SwarmHandler) DeleteAgent(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.db.Where("agent_id = ?", id).Delete(&SwarmAgent{}).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete agent",
		})
	}
	return c.JSON(fiber.Map{"status": "deleted"})
}

// CRUD operations for tasks
func (h *SwarmHandler) GetTasks(c *fiber.Ctx) error {
	var tasks []SwarmTask
	if err := h.db.Find(&tasks).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch tasks",
		})
	}
	return c.JSON(tasks)
}

func (h *SwarmHandler) GetTask(c *fiber.Ctx) error {
	id := c.Params("id")
	var task SwarmTask
	if err := h.db.Where("task_id = ?", id).First(&task).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Task not found",
		})
	}
	return c.JSON(task)
}

func (h *SwarmHandler) CreateTask(c *fiber.Ctx) error {
	var task SwarmTask
	if err := c.BodyParser(&task); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid task data",
		})
	}

	if err := h.db.Create(&task).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create task",
		})
	}

	return c.Status(http.StatusCreated).JSON(task)
}

func (h *SwarmHandler) UpdateTask(c *fiber.Ctx) error {
	id := c.Params("id")
	var task SwarmTask
	if err := h.db.Where("task_id = ?", id).First(&task).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Task not found",
		})
	}

	if err := c.BodyParser(&task); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid task data",
		})
	}

	if err := h.db.Save(&task).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update task",
		})
	}

	return c.JSON(task)
}

func (h *SwarmHandler) DeleteTask(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := h.db.Where("task_id = ?", id).Delete(&SwarmTask{}).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to delete task",
		})
	}
	return c.JSON(fiber.Map{"status": "deleted"})
}

// CRUD operations for vulnerabilities
func (h *SwarmHandler) GetVulnerabilities(c *fiber.Ctx) error {
	var vulns []SwarmVulnerability
	if err := h.db.Find(&vulns).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch vulnerabilities",
		})
	}
	return c.JSON(vulns)
}

func (h *SwarmHandler) GetVulnerability(c *fiber.Ctx) error {
	id := c.Params("id")
	var vuln SwarmVulnerability
	if err := h.db.Where("vuln_id = ?", id).First(&vuln).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Vulnerability not found",
		})
	}
	return c.JSON(vuln)
}

func (h *SwarmHandler) CreateVulnerability(c *fiber.Ctx) error {
	var vuln SwarmVulnerability
	if err := c.BodyParser(&vuln); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid vulnerability data",
		})
	}

	if err := h.db.Create(&vuln).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to create vulnerability",
		})
	}

	return c.Status(http.StatusCreated).JSON(vuln)
}

func (h *SwarmHandler) UpdateVulnerability(c *fiber.Ctx) error {
	id := c.Params("id")
	var vuln SwarmVulnerability
	if err := h.db.Where("vuln_id = ?", id).First(&vuln).Error; err != nil {
		return c.Status(http.StatusNotFound).JSON(fiber.Map{
			"error": "Vulnerability not found",
		})
	}

	if err := c.BodyParser(&vuln); err != nil {
		return c.Status(http.StatusBadRequest).JSON(fiber.Map{
			"error": "Invalid vulnerability data",
		})
	}

	if err := h.db.Save(&vuln).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to update vulnerability",
		})
	}

	return c.JSON(vuln)
}

// Metrics and monitoring
func (h *SwarmHandler) GetMetrics(c *fiber.Ctx) error {
	var metrics []SwarmMetrics
	if err := h.db.Order("created_at desc").Limit(100).Find(&metrics).Error; err != nil {
		return c.Status(http.StatusInternalServerError).JSON(fiber.Map{
			"error": "Failed to fetch metrics",
		})
	}
	return c.JSON(metrics)
}

func (h *SwarmHandler) GetSwarmStatus(c *fiber.Ctx) error {
	var agentCount int64
	var activeAgentCount int64
	var taskCount int64
	var vulnCount int64

	h.db.Model(&SwarmAgent{}).Count(&agentCount)
	h.db.Model(&SwarmAgent{}).Where("status != ?", "offline").Count(&activeAgentCount)
	h.db.Model(&SwarmTask{}).Count(&taskCount)
	h.db.Model(&SwarmVulnerability{}).Count(&vulnCount)

	status := fiber.Map{
		"total_agents":         agentCount,
		"active_agents":        activeAgentCount,
		"total_tasks":          taskCount,
		"total_vulnerabilities": vulnCount,
		"timestamp":            time.Now(),
	}

	return c.JSON(status)
}

func (h *SwarmHandler) HandleWebSocket(c *fiber.Ctx) error {
	// WebSocket implementation for real-time updates
	// This would require additional WebSocket handling
	return c.SendString("WebSocket endpoint - implement with gorilla/websocket")
}