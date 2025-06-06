"""
Swarm Architecture Types and Data Models

Defines the core data structures for agent swarm coordination.
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field
from datetime import datetime

class SwarmStatus(str, Enum):
    """Agent status in the swarm"""
    IDLE = "idle"
    ACTIVE = "active"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"

class SwarmPriority(str, Enum):
    """Task priority levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class SwarmAgentType(str, Enum):
    """Types of agents in the swarm"""
    WEB_VENOM = "web_venom"
    SQL_REAPER = "sql_reaper"
    TOKEN_BREAKER = "token_breaker"
    PROXY_PHANTOM = "proxy_phantom"
    AUTH_BANE = "auth_bane"
    CIPHER_BREAKER = "cipher_breaker"
    MEMORY_REAPER = "memory_reaper"
    BINARY_GHOST = "binary_ghost"
    EXPLOIT_FORGE = "exploit_forge"
    VULN_HUNTER = "vuln_hunter"
    CODE_SENTINEL = "code_sentinel"
    REAPER_MASTER = "reaper_master"

class SwarmMessage(BaseModel):
    """Message passed between agents in the swarm"""
    id: str = Field(description="Unique message ID")
    sender: SwarmAgentType = Field(description="Agent that sent the message")
    recipient: Optional[SwarmAgentType] = Field(default=None, description="Target agent (None for broadcast)")
    message_type: str = Field(description="Type of message")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Message data")
    priority: SwarmPriority = Field(default=SwarmPriority.MEDIUM, description="Message priority")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Message timestamp")
    correlation_id: Optional[str] = Field(default=None, description="ID linking related messages")

class SwarmTask(BaseModel):
    """Task assigned to an agent in the swarm"""
    id: str = Field(description="Unique task ID")
    agent_type: SwarmAgentType = Field(description="Agent type to handle this task")
    task_type: str = Field(description="Type of task to perform")
    target: str = Field(description="Target URL, file, or identifier")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Task parameters")
    priority: SwarmPriority = Field(default=SwarmPriority.MEDIUM, description="Task priority")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Task creation time")
    assigned_at: Optional[datetime] = Field(default=None, description="Task assignment time")
    completed_at: Optional[datetime] = Field(default=None, description="Task completion time")
    status: str = Field(default="pending", description="Task status")
    result: Optional[Dict[str, Any]] = Field(default=None, description="Task result")
    error: Optional[str] = Field(default=None, description="Error message if task failed")

class SwarmAgent(BaseModel):
    """Agent registration in the swarm"""
    agent_id: str = Field(description="Unique agent identifier")
    agent_type: SwarmAgentType = Field(description="Type of agent")
    codename: str = Field(description="Agent codename")
    status: SwarmStatus = Field(default=SwarmStatus.IDLE, description="Current agent status")
    capabilities: List[str] = Field(default_factory=list, description="Agent capabilities")
    current_task: Optional[str] = Field(default=None, description="Current task ID")
    last_heartbeat: datetime = Field(default_factory=datetime.utcnow, description="Last heartbeat timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional agent metadata")

class SwarmVulnerability(BaseModel):
    """Vulnerability discovered by the swarm"""
    id: str = Field(description="Unique vulnerability ID")
    discoverer: SwarmAgentType = Field(description="Agent that discovered the vulnerability")
    vulnerability_type: str = Field(description="Type of vulnerability")
    severity: str = Field(description="Vulnerability severity")
    target: str = Field(description="Target where vulnerability was found")
    description: str = Field(description="Vulnerability description")
    evidence: Dict[str, Any] = Field(default_factory=dict, description="Evidence and proof")
    remediation: str = Field(description="Remediation recommendations")
    confidence: float = Field(description="Confidence score (0.0-1.0)")
    discovered_at: datetime = Field(default_factory=datetime.utcnow, description="Discovery timestamp")
    verified: bool = Field(default=False, description="Whether vulnerability has been verified")
    exploitable: bool = Field(default=False, description="Whether vulnerability is exploitable")

class SwarmCoordinationEvent(BaseModel):
    """Event for swarm coordination"""
    event_id: str = Field(description="Unique event ID")
    event_type: str = Field(description="Type of coordination event")
    initiator: SwarmAgentType = Field(description="Agent that initiated the event")
    participants: List[SwarmAgentType] = Field(description="Agents involved in the event")
    data: Dict[str, Any] = Field(default_factory=dict, description="Event data")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")

class SwarmMetrics(BaseModel):
    """Swarm performance metrics"""
    total_agents: int = Field(description="Total number of agents")
    active_agents: int = Field(description="Number of active agents")
    tasks_completed: int = Field(description="Total tasks completed")
    vulnerabilities_found: int = Field(description="Total vulnerabilities discovered")
    average_response_time: float = Field(description="Average agent response time")
    success_rate: float = Field(description="Task success rate")
    uptime: float = Field(description="Swarm uptime percentage")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Metrics update timestamp")

# Message types for swarm communication
class MessageTypes:
    # Discovery and reconnaissance
    TARGET_DISCOVERED = "target_discovered"
    SCAN_REQUEST = "scan_request"
    SCAN_COMPLETE = "scan_complete"
    
    # Vulnerability management
    VULNERABILITY_FOUND = "vulnerability_found"
    VULNERABILITY_VERIFIED = "vulnerability_verified"
    EXPLOIT_DEVELOPED = "exploit_developed"
    
    # Coordination
    AGENT_REGISTRATION = "agent_registration"
    HEARTBEAT = "heartbeat"
    TASK_ASSIGNMENT = "task_assignment"
    TASK_COMPLETE = "task_complete"
    HANDOFF_REQUEST = "handoff_request"
    
    # Status updates
    STATUS_UPDATE = "status_update"
    ERROR_REPORT = "error_report"
    METRICS_UPDATE = "metrics_update"
    
    # Emergency
    CRITICAL_FINDING = "critical_finding"
    ABORT_MISSION = "abort_mission"
    EMERGENCY_SHUTDOWN = "emergency_shutdown"

# Task types for different agents
class TaskTypes:
    # Web security tasks
    XSS_SCAN = "xss_scan"
    SQLI_SCAN = "sqli_scan"
    CSRF_SCAN = "csrf_scan"
    SSRF_SCAN = "ssrf_scan"
    AUTH_BYPASS = "auth_bypass"
    CRYPTO_ANALYSIS = "crypto_analysis"
    
    # Binary security tasks
    MEMORY_ANALYSIS = "memory_analysis"
    BINARY_ANALYSIS = "binary_analysis"
    EXPLOIT_DEVELOPMENT = "exploit_development"
    
    # Code analysis tasks
    STATIC_ANALYSIS = "static_analysis"
    CODE_REVIEW = "code_review"
    VULNERABILITY_DISCOVERY = "vulnerability_discovery"
    
    # Coordination tasks
    TARGET_RECONNAISSANCE = "target_reconnaissance"
    VULNERABILITY_VERIFICATION = "vulnerability_verification"
    REPORT_GENERATION = "report_generation"