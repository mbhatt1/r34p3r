"""
Agent Swarm Base Class

Base class for all swarm-enabled security agents with coordination capabilities.
"""

import asyncio
import uuid
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime

from .swarm_types import (
    SwarmAgent, SwarmMessage, SwarmTask, SwarmVulnerability,
    SwarmStatus, SwarmAgentType, SwarmPriority,
    MessageTypes, TaskTypes
)
from .swarm_coordinator import SwarmCoordinator
from utils.logging import send_log_message

class AgentSwarm(ABC):
    """Base class for all swarm-enabled security agents"""
    
    def __init__(self, agent_type: SwarmAgentType, codename: str, capabilities: List[str]):
        """Initialize swarm agent"""
        self.agent_id = str(uuid.uuid4())
        self.agent_type = agent_type
        self.codename = codename
        self.capabilities = capabilities
        self.status = SwarmStatus.IDLE
        self.current_task: Optional[SwarmTask] = None
        self.coordinator: Optional[SwarmCoordinator] = None
        self.running = False
        
        # Agent metadata
        self.metadata = {
            "version": "1.0.0",
            "startup_time": datetime.utcnow().isoformat(),
            "tasks_completed": 0,
            "vulnerabilities_found": 0
        }
        
        # Message handlers
        self.message_handlers = {
            MessageTypes.TASK_ASSIGNMENT: self._handle_task_assignment,
            MessageTypes.ABORT_MISSION: self._handle_abort_mission,
            MessageTypes.STATUS_UPDATE: self._handle_status_update,
        }
    
    async def join_swarm(self, coordinator: SwarmCoordinator):
        """Join the agent swarm"""
        self.coordinator = coordinator
        
        # Create agent registration
        agent = SwarmAgent(
            agent_id=self.agent_id,
            agent_type=self.agent_type,
            codename=self.codename,
            status=self.status,
            capabilities=self.capabilities,
            metadata=self.metadata
        )
        
        # Register with coordinator
        success = await coordinator.register_agent(agent)
        if success:
            self.running = True
            await send_log_message(f"🤖 {self.codename}: Joined swarm successfully")
            
            # Start agent background tasks
            asyncio.create_task(self._heartbeat_loop())
            asyncio.create_task(self._message_listener())
            
            return True
        else:
            await send_log_message(f"❌ {self.codename}: Failed to join swarm")
            return False
    
    async def leave_swarm(self):
        """Leave the agent swarm"""
        self.running = False
        self.status = SwarmStatus.OFFLINE
        await send_log_message(f"👋 {self.codename}: Left swarm")
    
    async def send_message(self, message: SwarmMessage):
        """Send a message through the swarm coordinator"""
        if self.coordinator:
            message.sender = self.agent_type
            await self.coordinator.send_direct_message(message)
    
    async def broadcast_message(self, message: SwarmMessage):
        """Broadcast a message to all agents"""
        if self.coordinator:
            message.sender = self.agent_type
            await self.coordinator.broadcast_message(message)
    
    async def report_vulnerability(self, vulnerability: SwarmVulnerability):
        """Report a discovered vulnerability"""
        vulnerability.discoverer = self.agent_type
        vulnerability.id = str(uuid.uuid4())
        
        # Send vulnerability found message
        message = SwarmMessage(
            id=str(uuid.uuid4()),
            sender=self.agent_type,
            message_type=MessageTypes.VULNERABILITY_FOUND,
            payload=vulnerability.dict(),
            priority=SwarmPriority.HIGH if vulnerability.severity in ["critical", "high"] else SwarmPriority.MEDIUM
        )
        
        await self.send_message(message)
        
        # Update metadata
        self.metadata["vulnerabilities_found"] += 1
        
        await send_log_message(f"🚨 {self.codename}: Reported {vulnerability.severity} {vulnerability.vulnerability_type}")
    
    async def request_handoff(self, target_agent_type: SwarmAgentType, task_type: str, parameters: Dict[str, Any]):
        """Request to hand off work to another agent"""
        message = SwarmMessage(
            id=str(uuid.uuid4()),
            sender=self.agent_type,
            recipient=SwarmAgentType.REAPER_MASTER,
            message_type=MessageTypes.HANDOFF_REQUEST,
            payload={
                "task_id": self.current_task.id if self.current_task else None,
                "target_agent_type": target_agent_type.value,
                "new_task_type": task_type,
                "parameters": parameters
            },
            priority=SwarmPriority.HIGH
        )
        
        await self.send_message(message)
        await send_log_message(f"🔄 {self.codename}: Requested handoff to {target_agent_type.value}")
    
    async def report_critical_finding(self, finding: Dict[str, Any]):
        """Report a critical security finding that requires immediate attention"""
        message = SwarmMessage(
            id=str(uuid.uuid4()),
            sender=self.agent_type,
            message_type=MessageTypes.CRITICAL_FINDING,
            payload=finding,
            priority=SwarmPriority.CRITICAL
        )
        
        await self.broadcast_message(message)
        await send_log_message(f"🚨 {self.codename}: Reported CRITICAL finding!")
    
    async def update_status(self, new_status: SwarmStatus):
        """Update agent status"""
        old_status = self.status
        self.status = new_status
        
        # Send status update message
        message = SwarmMessage(
            id=str(uuid.uuid4()),
            sender=self.agent_type,
            message_type=MessageTypes.STATUS_UPDATE,
            payload={
                "agent_id": self.agent_id,
                "old_status": old_status.value,
                "new_status": new_status.value
            }
        )
        
        await self.send_message(message)
        await send_log_message(f"📊 {self.codename}: Status changed from {old_status.value} to {new_status.value}")
    
    async def _heartbeat_loop(self):
        """Send periodic heartbeat messages"""
        while self.running:
            try:
                message = SwarmMessage(
                    id=str(uuid.uuid4()),
                    sender=self.agent_type,
                    message_type=MessageTypes.HEARTBEAT,
                    payload={
                        "agent_id": self.agent_id,
                        "status": self.status.value,
                        "current_task": self.current_task.id if self.current_task else None,
                        "metadata": self.metadata
                    }
                )
                
                await self.send_message(message)
                await asyncio.sleep(30)  # Heartbeat every 30 seconds
                
            except Exception as e:
                await send_log_message(f"❌ {self.codename}: Heartbeat error: {e}")
                await asyncio.sleep(30)
    
    async def _message_listener(self):
        """Listen for messages from the swarm coordinator"""
        # This would be implemented with actual message queue/WebSocket connection
        # For now, it's a placeholder that agents can override
        while self.running:
            await asyncio.sleep(1)
    
    async def _handle_task_assignment(self, message: SwarmMessage):
        """Handle task assignment from coordinator"""
        try:
            task_data = message.payload
            task = SwarmTask(**task_data)
            
            await send_log_message(f"📋 {self.codename}: Received task {task.id} ({task.task_type})")
            
            # Update status
            await self.update_status(SwarmStatus.BUSY)
            self.current_task = task
            
            # Execute the task
            result = await self.execute_task(task)
            
            # Report task completion
            completion_message = SwarmMessage(
                id=str(uuid.uuid4()),
                sender=self.agent_type,
                recipient=SwarmAgentType.REAPER_MASTER,
                message_type=MessageTypes.TASK_COMPLETE,
                payload={
                    "task_id": task.id,
                    "result": result,
                    "agent_id": self.agent_id
                }
            )
            
            await self.send_message(completion_message)
            
            # Update metadata and status
            self.metadata["tasks_completed"] += 1
            self.current_task = None
            await self.update_status(SwarmStatus.IDLE)
            
            await send_log_message(f"✅ {self.codename}: Completed task {task.id}")
            
        except Exception as e:
            await send_log_message(f"❌ {self.codename}: Task execution failed: {e}")
            
            # Report error
            error_message = SwarmMessage(
                id=str(uuid.uuid4()),
                sender=self.agent_type,
                message_type=MessageTypes.ERROR_REPORT,
                payload={
                    "agent_id": self.agent_id,
                    "error": str(e),
                    "task_id": self.current_task.id if self.current_task else None
                }
            )
            
            await self.send_message(error_message)
            await self.update_status(SwarmStatus.ERROR)
    
    async def _handle_abort_mission(self, message: SwarmMessage):
        """Handle abort mission command"""
        await send_log_message(f"🛑 {self.codename}: Aborting current mission")
        
        if self.current_task:
            self.current_task = None
        
        await self.update_status(SwarmStatus.IDLE)
    
    async def _handle_status_update(self, message: SwarmMessage):
        """Handle status update requests"""
        # Send current status
        status_message = SwarmMessage(
            id=str(uuid.uuid4()),
            sender=self.agent_type,
            message_type=MessageTypes.STATUS_UPDATE,
            payload={
                "agent_id": self.agent_id,
                "status": self.status.value,
                "current_task": self.current_task.id if self.current_task else None,
                "metadata": self.metadata
            }
        )
        
        await self.send_message(status_message)
    
    @abstractmethod
    async def execute_task(self, task: SwarmTask) -> Dict[str, Any]:
        """Execute a task assigned by the swarm coordinator"""
        pass
    
    @abstractmethod
    async def get_agent_info(self) -> Dict[str, Any]:
        """Get agent information and capabilities"""
        pass
    
    def get_swarm_status(self) -> Dict[str, Any]:
        """Get current swarm status for this agent"""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type.value,
            "codename": self.codename,
            "status": self.status.value,
            "capabilities": self.capabilities,
            "current_task": self.current_task.dict() if self.current_task else None,
            "metadata": self.metadata,
            "running": self.running
        }

class WebSecuritySwarmAgent(AgentSwarm):
    """Base class for web security agents in the swarm"""
    
    def __init__(self, agent_type: SwarmAgentType, codename: str):
        web_capabilities = [
            "http_testing",
            "payload_injection",
            "response_analysis",
            "vulnerability_detection"
        ]
        super().__init__(agent_type, codename, web_capabilities)
    
    async def test_endpoint(self, url: str, method: str = "GET", payload: str = "") -> Dict[str, Any]:
        """Base method for testing web endpoints"""
        # This would be implemented by specific agents
        return {
            "url": url,
            "method": method,
            "payload": payload,
            "tested_by": self.codename
        }

class BinarySecuritySwarmAgent(AgentSwarm):
    """Base class for binary security agents in the swarm"""
    
    def __init__(self, agent_type: SwarmAgentType, codename: str):
        binary_capabilities = [
            "binary_analysis",
            "memory_analysis",
            "exploit_development",
            "reverse_engineering"
        ]
        super().__init__(agent_type, codename, binary_capabilities)
    
    async def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """Base method for binary analysis"""
        # This would be implemented by specific agents
        return {
            "binary_path": binary_path,
            "analyzed_by": self.codename
        }

class CodeAnalysisSwarmAgent(AgentSwarm):
    """Base class for code analysis agents in the swarm"""
    
    def __init__(self, agent_type: SwarmAgentType, codename: str):
        code_capabilities = [
            "static_analysis",
            "pattern_matching",
            "vulnerability_discovery",
            "code_review"
        ]
        super().__init__(agent_type, codename, code_capabilities)
    
    async def analyze_code(self, code_path: str) -> Dict[str, Any]:
        """Base method for code analysis"""
        # This would be implemented by specific agents
        return {
            "code_path": code_path,
            "analyzed_by": self.codename
        }