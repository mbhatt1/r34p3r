"""
Swarm Coordinator

Central coordination system for managing agent swarms and their interactions.
Handles task distribution, message routing, and swarm intelligence.
"""

import asyncio
import uuid
import json
from typing import Dict, List, Optional, Set, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque

from .swarm_types import (
    SwarmAgent, SwarmTask, SwarmMessage, SwarmVulnerability,
    SwarmStatus, SwarmPriority, SwarmAgentType, SwarmMetrics,
    MessageTypes, TaskTypes
)
from utils.logging import send_log_message

class SwarmCoordinator:
    """Central coordinator for the agent swarm"""
    
    def __init__(self, go_backend_url: str = "http://localhost:8080"):
        """Initialize the swarm coordinator"""
        self.go_backend_url = go_backend_url
        self.agents: Dict[str, SwarmAgent] = {}
        self.tasks: Dict[str, SwarmTask] = {}
        self.vulnerabilities: Dict[str, SwarmVulnerability] = {}
        self.message_queue: deque = deque()
        self.message_handlers: Dict[str, Callable] = {}
        self.running = False
        self.metrics = SwarmMetrics(
            total_agents=0,
            active_agents=0,
            tasks_completed=0,
            vulnerabilities_found=0,
            average_response_time=0.0,
            success_rate=0.0,
            uptime=0.0
        )
        
        # Agent capability mapping
        self.agent_capabilities = {
            SwarmAgentType.WEB_VENOM: [TaskTypes.XSS_SCAN],
            SwarmAgentType.SQL_REAPER: [TaskTypes.SQLI_SCAN],
            SwarmAgentType.TOKEN_BREAKER: [TaskTypes.CSRF_SCAN],
            SwarmAgentType.PROXY_PHANTOM: [TaskTypes.SSRF_SCAN],
            SwarmAgentType.AUTH_BANE: [TaskTypes.AUTH_BYPASS],
            SwarmAgentType.CIPHER_BREAKER: [TaskTypes.CRYPTO_ANALYSIS],
            SwarmAgentType.MEMORY_REAPER: [TaskTypes.MEMORY_ANALYSIS],
            SwarmAgentType.BINARY_GHOST: [TaskTypes.BINARY_ANALYSIS],
            SwarmAgentType.EXPLOIT_FORGE: [TaskTypes.EXPLOIT_DEVELOPMENT],
            SwarmAgentType.VULN_HUNTER: [TaskTypes.STATIC_ANALYSIS, TaskTypes.VULNERABILITY_DISCOVERY],
            SwarmAgentType.CODE_SENTINEL: [TaskTypes.CODE_REVIEW],
        }
        
        # Initialize message handlers
        self._setup_message_handlers()
    
    def _setup_message_handlers(self):
        """Setup message handlers for different message types"""
        self.message_handlers = {
            MessageTypes.AGENT_REGISTRATION: self._handle_agent_registration,
            MessageTypes.HEARTBEAT: self._handle_heartbeat,
            MessageTypes.TASK_COMPLETE: self._handle_task_complete,
            MessageTypes.VULNERABILITY_FOUND: self._handle_vulnerability_found,
            MessageTypes.STATUS_UPDATE: self._handle_status_update,
            MessageTypes.ERROR_REPORT: self._handle_error_report,
            MessageTypes.HANDOFF_REQUEST: self._handle_handoff_request,
            MessageTypes.CRITICAL_FINDING: self._handle_critical_finding,
        }
    
    async def start_swarm(self):
        """Start the swarm coordination system"""
        self.running = True
        await send_log_message("🚀 SwarmCoordinator: Starting agent swarm")
        
        # Start background tasks
        asyncio.create_task(self._message_processor())
        asyncio.create_task(self._heartbeat_monitor())
        asyncio.create_task(self._metrics_updater())
        asyncio.create_task(self._sync_with_go_backend())
        
        await send_log_message("✅ SwarmCoordinator: Swarm is operational")
    
    async def stop_swarm(self):
        """Stop the swarm coordination system"""
        self.running = False
        await send_log_message("🛑 SwarmCoordinator: Stopping agent swarm")
    
    async def register_agent(self, agent: SwarmAgent) -> bool:
        """Register a new agent in the swarm"""
        try:
            self.agents[agent.agent_id] = agent
            self.metrics.total_agents = len(self.agents)
            
            await send_log_message(f"🤖 SwarmCoordinator: Registered agent {agent.codename} ({agent.agent_type})")
            
            # Notify Go backend
            await self._notify_go_backend("agent_registered", {
                "agent_id": agent.agent_id,
                "agent_type": agent.agent_type,
                "codename": agent.codename,
                "capabilities": agent.capabilities
            })
            
            return True
        except Exception as e:
            await send_log_message(f"❌ SwarmCoordinator: Failed to register agent: {e}")
            return False
    
    async def assign_task(self, task: SwarmTask) -> bool:
        """Assign a task to an appropriate agent"""
        try:
            # Find available agent for this task type
            suitable_agents = [
                agent for agent in self.agents.values()
                if (agent.agent_type in self.agent_capabilities and
                    any(capability in self.agent_capabilities[agent.agent_type] for capability in [task.task_type]) and
                    agent.status == SwarmStatus.IDLE)
            ]
            
            if not suitable_agents:
                await send_log_message(f"⚠️ SwarmCoordinator: No available agents for task {task.task_type}")
                return False
            
            # Select agent (simple round-robin for now)
            selected_agent = suitable_agents[0]
            
            # Assign task
            task.assigned_at = datetime.utcnow()
            task.status = "assigned"
            self.tasks[task.id] = task
            
            # Update agent status
            selected_agent.status = SwarmStatus.BUSY
            selected_agent.current_task = task.id
            
            # Send task assignment message
            message = SwarmMessage(
                id=str(uuid.uuid4()),
                sender=SwarmAgentType.REAPER_MASTER,
                recipient=selected_agent.agent_type,
                message_type=MessageTypes.TASK_ASSIGNMENT,
                payload=task.dict(),
                priority=task.priority
            )
            
            await self._send_message(message)
            
            await send_log_message(f"📋 SwarmCoordinator: Assigned task {task.id} to {selected_agent.codename}")
            
            return True
            
        except Exception as e:
            await send_log_message(f"❌ SwarmCoordinator: Failed to assign task: {e}")
            return False
    
    async def broadcast_message(self, message: SwarmMessage):
        """Broadcast a message to all agents"""
        message.recipient = None  # Broadcast
        await self._send_message(message)
    
    async def send_direct_message(self, message: SwarmMessage):
        """Send a direct message to a specific agent"""
        await self._send_message(message)
    
    async def _send_message(self, message: SwarmMessage):
        """Internal method to send messages"""
        self.message_queue.append(message)
        await send_log_message(f"📨 SwarmCoordinator: Queued message {message.message_type} from {message.sender}")
    
    async def _message_processor(self):
        """Process messages in the queue"""
        while self.running:
            try:
                if self.message_queue:
                    message = self.message_queue.popleft()
                    await self._process_message(message)
                else:
                    await asyncio.sleep(0.1)
            except Exception as e:
                await send_log_message(f"❌ SwarmCoordinator: Message processing error: {e}")
    
    async def _process_message(self, message: SwarmMessage):
        """Process a single message"""
        try:
            handler = self.message_handlers.get(message.message_type)
            if handler:
                await handler(message)
            else:
                await send_log_message(f"⚠️ SwarmCoordinator: No handler for message type {message.message_type}")
                
            # Forward to Go backend
            await self._notify_go_backend("swarm_message", message.dict())
            
        except Exception as e:
            await send_log_message(f"❌ SwarmCoordinator: Error processing message: {e}")
    
    async def _handle_agent_registration(self, message: SwarmMessage):
        """Handle agent registration messages"""
        agent_data = message.payload
        agent = SwarmAgent(**agent_data)
        await self.register_agent(agent)
    
    async def _handle_heartbeat(self, message: SwarmMessage):
        """Handle agent heartbeat messages"""
        agent_id = message.payload.get("agent_id")
        if agent_id in self.agents:
            self.agents[agent_id].last_heartbeat = datetime.utcnow()
    
    async def _handle_task_complete(self, message: SwarmMessage):
        """Handle task completion messages"""
        task_id = message.payload.get("task_id")
        result = message.payload.get("result")
        
        if task_id in self.tasks:
            task = self.tasks[task_id]
            task.completed_at = datetime.utcnow()
            task.status = "completed"
            task.result = result
            
            # Free up the agent
            for agent in self.agents.values():
                if agent.current_task == task_id:
                    agent.status = SwarmStatus.IDLE
                    agent.current_task = None
                    break
            
            self.metrics.tasks_completed += 1
            await send_log_message(f"✅ SwarmCoordinator: Task {task_id} completed")
    
    async def _handle_vulnerability_found(self, message: SwarmMessage):
        """Handle vulnerability discovery messages"""
        vuln_data = message.payload
        vulnerability = SwarmVulnerability(**vuln_data)
        self.vulnerabilities[vulnerability.id] = vulnerability
        self.metrics.vulnerabilities_found += 1
        
        await send_log_message(f"🚨 SwarmCoordinator: Vulnerability found by {message.sender}: {vulnerability.vulnerability_type}")
        
        # Trigger follow-up actions based on severity
        if vulnerability.severity == "critical":
            await self._handle_critical_vulnerability(vulnerability)
    
    async def _handle_status_update(self, message: SwarmMessage):
        """Handle agent status updates"""
        agent_id = message.payload.get("agent_id")
        new_status = message.payload.get("status")
        
        if agent_id in self.agents:
            self.agents[agent_id].status = SwarmStatus(new_status)
    
    async def _handle_error_report(self, message: SwarmMessage):
        """Handle error reports from agents"""
        error = message.payload.get("error")
        agent_id = message.payload.get("agent_id")
        
        await send_log_message(f"❌ SwarmCoordinator: Error from {message.sender}: {error}")
        
        # Mark agent as error state
        if agent_id in self.agents:
            self.agents[agent_id].status = SwarmStatus.ERROR
    
    async def _handle_handoff_request(self, message: SwarmMessage):
        """Handle requests to hand off tasks between agents"""
        task_id = message.payload.get("task_id")
        target_agent_type = message.payload.get("target_agent_type")
        
        if task_id in self.tasks:
            # Create new task for target agent
            original_task = self.tasks[task_id]
            new_task = SwarmTask(
                id=str(uuid.uuid4()),
                agent_type=SwarmAgentType(target_agent_type),
                task_type=message.payload.get("new_task_type", original_task.task_type),
                target=original_task.target,
                parameters=message.payload.get("parameters", {}),
                priority=SwarmPriority.HIGH
            )
            
            await self.assign_task(new_task)
    
    async def _handle_critical_finding(self, message: SwarmMessage):
        """Handle critical security findings"""
        finding = message.payload
        
        # Immediately deploy exploit development agents
        exploit_task = SwarmTask(
            id=str(uuid.uuid4()),
            agent_type=SwarmAgentType.EXPLOIT_FORGE,
            task_type=TaskTypes.EXPLOIT_DEVELOPMENT,
            target=finding.get("target"),
            parameters={"vulnerability": finding},
            priority=SwarmPriority.CRITICAL
        )
        
        await self.assign_task(exploit_task)
    
    async def _handle_critical_vulnerability(self, vulnerability: SwarmVulnerability):
        """Handle critical vulnerability discovery"""
        # Deploy additional agents for verification and exploitation
        verification_task = SwarmTask(
            id=str(uuid.uuid4()),
            agent_type=SwarmAgentType.VULN_HUNTER,
            task_type=TaskTypes.VULNERABILITY_VERIFICATION,
            target=vulnerability.target,
            parameters={"vulnerability_id": vulnerability.id},
            priority=SwarmPriority.CRITICAL
        )
        
        await self.assign_task(verification_task)
    
    async def _heartbeat_monitor(self):
        """Monitor agent heartbeats and detect offline agents"""
        while self.running:
            try:
                current_time = datetime.utcnow()
                timeout_threshold = timedelta(minutes=5)
                
                for agent in self.agents.values():
                    if current_time - agent.last_heartbeat > timeout_threshold:
                        if agent.status != SwarmStatus.OFFLINE:
                            agent.status = SwarmStatus.OFFLINE
                            await send_log_message(f"💀 SwarmCoordinator: Agent {agent.codename} went offline")
                
                # Update active agent count
                self.metrics.active_agents = len([a for a in self.agents.values() if a.status != SwarmStatus.OFFLINE])
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                await send_log_message(f"❌ SwarmCoordinator: Heartbeat monitor error: {e}")
    
    async def _metrics_updater(self):
        """Update swarm metrics periodically"""
        while self.running:
            try:
                # Calculate success rate
                completed_tasks = len([t for t in self.tasks.values() if t.status == "completed"])
                total_tasks = len(self.tasks)
                self.metrics.success_rate = completed_tasks / total_tasks if total_tasks > 0 else 0.0
                
                # Update timestamp
                self.metrics.last_updated = datetime.utcnow()
                
                # Send metrics to Go backend
                await self._notify_go_backend("swarm_metrics", self.metrics.dict())
                
                await asyncio.sleep(60)  # Update every minute
                
            except Exception as e:
                await send_log_message(f"❌ SwarmCoordinator: Metrics update error: {e}")
    
    async def _sync_with_go_backend(self):
        """Sync swarm state with Go backend"""
        while self.running:
            try:
                # Send swarm state to Go backend
                swarm_state = {
                    "agents": [agent.dict() for agent in self.agents.values()],
                    "tasks": [task.dict() for task in self.tasks.values()],
                    "vulnerabilities": [vuln.dict() for vuln in self.vulnerabilities.values()],
                    "metrics": self.metrics.dict()
                }
                
                await self._notify_go_backend("swarm_state", swarm_state)
                
                await asyncio.sleep(30)  # Sync every 30 seconds
                
            except Exception as e:
                await send_log_message(f"❌ SwarmCoordinator: Go backend sync error: {e}")
    
    async def _notify_go_backend(self, event_type: str, data: dict):
        """Send notification to Go backend"""
        try:
            import aiohttp
            
            payload = {
                "event_type": event_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.go_backend_url}/api/swarm/events",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    if response.status != 200:
                        await send_log_message(f"⚠️ SwarmCoordinator: Go backend returned {response.status}")
                        
        except Exception as e:
            # Don't log every backend connection error to avoid spam
            pass
    
    def get_swarm_status(self) -> dict:
        """Get current swarm status"""
        return {
            "running": self.running,
            "agents": {agent_id: agent.dict() for agent_id, agent in self.agents.items()},
            "tasks": {task_id: task.dict() for task_id, task in self.tasks.items()},
            "vulnerabilities": {vuln_id: vuln.dict() for vuln_id, vuln in self.vulnerabilities.items()},
            "metrics": self.metrics.dict(),
            "message_queue_size": len(self.message_queue)
        }