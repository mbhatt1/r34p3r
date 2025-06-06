"""
Reaper Agent Swarm Architecture

This module implements a swarm-based coordination system for security testing agents.
Each agent operates autonomously while coordinating with others through the swarm.
"""

from .swarm_coordinator import SwarmCoordinator
from .agent_swarm import AgentSwarm
from .swarm_types import SwarmMessage, SwarmTask, SwarmStatus

__all__ = [
    'SwarmCoordinator',
    'AgentSwarm', 
    'SwarmMessage',
    'SwarmTask',
    'SwarmStatus'
]