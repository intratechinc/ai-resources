#!/usr/bin/env python3
"""
OSINT Agent for Intratech Cybersecurity Suite
"""

from typing import Dict, List, Any
from .base_agent import BaseAgent, TaskPriority

class OSINTAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="OSINT Agent",
            description="Conducts open source intelligence gathering",
            capabilities=["OSINT gathering", "Reconnaissance", "Social media analysis", "Public records search"]
        )
    
    def get_system_prompt(self) -> str:
        return "You are an OSINT Agent specializing in open source intelligence gathering and reconnaissance."
    
    def process_message(self, message: str, context: Dict[str, Any] = None) -> str:
        return "🔍 **OSINT Agent**\n\nI can help with open source intelligence gathering and reconnaissance activities."
    
    def execute_task(self, task_type: str, parameters: Dict[str, Any], user_id: str = None) -> str:
        return f"OSINT task '{task_type}' executed"
    
    def get_available_tasks(self) -> List[Dict[str, Any]]:
        return [{'name': 'osint_search', 'description': 'Perform OSINT search', 'parameters': ['target']}]