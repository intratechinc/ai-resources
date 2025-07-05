#!/usr/bin/env python3
"""
Network Security Agent for Intratech Cybersecurity Suite
"""

from typing import Dict, List, Any
from .base_agent import BaseAgent, TaskPriority

class NetworkSecurityAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Network Security Agent",
            description="Monitors network traffic and security",
            capabilities=["Network monitoring", "Traffic analysis", "Intrusion detection", "Firewall management"]
        )
    
    def get_system_prompt(self) -> str:
        return "You are a Network Security Agent specializing in network monitoring and traffic analysis."
    
    def process_message(self, message: str, context: Dict[str, Any] = None) -> str:
        return "🌐 **Network Security Agent**\n\nI can help monitor network traffic and detect security threats."
    
    def execute_task(self, task_type: str, parameters: Dict[str, Any], user_id: str = None) -> str:
        return f"Network security task '{task_type}' executed"
    
    def get_available_tasks(self) -> List[Dict[str, Any]]:
        return [{'name': 'monitor_traffic', 'description': 'Monitor network traffic', 'parameters': ['interface']}]