#!/usr/bin/env python3
"""
Forensics Agent for Intratech Cybersecurity Suite
"""

from typing import Dict, List, Any
from .base_agent import BaseAgent, TaskPriority

class ForensicsAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="Forensics Agent",
            description="Performs digital forensics and investigation",
            capabilities=["Digital forensics", "Evidence collection", "Data recovery", "Chain of custody"]
        )
    
    def get_system_prompt(self) -> str:
        return "You are a Forensics Agent specializing in digital forensics and evidence collection."
    
    def process_message(self, message: str, context: Dict[str, Any] = None) -> str:
        return "🔬 **Forensics Agent**\n\nI can help with digital forensics analysis and evidence collection."
    
    def execute_task(self, task_type: str, parameters: Dict[str, Any], user_id: str = None) -> str:
        return f"Forensics task '{task_type}' executed"
    
    def get_available_tasks(self) -> List[Dict[str, Any]]:
        return [{'name': 'collect_evidence', 'description': 'Collect digital evidence', 'parameters': ['source']}]