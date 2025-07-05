#!/usr/bin/env python3
"""
Coordinator Agent for Intratech Cybersecurity Suite
Central orchestrator that routes messages to appropriate specialized agents
"""

import json
import re
from typing import Dict, List, Any, Optional
from datetime import datetime

from .base_agent import BaseAgent, TaskPriority
from database import create_security_event, SeverityLevel

class CoordinatorAgent(BaseAgent):
    """
    Central coordinator agent that manages and routes requests to specialized agents
    """
    
    def __init__(self):
        super().__init__(
            name="Coordinator",
            description="Central orchestrator for cybersecurity operations and agent coordination",
            capabilities=[
                "Message routing",
                "Agent coordination",
                "Task prioritization",
                "Security event correlation",
                "Multi-agent workflow orchestration",
                "User query interpretation",
                "Response aggregation",
                "Incident escalation"
            ]
        )
        
        # Agent routing mapping
        self.agent_routes = {
            'threat_intelligence': {
                'keywords': ['threat', 'intelligence', 'ioc', 'indicator', 'malware', 'apt', 'campaign'],
                'patterns': [
                    r'threat.*intelligence',
                    r'ioc.*check',
                    r'malware.*analysis',
                    r'apt.*group',
                    r'threat.*actor'
                ]
            },
            'vulnerability_scanner': {
                'keywords': ['vulnerability', 'scan', 'cve', 'exploit', 'security hole', 'weakness'],
                'patterns': [
                    r'vuln.*scan',
                    r'security.*scan',
                    r'cve.*check',
                    r'exploit.*check',
                    r'find.*vulnerabilities'
                ]
            },
            'penetration_testing': {
                'keywords': ['pentest', 'penetration', 'exploitation', 'attack', 'compromise'],
                'patterns': [
                    r'pen.*test',
                    r'penetration.*test',
                    r'exploit.*attempt',
                    r'attack.*simulation',
                    r'security.*assessment'
                ]
            },
            'incident_response': {
                'keywords': ['incident', 'response', 'emergency', 'breach', 'compromise', 'alert'],
                'patterns': [
                    r'incident.*response',
                    r'security.*incident',
                    r'data.*breach',
                    r'system.*compromise',
                    r'emergency.*response'
                ]
            },
            'osint': {
                'keywords': ['osint', 'reconnaissance', 'intelligence', 'investigation', 'research'],
                'patterns': [
                    r'osint.*search',
                    r'open.*source.*intelligence',
                    r'recon.*target',
                    r'investigate.*domain',
                    r'research.*company'
                ]
            },
            'malware_analysis': {
                'keywords': ['malware', 'virus', 'trojan', 'ransomware', 'analysis', 'sandbox'],
                'patterns': [
                    r'malware.*analysis',
                    r'virus.*scan',
                    r'analyze.*file',
                    r'sandbox.*analysis',
                    r'reverse.*engineering'
                ]
            },
            'network_security': {
                'keywords': ['network', 'traffic', 'firewall', 'ids', 'ips', 'monitoring'],
                'patterns': [
                    r'network.*security',
                    r'traffic.*analysis',
                    r'firewall.*rules',
                    r'intrusion.*detection',
                    r'network.*monitoring'
                ]
            },
            'compliance': {
                'keywords': ['compliance', 'audit', 'policy', 'regulation', 'framework'],
                'patterns': [
                    r'compliance.*check',
                    r'audit.*requirements',
                    r'policy.*violation',
                    r'regulatory.*compliance',
                    r'framework.*assessment'
                ]
            },
            'forensics': {
                'keywords': ['forensics', 'investigation', 'evidence', 'analysis', 'recovery'],
                'patterns': [
                    r'digital.*forensics',
                    r'forensic.*analysis',
                    r'evidence.*collection',
                    r'incident.*investigation',
                    r'data.*recovery'
                ]
            }
        }
        
        # Multi-agent workflows
        self.workflows = {
            'security_assessment': ['vulnerability_scanner', 'penetration_testing', 'compliance'],
            'incident_investigation': ['incident_response', 'forensics', 'malware_analysis'],
            'threat_hunting': ['threat_intelligence', 'osint', 'network_security'],
            'comprehensive_analysis': ['vulnerability_scanner', 'malware_analysis', 'network_security', 'compliance']
        }
        
        # Message routing history
        self.routing_history = {}
        
        self.logger.info("Coordinator Agent initialized with agent routing capabilities")
    
    def get_system_prompt(self) -> str:
        """Get the system prompt for the coordinator agent"""
        return """You are the Coordinator Agent for the Intratech Cybersecurity Suite. Your role is to:

1. **Message Routing**: Analyze incoming messages and route them to the most appropriate specialized agent
2. **Agent Coordination**: Coordinate between multiple agents for complex tasks
3. **Task Prioritization**: Determine the priority and urgency of security tasks
4. **Response Aggregation**: Combine responses from multiple agents into coherent insights
5. **Workflow Orchestration**: Manage multi-agent workflows for comprehensive security operations

Available specialized agents:
- **Threat Intelligence Agent**: Threat analysis, IOC checking, APT tracking
- **Vulnerability Scanner Agent**: Vulnerability assessments, CVE analysis, security scanning
- **Penetration Testing Agent**: Security testing, exploitation attempts, attack simulation
- **Incident Response Agent**: Security incident handling, emergency response
- **OSINT Agent**: Open source intelligence, reconnaissance, investigation
- **Malware Analysis Agent**: File analysis, sandbox testing, reverse engineering
- **Network Security Agent**: Network monitoring, traffic analysis, intrusion detection
- **Compliance Agent**: Regulatory compliance, audit checks, policy validation
- **Forensics Agent**: Digital forensics, evidence collection, incident investigation

When routing messages:
- Analyze the user's intent and content
- Route to the most appropriate agent
- For complex queries, coordinate multiple agents
- Provide clear explanations of your routing decisions
- Escalate high-priority security incidents immediately

Always maintain situational awareness and prioritize security threats appropriately."""
    
    def process_message(self, message: str, context: Dict[str, Any] = None) -> str:
        """Process a message and route it to appropriate agents"""
        try:
            # Analyze the message
            analysis = self._analyze_message(message)
            
            # Determine routing
            routing_decision = self._determine_routing(message, analysis)
            
            # Handle the routing
            if routing_decision['type'] == 'single_agent':
                return self._route_to_single_agent(message, routing_decision, context)
            elif routing_decision['type'] == 'multi_agent':
                return self._route_to_multiple_agents(message, routing_decision, context)
            elif routing_decision['type'] == 'workflow':
                return self._execute_workflow(message, routing_decision, context)
            else:
                return self._handle_general_query(message, context)
                
        except Exception as e:
            self.logger.error(f"Error processing message: {str(e)}")
            return f"I encountered an error while processing your request: {str(e)}"
    
    def _analyze_message(self, message: str) -> Dict[str, Any]:
        """Analyze the message to understand intent and content"""
        message_lower = message.lower()
        
        analysis = {
            'urgency': self._assess_urgency(message_lower),
            'security_keywords': self._extract_security_keywords(message_lower),
            'intent': self._classify_intent(message_lower),
            'entities': self._extract_entities(message),
            'complexity': self._assess_complexity(message_lower)
        }
        
        return analysis
    
    def _assess_urgency(self, message: str) -> str:
        """Assess the urgency of the message"""
        urgent_keywords = ['urgent', 'emergency', 'critical', 'immediate', 'breach', 'compromised', 'attack']
        high_keywords = ['important', 'high', 'priority', 'incident', 'alert']
        
        for keyword in urgent_keywords:
            if keyword in message:
                return 'urgent'
        
        for keyword in high_keywords:
            if keyword in message:
                return 'high'
        
        return 'normal'
    
    def _extract_security_keywords(self, message: str) -> List[str]:
        """Extract security-related keywords from the message"""
        all_keywords = []
        for agent, config in self.agent_routes.items():
            for keyword in config['keywords']:
                if keyword in message:
                    all_keywords.append(keyword)
        return all_keywords
    
    def _classify_intent(self, message: str) -> str:
        """Classify the intent of the message"""
        if any(word in message for word in ['scan', 'check', 'test', 'analyze']):
            return 'analysis'
        elif any(word in message for word in ['help', 'how', 'what', 'explain']):
            return 'information'
        elif any(word in message for word in ['report', 'incident', 'alert']):
            return 'reporting'
        elif any(word in message for word in ['fix', 'resolve', 'remediate']):
            return 'remediation'
        else:
            return 'general'
    
    def _extract_entities(self, message: str) -> Dict[str, List[str]]:
        """Extract entities like IPs, domains, files from the message"""
        entities = {
            'ip_addresses': re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', message),
            'domains': re.findall(r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b', message),
            'file_hashes': re.findall(r'\b[a-fA-F0-9]{32,64}\b', message),
            'urls': re.findall(r'https?://[^\s]+', message),
            'email_addresses': re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', message)
        }
        return entities
    
    def _assess_complexity(self, message: str) -> str:
        """Assess the complexity of the request"""
        if len(message.split()) > 50:
            return 'complex'
        elif any(word in message for word in ['comprehensive', 'full', 'complete', 'detailed']):
            return 'complex'
        else:
            return 'simple'
    
    def _determine_routing(self, message: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Determine how to route the message"""
        message_lower = message.lower()
        
        # Check for workflow keywords
        for workflow_name, agents in self.workflows.items():
            if workflow_name.replace('_', ' ') in message_lower:
                return {
                    'type': 'workflow',
                    'workflow': workflow_name,
                    'agents': agents,
                    'priority': self._get_priority_from_urgency(analysis['urgency'])
                }
        
        # Find matching agents
        matching_agents = []
        for agent_name, config in self.agent_routes.items():
            score = 0
            
            # Check keywords
            for keyword in config['keywords']:
                if keyword in message_lower:
                    score += 1
            
            # Check patterns
            for pattern in config['patterns']:
                if re.search(pattern, message_lower, re.IGNORECASE):
                    score += 2
            
            if score > 0:
                matching_agents.append((agent_name, score))
        
        # Sort by score
        matching_agents.sort(key=lambda x: x[1], reverse=True)
        
        if len(matching_agents) == 0:
            return {'type': 'general'}
        elif len(matching_agents) == 1:
            return {
                'type': 'single_agent',
                'agent': matching_agents[0][0],
                'priority': self._get_priority_from_urgency(analysis['urgency'])
            }
        elif analysis['complexity'] == 'complex' or analysis['urgency'] in ['urgent', 'high']:
            return {
                'type': 'multi_agent',
                'agents': [agent[0] for agent in matching_agents[:3]],
                'priority': self._get_priority_from_urgency(analysis['urgency'])
            }
        else:
            return {
                'type': 'single_agent',
                'agent': matching_agents[0][0],
                'priority': self._get_priority_from_urgency(analysis['urgency'])
            }
    
    def _get_priority_from_urgency(self, urgency: str) -> TaskPriority:
        """Convert urgency to task priority"""
        if urgency == 'urgent':
            return TaskPriority.CRITICAL
        elif urgency == 'high':
            return TaskPriority.HIGH
        else:
            return TaskPriority.MEDIUM
    
    def _route_to_single_agent(self, message: str, routing_decision: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Route message to a single agent"""
        agent_name = routing_decision['agent']
        
        # This would be implemented by calling the actual agent
        # For now, return a routing response
        response = f"🤖 **Routing to {agent_name.replace('_', ' ').title()} Agent**\n\n"
        response += f"I've analyzed your request and determined that the {agent_name.replace('_', ' ').title()} Agent is best suited to handle this task.\n\n"
        response += f"**Request Priority**: {routing_decision['priority'].name}\n\n"
        response += f"The {agent_name.replace('_', ' ').title()} Agent will process your request and provide detailed analysis and recommendations.\n\n"
        response += "*This is a demonstration response. In the full implementation, your request would be forwarded to the actual specialized agent.*"
        
        # Log the routing decision
        self.logger.info(f"Routed message to {agent_name}", 
                        routing_decision=routing_decision,
                        message_preview=message[:100])
        
        return response
    
    def _route_to_multiple_agents(self, message: str, routing_decision: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Route message to multiple agents for comprehensive analysis"""
        agents = routing_decision['agents']
        
        response = f"🤖 **Multi-Agent Coordination Initiated**\n\n"
        response += f"Your request requires coordination between multiple specialized agents for comprehensive analysis:\n\n"
        
        for i, agent_name in enumerate(agents, 1):
            response += f"{i}. **{agent_name.replace('_', ' ').title()} Agent** - {self._get_agent_description(agent_name)}\n"
        
        response += f"\n**Request Priority**: {routing_decision['priority'].name}\n\n"
        response += "Each agent will provide their specialized analysis, and I'll coordinate their responses to give you a comprehensive security assessment.\n\n"
        response += "*This is a demonstration response. In the full implementation, your request would be coordinated across all relevant agents.*"
        
        # Log the multi-agent routing
        self.logger.info(f"Routed message to multiple agents: {agents}", 
                        routing_decision=routing_decision,
                        message_preview=message[:100])
        
        return response
    
    def _execute_workflow(self, message: str, routing_decision: Dict[str, Any], context: Dict[str, Any]) -> str:
        """Execute a predefined workflow"""
        workflow = routing_decision['workflow']
        agents = routing_decision['agents']
        
        response = f"🤖 **Executing {workflow.replace('_', ' ').title()} Workflow**\n\n"
        response += f"I've initiated the {workflow.replace('_', ' ').title()} workflow which involves the following agents:\n\n"
        
        for i, agent_name in enumerate(agents, 1):
            response += f"{i}. **{agent_name.replace('_', ' ').title()} Agent** - {self._get_agent_description(agent_name)}\n"
        
        response += f"\n**Workflow Priority**: {routing_decision['priority'].name}\n\n"
        response += "The workflow will execute in the optimal sequence to provide you with comprehensive results.\n\n"
        response += "*This is a demonstration response. In the full implementation, the complete workflow would be executed automatically.*"
        
        # Log the workflow execution
        self.logger.info(f"Executed workflow: {workflow}", 
                        routing_decision=routing_decision,
                        message_preview=message[:100])
        
        return response
    
    def _handle_general_query(self, message: str, context: Dict[str, Any]) -> str:
        """Handle general queries that don't match specific agents"""
        response = "🤖 **General Cybersecurity Assistant**\n\n"
        response += "I'm here to help with cybersecurity tasks! I can coordinate with various specialized agents:\n\n"
        
        for agent_name, config in self.agent_routes.items():
            response += f"• **{agent_name.replace('_', ' ').title()} Agent** - {', '.join(config['keywords'][:3])}\n"
        
        response += "\n**How I can help:**\n"
        response += "• Route your security questions to the right experts\n"
        response += "• Coordinate complex security assessments\n"
        response += "• Manage incident response workflows\n"
        response += "• Provide general cybersecurity guidance\n\n"
        response += "Please let me know what specific security task you need help with!"
        
        return response
    
    def _get_agent_description(self, agent_name: str) -> str:
        """Get a brief description of what each agent does"""
        descriptions = {
            'threat_intelligence': 'Analyzes threats, IOCs, and threat actor intelligence',
            'vulnerability_scanner': 'Scans for vulnerabilities and security weaknesses',
            'penetration_testing': 'Performs security testing and attack simulation',
            'incident_response': 'Handles security incidents and emergency response',
            'osint': 'Conducts open source intelligence gathering',
            'malware_analysis': 'Analyzes malicious files and software',
            'network_security': 'Monitors network traffic and security',
            'compliance': 'Checks regulatory compliance and policies',
            'forensics': 'Performs digital forensics and investigation'
        }
        return descriptions.get(agent_name, 'Specialized security analysis')
    
    def route_message(self, message: str, user_id: str) -> str:
        """Main entry point for message routing"""
        try:
            # Add to routing history
            if user_id not in self.routing_history:
                self.routing_history[user_id] = []
            
            self.routing_history[user_id].append({
                'timestamp': datetime.now().isoformat(),
                'message': message,
                'user_id': user_id
            })
            
            # Process the message
            response = self.process_message(message, {'user_id': user_id})
            
            # Add response to history
            self.routing_history[user_id][-1]['response'] = response
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error routing message: {str(e)}")
            return f"I encountered an error while processing your request: {str(e)}"
    
    def execute_task(self, task_type: str, parameters: Dict[str, Any], user_id: str = None) -> str:
        """Execute coordinator-specific tasks"""
        if task_type == 'route_message':
            return self.route_message(parameters.get('message', ''), user_id or 'system')
        elif task_type == 'execute_workflow':
            return self._execute_workflow(
                parameters.get('message', ''),
                parameters.get('routing_decision', {}),
                parameters.get('context', {})
            )
        elif task_type == 'analyze_message':
            analysis = self._analyze_message(parameters.get('message', ''))
            return json.dumps(analysis, indent=2)
        else:
            return f"Unknown task type: {task_type}"
    
    def get_available_tasks(self) -> List[Dict[str, Any]]:
        """Get list of available tasks"""
        return [
            {
                'name': 'route_message',
                'description': 'Route a message to appropriate agents',
                'parameters': ['message']
            },
            {
                'name': 'execute_workflow',
                'description': 'Execute a predefined security workflow',
                'parameters': ['message', 'routing_decision', 'context']
            },
            {
                'name': 'analyze_message',
                'description': 'Analyze a message for routing decisions',
                'parameters': ['message']
            }
        ]
    
    def get_routing_stats(self) -> Dict[str, Any]:
        """Get routing statistics"""
        total_routes = sum(len(history) for history in self.routing_history.values())
        return {
            'total_routes': total_routes,
            'unique_users': len(self.routing_history),
            'available_agents': len(self.agent_routes),
            'available_workflows': len(self.workflows)
        }