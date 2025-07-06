#!/usr/bin/env python3
"""
Intratech Cybersecurity Suite
Main Application - AI-Powered Cybersecurity Command Center
"""

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit, disconnect
from flask_cors import CORS
import os
import logging
from datetime import datetime
import json
import asyncio
from threading import Thread
import time

# Import our custom modules
from agents.coordinator import CoordinatorAgent
from agents.threat_intelligence import ThreatIntelligenceAgent
from agents.vulnerability_scanner import VulnerabilityAgent
from agents.penetration_testing import PenetrationTestingAgent
from agents.incident_response import IncidentResponseAgent
from agents.osint import OSINTAgent
from agents.malware_analysis import MalwareAnalysisAgent
from agents.network_security import NetworkSecurityAgent
from agents.compliance import ComplianceAgent
from agents.forensics import ForensicsAgent
from config import Config
from database import init_db, AgentLog, SecurityEvent
from utils.logger import setup_logger

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(
    app, 
    cors_allowed_origins="*", 
    async_mode='threading',
    engineio_logger=False,
    socketio_logger=False,
    ping_timeout=60,
    ping_interval=25,
    allow_upgrades=True,
    json=None
)
CORS(app)

# Setup logging
logger = setup_logger('intratech_cybersecurity', app.config['LOG_LEVEL'])

# Initialize database
with app.app_context():
    init_db(app)

class CybersecuritySuite:
    """Main cybersecurity suite orchestrator"""
    
    def __init__(self):
        self.agents = {}
        self.active_tasks = {}
        self.chat_sessions = {}
        # Initialize agents within app context
        with app.app_context():
            self.initialize_agents()
        
    def initialize_agents(self):
        """Initialize all cybersecurity agents"""
        logger.info("Initializing Intratech Cybersecurity Suite Agents...")
        
        # Initialize all specialized agents
        self.agents['coordinator'] = CoordinatorAgent()
        self.agents['threat_intelligence'] = ThreatIntelligenceAgent()
        self.agents['vulnerability_scanner'] = VulnerabilityAgent()
        self.agents['penetration_testing'] = PenetrationTestingAgent()
        self.agents['incident_response'] = IncidentResponseAgent()
        self.agents['osint'] = OSINTAgent()
        self.agents['malware_analysis'] = MalwareAnalysisAgent()
        self.agents['network_security'] = NetworkSecurityAgent()
        self.agents['compliance'] = ComplianceAgent()
        self.agents['forensics'] = ForensicsAgent()
        
        # Start autonomous monitoring for each agent
        for agent_name, agent in self.agents.items():
            if hasattr(agent, 'start_autonomous_monitoring'):
                Thread(target=agent.start_autonomous_monitoring, daemon=True).start()
                
        logger.info(f"Initialized {len(self.agents)} cybersecurity agents")
        
    def get_agent(self, agent_type):
        """Get specific agent by type"""
        return self.agents.get(agent_type)
    
    def get_all_agents_status(self):
        """Get status of all agents"""
        status = {}
        for agent_name, agent in self.agents.items():
            status[agent_name] = {
                'name': agent.name,
                'status': agent.status.value if hasattr(agent.status, 'value') else str(agent.status),
                'last_activity': agent.last_activity.isoformat() if hasattr(agent.last_activity, 'isoformat') else str(agent.last_activity),
                'active_tasks': len(agent.active_tasks) if hasattr(agent, 'active_tasks') else 0
            }
        return status
    
    def handle_chat_message(self, user_id, message):
        """Handle incoming chat message and route to appropriate agent"""
        logger.info(f"Chat message from {user_id}: {message}")
        
        # Use coordinator to determine which agent should handle the message
        coordinator = self.agents['coordinator']
        response = coordinator.route_message(message, user_id)
        
        # Log the interaction
        self.log_chat_interaction(user_id, message, response)
        
        return response
    
    def log_chat_interaction(self, user_id, message, response):
        """Log chat interaction to database"""
        try:
            with app.app_context():
                from database import db
                log_entry = AgentLog(
                    agent_name='chat_interface',
                    user_id=user_id,
                    message=message,
                    response=response,
                    timestamp=datetime.now()
                )
                db.session.add(log_entry)
                db.session.commit()
                logger.info(f"Logged chat interaction for user {user_id}")
        except Exception as e:
            logger.error(f"Failed to log chat interaction: {e}")

# Initialize the cybersecurity suite within app context
with app.app_context():
    cyber_suite = CybersecuritySuite()

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    logger.info(f"Client connected: {request.sid}")
    emit('connected', {'status': 'Connected to Intratech Cybersecurity Suite'})
    
    # Send initial agent status
    emit('agent_status', cyber_suite.get_all_agents_status())

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('chat_message')
def handle_chat_message(data):
    """Handle chat messages with agent selection"""
    try:
        user_id = data.get('user_id', 'anonymous')
        message = data.get('message', '')
        agent_type = data.get('agent_type')
        
        print(f"Chat message from {user_id}: {message}")
        
        if not message.strip():
            emit('error', {'message': 'Empty message'})
            return
        
        # If specific agent is selected, use that agent
        if agent_type and agent_type in cyber_suite.agents:
            agent = cyber_suite.agents[agent_type]
            response = agent.process_query(message, user_id)
        else:
            # Use coordinator for general queries
            coordinator = cyber_suite.agents.get('coordinator')
            if coordinator:
                response = coordinator.process_query(message, user_id)
            else:
                response = "No agents available to process your request."
        
        emit('chat_response', {
            'response': response,
            'agent_type': agent_type or 'coordinator',
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error handling chat message: {str(e)}")
        emit('error', {'message': f'Chat processing failed: {str(e)}'})

@socketio.on('get_agent_status')
def handle_get_agent_status():
    """Handle request for agent status"""
    emit('agent_status', cyber_suite.get_all_agents_status())

@socketio.on('execute_task')
def handle_execute_task(data):
    """Handle task execution from dropdown menus"""
    try:
        user_id = data.get('user_id', 'anonymous')
        agent_type = data.get('agent_type')
        task_type = data.get('task_type')
        parameters = data.get('parameters', {})
        
        print(f"Executing task: {task_type} for agent: {agent_type}")
        
        if not agent_type or agent_type not in cyber_suite.agents:
            emit('error', {'message': f'Agent {agent_type} not found'})
            return
        
        agent = cyber_suite.agents[agent_type]
        task_description = parameters.get('task_description', 'Execute predefined task')
        
        # Create a task execution prompt based on the selected task
        task_prompt = f"""
        You are a professional cybersecurity {agent.name.lower()}. 
        Execute the following task: {task_description}
        
        Provide a detailed professional response including:
        1. Task understanding and approach
        2. Analysis methodology 
        3. Key findings or recommendations
        4. Next steps or follow-up actions
        5. Any security considerations
        
        If this task requires specific inputs (like IP addresses, domains, files), 
        explain what information you would need and provide an example analysis.
        """
        
        # Execute the task
        response = agent.process_query(task_prompt, user_id)
        
        # Emit response back to client
        emit('task_response', {
            'agent_type': agent_type,
            'task_type': task_type,
            'task_description': task_description,
            'response': response,
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        })
        
        # Also emit as chat response for consistency
        emit('chat_response', {
            'response': response,
            'agent_type': agent_type,
            'timestamp': datetime.now().isoformat()
        })
        
    except Exception as e:
        print(f"Error executing task: {str(e)}")
        emit('error', {'message': f'Task execution failed: {str(e)}'})

# HTTP Routes
@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/agents')
def get_agents():
    """Get all agents status"""
    return jsonify(cyber_suite.get_all_agents_status())

@app.route('/api/agents/<agent_type>')
def get_agent_info(agent_type):
    """Get specific agent information"""
    agent = cyber_suite.get_agent(agent_type)
    if not agent:
        return jsonify({'error': 'Agent not found'}), 404
    
    return jsonify({
        'name': agent.name,
        'description': agent.description,
        'capabilities': agent.capabilities,
        'status': agent.status.value if hasattr(agent.status, 'value') else str(agent.status),
        'last_activity': agent.last_activity.isoformat() if hasattr(agent.last_activity, 'isoformat') else str(agent.last_activity)
    })

@app.route('/api/security-events')
def get_security_events():
    """Get recent security events"""
    # Implement database query for security events
    events = []  # Fetch from database
    return jsonify(events)

@app.route('/api/logs')
def get_logs():
    """Get system logs"""
    # Implement database query for logs
    logs = []  # Fetch from database
    return jsonify(logs)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'agents': len(cyber_suite.agents),
        'active_tasks': len(cyber_suite.active_tasks)
    })

# Background task for sending periodic updates
def background_updates():
    """Send periodic updates to connected clients"""
    while True:
        time.sleep(30)  # Update every 30 seconds
        agent_status = cyber_suite.get_all_agents_status()
        socketio.emit('agent_status_update', agent_status)

# Start background task
background_thread = Thread(target=background_updates, daemon=True)
background_thread.start()

if __name__ == '__main__':
    logger.info("Starting Intratech Cybersecurity Suite...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)