#!/usr/bin/env python3
"""
Base Agent class for Intratech Cybersecurity Suite
All specialized agents inherit from this base class
"""

import uuid
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from abc import ABC, abstractmethod
import threading
import time
import json
from enum import Enum

from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.callbacks import StreamingStdOutCallbackHandler

from config import Config
from utils.logger import setup_logger
from database import db, log_agent_activity, AgentStatus, TaskStatus

# Import will be added after tools.py is created
try:
    from agents.tools import cybersec_tools
except ImportError:
    cybersec_tools = None

class TaskPriority(Enum):
    """Task priority levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class BaseAgent(ABC):
    """Base class for all cybersecurity agents"""
    
    def __init__(self, name: str, description: str, capabilities: List[str]):
        self.name = name
        self.description = description
        self.capabilities = capabilities
        self.agent_id = str(uuid.uuid4())
        self.status = AgentStatus.INACTIVE
        self.last_activity = datetime.now()
        self.active_tasks = {}
        self.task_queue = []
        self.conversation_history = {}
        self.config = Config.get_agent_config(name.lower().replace(' ', '_'))
        
        # Initialize logger
        self.logger = setup_logger(f"agent_{name.lower().replace(' ', '_')}")
        
        # Initialize LLM
        self.llm = self._initialize_llm()
        
        # Performance metrics
        self.metrics = {
            'tasks_completed': 0,
            'tasks_failed': 0,
            'average_response_time': 0,
            'uptime': 0
        }
        
        # Thread safety
        self.task_lock = threading.Lock()
        self.status_lock = threading.Lock()
        
        # Initialize agent
        self._initialize_agent()
        
        self.logger.info(f"Agent {self.name} initialized successfully")
    
    def _initialize_llm(self) -> ChatOpenAI:
        """Initialize the language model for the agent"""
        return ChatOpenAI(
            model_name=self.config.get('model', Config.DEFAULT_LLM_MODEL),
            temperature=self.config.get('temperature', 0.3),
            max_tokens=self.config.get('max_tokens', 2000),
            openai_api_key=Config.OPENAI_API_KEY,
            callbacks=[StreamingStdOutCallbackHandler()]
        )
    
    def _initialize_agent(self):
        """Initialize agent-specific components"""
        with self.status_lock:
            self.status = AgentStatus.ACTIVE
            self.last_activity = datetime.now()
        
        # Log agent initialization
        log_agent_activity(
            agent_name=self.name,
            action='agent_initialized',
            status=TaskStatus.COMPLETED,
            metadata={'agent_id': self.agent_id}
        )
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get the system prompt for this agent"""
        pass
    
    @abstractmethod
    def process_message(self, message: str, context: Dict[str, Any] = None) -> str:
        """Process a message and return a response"""
        pass
    
    @abstractmethod
    def execute_task(self, task_type: str, parameters: Dict[str, Any], user_id: str = None) -> str:
        """Execute a specific task"""
        pass
    
    @abstractmethod
    def get_available_tasks(self) -> List[Dict[str, Any]]:
        """Get list of available tasks this agent can perform"""
        pass
    
    def generate_response(self, message: str, context: Dict[str, Any] = None) -> str:
        """Generate a response using the LLM"""
        try:
            # Build the conversation
            messages = [
                SystemMessage(content=self.get_system_prompt()),
                HumanMessage(content=message)
            ]
            
            # Add context if provided
            if context:
                context_msg = f"Context: {json.dumps(context, indent=2)}"
                messages.insert(1, SystemMessage(content=context_msg))
            
            # Generate response
            start_time = time.time()
            response = self.llm(messages)
            end_time = time.time()
            
            # Update metrics
            response_time = end_time - start_time
            self._update_metrics(response_time, True)
            
            # Log the interaction
            self.logger.info(
                f"Generated response for message",
                response_time=response_time,
                message_length=len(message),
                response_length=len(response.content)
            )
            
            return response.content
            
        except Exception as e:
            self.logger.error(f"Error generating response: {str(e)}")
            self._update_metrics(0, False)
            return f"I encountered an error while processing your request: {str(e)}"
    
    def add_task(self, task_type: str, parameters: Dict[str, Any], priority: TaskPriority = TaskPriority.MEDIUM, user_id: str = None) -> str:
        """Add a task to the agent's queue"""
        task_id = str(uuid.uuid4())
        task = {
            'task_id': task_id,
            'task_type': task_type,
            'parameters': parameters,
            'priority': priority,
            'user_id': user_id,
            'created_at': datetime.now(),
            'status': TaskStatus.PENDING
        }
        
        with self.task_lock:
            # Insert task based on priority
            inserted = False
            for i, existing_task in enumerate(self.task_queue):
                if task['priority'].value > existing_task['priority'].value:
                    self.task_queue.insert(i, task)
                    inserted = True
                    break
            
            if not inserted:
                self.task_queue.append(task)
            
            self.active_tasks[task_id] = task
        
        self.logger.info(f"Task added to queue: {task_type} with priority {priority.name}")
        return task_id
    
    def get_task_status(self, task_id: str) -> Dict[str, Any]:
        """Get the status of a specific task"""
        with self.task_lock:
            task = self.active_tasks.get(task_id)
            if task:
                return {
                    'task_id': task_id,
                    'task_type': task['task_type'],
                    'status': task['status'].value,
                    'created_at': task['created_at'].isoformat(),
                    'priority': task['priority'].name
                }
            return {'error': 'Task not found'}
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a specific task"""
        with self.task_lock:
            task = self.active_tasks.get(task_id)
            if task and task['status'] == TaskStatus.PENDING:
                task['status'] = TaskStatus.CANCELLED
                self.task_queue = [t for t in self.task_queue if t['task_id'] != task_id]
                self.logger.info(f"Task cancelled: {task_id}")
                return True
            return False
    
    def process_task_queue(self):
        """Process tasks in the queue"""
        while True:
            task = None
            with self.task_lock:
                if self.task_queue:
                    task = self.task_queue.pop(0)
                    task['status'] = TaskStatus.RUNNING
            
            if task:
                try:
                    self.logger.info(f"Processing task: {task['task_type']}")
                    
                    # Execute the task
                    result = self.execute_task(
                        task['task_type'],
                        task['parameters'],
                        task['user_id']
                    )
                    
                    # Update task status
                    with self.task_lock:
                        task['status'] = TaskStatus.COMPLETED
                        task['result'] = result
                        task['completed_at'] = datetime.now()
                    
                    self.logger.info(f"Task completed: {task['task_id']}")
                    
                except Exception as e:
                    self.logger.error(f"Task failed: {task['task_id']} - {str(e)}")
                    with self.task_lock:
                        task['status'] = TaskStatus.FAILED
                        task['error'] = str(e)
                        task['completed_at'] = datetime.now()
            
            time.sleep(1)  # Prevent busy waiting
    
    def start_autonomous_monitoring(self):
        """Start autonomous monitoring and task processing"""
        self.logger.info(f"Starting autonomous monitoring for {self.name}")
        
        # Start task processing thread
        task_thread = threading.Thread(target=self.process_task_queue, daemon=True)
        task_thread.start()
        
        # Start autonomous monitoring
        monitoring_thread = threading.Thread(target=self._autonomous_monitoring_loop, daemon=True)
        monitoring_thread.start()
    
    def _autonomous_monitoring_loop(self):
        """Main autonomous monitoring loop"""
        while True:
            try:
                self._perform_autonomous_tasks()
                self._update_status()
                time.sleep(Config.AGENT_UPDATE_INTERVAL)
            except Exception as e:
                self.logger.error(f"Error in autonomous monitoring: {str(e)}")
                time.sleep(60)  # Wait longer on error
    
    def _perform_autonomous_tasks(self):
        """Perform autonomous tasks - implemented by subclasses"""
        pass
    
    def _update_status(self):
        """Update agent status"""
        with self.status_lock:
            self.last_activity = datetime.now()
            # Update status based on task queue
            if self.task_queue:
                self.status = AgentStatus.BUSY
            else:
                self.status = AgentStatus.ACTIVE
    
    def _update_metrics(self, response_time: float, success: bool):
        """Update performance metrics"""
        if success:
            self.metrics['tasks_completed'] += 1
        else:
            self.metrics['tasks_failed'] += 1
        
        # Update average response time
        total_tasks = self.metrics['tasks_completed'] + self.metrics['tasks_failed']
        if total_tasks > 0:
            current_avg = self.metrics['average_response_time']
            self.metrics['average_response_time'] = (
                (current_avg * (total_tasks - 1) + response_time) / total_tasks
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get agent performance metrics"""
        return {
            'agent_name': self.name,
            'status': self.status.value,
            'last_activity': self.last_activity.isoformat(),
            'active_tasks': len(self.active_tasks),
            'queued_tasks': len(self.task_queue),
            'metrics': self.metrics
        }
    
    def get_conversation_history(self, user_id: str) -> List[Dict[str, Any]]:
        """Get conversation history for a user"""
        return self.conversation_history.get(user_id, [])
    
    def add_to_conversation_history(self, user_id: str, message: str, response: str):
        """Add to conversation history"""
        if user_id not in self.conversation_history:
            self.conversation_history[user_id] = []
        
        self.conversation_history[user_id].append({
            'timestamp': datetime.now().isoformat(),
            'message': message,
            'response': response
        })
        
        # Keep only last 50 messages per user
        if len(self.conversation_history[user_id]) > 50:
            self.conversation_history[user_id] = self.conversation_history[user_id][-50:]
    
    def execute_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """Execute a cybersecurity tool"""
        if not cybersec_tools:
            return {"error": "Cybersecurity tools not available"}
        
        try:
            tool_method = getattr(cybersec_tools, tool_name, None)
            if not tool_method:
                return {"error": f"Tool '{tool_name}' not found"}
            
            result = tool_method(**kwargs)
            
            # Log tool usage
            self.logger.info(f"Executed tool: {tool_name}", kwargs=kwargs)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error executing tool {tool_name}: {str(e)}")
            return {"error": f"Tool execution failed: {str(e)}"}
    
    def get_available_tools(self) -> List[str]:
        """Get list of available cybersecurity tools"""
        if not cybersec_tools:
            return []
        
        tools = []
        for attr_name in dir(cybersec_tools):
            if not attr_name.startswith('_') and callable(getattr(cybersec_tools, attr_name)):
                tools.append(attr_name)
        
        return tools
    
    def process_query(self, query: str, user_id: str = None) -> str:
        """Process a query and return a response - used by the UI"""
        try:
            # Get conversation context if user_id provided
            context = {}
            if user_id:
                history = self.get_conversation_history(user_id)
                context = {
                    'user_id': user_id,
                    'conversation_history': history[-5:] if history else [],
                    'agent_capabilities': self.capabilities,
                    'available_tools': self.get_available_tools()
                }
            
            # Process the message
            response = self.process_message(query, context)
            
            # Add to conversation history if user_id provided
            if user_id:
                self.add_to_conversation_history(user_id, query, response)
            
            # Update activity
            self.last_activity = datetime.now()
            
            return response
            
        except Exception as e:
            self.logger.error(f"Error processing query: {str(e)}")
            return f"I encountered an error while processing your request: {str(e)}"

    def handle_chat_message(self, user_id: str, message: str) -> str:
        """Handle incoming chat message - legacy method"""
        return self.process_query(message, user_id)
    
    def get_agent_info(self) -> Dict[str, Any]:
        """Get comprehensive agent information"""
        return {
            'agent_id': self.agent_id,
            'name': self.name,
            'description': self.description,
            'capabilities': self.capabilities,
            'status': self.status.value,
            'last_activity': self.last_activity.isoformat(),
            'active_tasks': len(self.active_tasks),
            'queued_tasks': len(self.task_queue),
            'available_tasks': self.get_available_tasks(),
            'metrics': self.metrics,
            'config': self.config
        }
    
    def shutdown(self):
        """Gracefully shutdown the agent"""
        self.logger.info(f"Shutting down agent: {self.name}")
        
        with self.status_lock:
            self.status = AgentStatus.INACTIVE
        
        # Cancel all pending tasks
        with self.task_lock:
            for task in self.task_queue:
                task['status'] = TaskStatus.CANCELLED
            self.task_queue.clear()
        
        # Log shutdown
        log_agent_activity(
            agent_name=self.name,
            action='agent_shutdown',
            status=TaskStatus.COMPLETED,
            metadata={'agent_id': self.agent_id}
        )
    
    def __str__(self):
        return f"Agent({self.name})"
    
    def __repr__(self):
        return f"<Agent {self.name} - {self.status.value}>"