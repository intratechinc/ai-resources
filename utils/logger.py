#!/usr/bin/env python3
"""
Logging utility for Intratech Cybersecurity Suite
"""

import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
import sys
from typing import Optional
import json
from rich.console import Console
from rich.logging import RichHandler
from colorama import Fore, Back, Style, init

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    # Color mapping for different log levels
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE + Style.BRIGHT,
    }
    
    def format(self, record):
        # Get the original formatted message
        log_message = super().format(record)
        
        # Add color based on log level
        color = self.COLORS.get(record.levelname, '')
        if color:
            log_message = f"{color}{log_message}{Style.RESET_ALL}"
        
        return log_message

class CybersecurityLogger:
    """Enhanced logger for cybersecurity operations"""
    
    def __init__(self, name: str, log_level: str = 'INFO'):
        self.name = name
        self.log_level = log_level
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, log_level.upper()))
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            self._setup_handlers()
    
    def _setup_handlers(self):
        """Setup logging handlers"""
        
        # Create logs directory if it doesn't exist
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # File handler for all logs
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'cybersecurity_suite.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        
        # Separate file handler for security events
        security_handler = logging.handlers.RotatingFileHandler(
            log_dir / 'security_events.log',
            maxBytes=20*1024*1024,  # 20MB
            backupCount=10
        )
        security_handler.setLevel(logging.WARNING)
        security_formatter = logging.Formatter(
            '%(asctime)s - SECURITY - %(name)s - %(levelname)s - %(message)s'
        )
        security_handler.setFormatter(security_formatter)
        
        # Console handler with colors
        console_handler = RichHandler(
            console=Console(stderr=True),
            show_time=True,
            show_path=True,
            markup=True,
            rich_tracebacks=True
        )
        console_handler.setLevel(getattr(logging, self.log_level.upper()))
        
        # Add handlers to logger
        self.logger.addHandler(file_handler)
        self.logger.addHandler(security_handler)
        self.logger.addHandler(console_handler)
    
    def debug(self, message: str, **kwargs):
        """Log debug message"""
        self.logger.debug(self._format_message(message, **kwargs))
    
    def info(self, message: str, **kwargs):
        """Log info message"""
        self.logger.info(self._format_message(message, **kwargs))
    
    def warning(self, message: str, **kwargs):
        """Log warning message"""
        self.logger.warning(self._format_message(message, **kwargs))
    
    def error(self, message: str, **kwargs):
        """Log error message"""
        self.logger.error(self._format_message(message, **kwargs))
    
    def critical(self, message: str, **kwargs):
        """Log critical message"""
        self.logger.critical(self._format_message(message, **kwargs))
    
    def security_event(self, event_type: str, description: str, **kwargs):
        """Log security event"""
        event_data = {
            'event_type': event_type,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.logger.warning(f"SECURITY_EVENT: {json.dumps(event_data, indent=2)}")
    
    def agent_activity(self, agent_name: str, action: str, status: str = 'success', **kwargs):
        """Log agent activity"""
        activity_data = {
            'agent': agent_name,
            'action': action,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.logger.info(f"AGENT_ACTIVITY: {json.dumps(activity_data, indent=2)}")
    
    def threat_detection(self, threat_type: str, severity: str, details: dict):
        """Log threat detection"""
        threat_data = {
            'threat_type': threat_type,
            'severity': severity,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.logger.warning(f"THREAT_DETECTED: {json.dumps(threat_data, indent=2)}")
    
    def vulnerability_found(self, target: str, vulnerability: dict):
        """Log vulnerability discovery"""
        vuln_data = {
            'target': target,
            'vulnerability': vulnerability,
            'timestamp': datetime.now().isoformat()
        }
        self.logger.warning(f"VULNERABILITY_FOUND: {json.dumps(vuln_data, indent=2)}")
    
    def incident_response(self, incident_id: str, action: str, status: str, **kwargs):
        """Log incident response actions"""
        incident_data = {
            'incident_id': incident_id,
            'action': action,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.logger.error(f"INCIDENT_RESPONSE: {json.dumps(incident_data, indent=2)}")
    
    def compliance_check(self, framework: str, control: str, status: str, **kwargs):
        """Log compliance check results"""
        compliance_data = {
            'framework': framework,
            'control': control,
            'status': status,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.logger.info(f"COMPLIANCE_CHECK: {json.dumps(compliance_data, indent=2)}")
    
    def malware_analysis(self, file_hash: str, verdict: str, details: dict):
        """Log malware analysis results"""
        analysis_data = {
            'file_hash': file_hash,
            'verdict': verdict,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.logger.warning(f"MALWARE_ANALYSIS: {json.dumps(analysis_data, indent=2)}")
    
    def forensic_activity(self, case_id: str, evidence_type: str, action: str, **kwargs):
        """Log forensic activities"""
        forensic_data = {
            'case_id': case_id,
            'evidence_type': evidence_type,
            'action': action,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.logger.info(f"FORENSIC_ACTIVITY: {json.dumps(forensic_data, indent=2)}")
    
    def network_event(self, event_type: str, source: str, destination: str, **kwargs):
        """Log network security events"""
        network_data = {
            'event_type': event_type,
            'source': source,
            'destination': destination,
            'timestamp': datetime.now().isoformat(),
            **kwargs
        }
        self.logger.info(f"NETWORK_EVENT: {json.dumps(network_data, indent=2)}")
    
    def _format_message(self, message: str, **kwargs) -> str:
        """Format log message with additional context"""
        if kwargs:
            context = json.dumps(kwargs, default=str, indent=2)
            return f"{message} | Context: {context}"
        return message

class AuditLogger:
    """Specialized logger for audit trails"""
    
    def __init__(self):
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        
        if not self.logger.handlers:
            self._setup_audit_handler()
    
    def _setup_audit_handler(self):
        """Setup audit-specific handler"""
        log_dir = Path('logs')
        log_dir.mkdir(exist_ok=True)
        
        # Audit log handler (never rotated for compliance)
        audit_handler = logging.FileHandler(
            log_dir / 'audit.log',
            mode='a'
        )
        audit_handler.setLevel(logging.INFO)
        audit_formatter = logging.Formatter(
            '%(asctime)s - AUDIT - %(message)s'
        )
        audit_handler.setFormatter(audit_formatter)
        
        self.logger.addHandler(audit_handler)
    
    def log_access(self, user_id: str, resource: str, action: str, result: str):
        """Log access attempts"""
        audit_entry = {
            'type': 'access',
            'user_id': user_id,
            'resource': resource,
            'action': action,
            'result': result,
            'timestamp': datetime.now().isoformat(),
            'source_ip': 'system'  # TODO: Get actual IP
        }
        self.logger.info(json.dumps(audit_entry))
    
    def log_data_access(self, user_id: str, data_type: str, record_count: int):
        """Log data access"""
        audit_entry = {
            'type': 'data_access',
            'user_id': user_id,
            'data_type': data_type,
            'record_count': record_count,
            'timestamp': datetime.now().isoformat()
        }
        self.logger.info(json.dumps(audit_entry))
    
    def log_configuration_change(self, user_id: str, component: str, change_type: str, details: dict):
        """Log configuration changes"""
        audit_entry = {
            'type': 'configuration_change',
            'user_id': user_id,
            'component': component,
            'change_type': change_type,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.logger.info(json.dumps(audit_entry))

def setup_logger(name: str, log_level: str = 'INFO') -> CybersecurityLogger:
    """
    Setup and return a cybersecurity logger instance
    
    Args:
        name: Logger name
        log_level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    
    Returns:
        CybersecurityLogger instance
    """
    return CybersecurityLogger(name, log_level)

def get_audit_logger() -> AuditLogger:
    """
    Get audit logger instance
    
    Returns:
        AuditLogger instance
    """
    return AuditLogger()

# Performance monitoring decorator
def log_performance(logger: CybersecurityLogger):
    """Decorator to log function performance"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            start_time = datetime.now()
            try:
                result = func(*args, **kwargs)
                end_time = datetime.now()
                execution_time = (end_time - start_time).total_seconds()
                
                logger.debug(
                    f"Performance: {func.__name__} executed successfully",
                    execution_time=execution_time,
                    function=func.__name__,
                    args_count=len(args),
                    kwargs_count=len(kwargs)
                )
                return result
            except Exception as e:
                end_time = datetime.now()
                execution_time = (end_time - start_time).total_seconds()
                
                logger.error(
                    f"Performance: {func.__name__} failed with error: {str(e)}",
                    execution_time=execution_time,
                    function=func.__name__,
                    error=str(e)
                )
                raise
        return wrapper
    return decorator

# Security event levels
class SecurityEventLevel:
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'

# Common log message templates
class LogTemplates:
    USER_LOGIN = "User login attempt: {user_id} from {source_ip}"
    FAILED_LOGIN = "Failed login attempt: {user_id} from {source_ip}"
    UNAUTHORIZED_ACCESS = "Unauthorized access attempt to {resource} by {user_id}"
    THREAT_DETECTED = "Threat detected: {threat_type} with severity {severity}"
    VULNERABILITY_DISCOVERED = "Vulnerability discovered: {vuln_id} on {target}"
    INCIDENT_CREATED = "Security incident created: {incident_id} with severity {severity}"
    COMPLIANCE_VIOLATION = "Compliance violation: {framework} control {control_id}"
    MALWARE_DETECTED = "Malware detected: {file_name} with hash {file_hash}"
    NETWORK_ANOMALY = "Network anomaly detected: {anomaly_type} from {source_ip}"
    FORENSIC_EVIDENCE = "Forensic evidence collected: {evidence_type} for case {case_id}"