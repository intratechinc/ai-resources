#!/usr/bin/env python3
"""
Database models and initialization for Intratech Cybersecurity Suite
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timezone
import json
import uuid
from enum import Enum
from sqlalchemy import Column, String, Integer, DateTime, Text, Boolean, Float, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

# Initialize SQLAlchemy
db = SQLAlchemy()

class TaskStatus(Enum):
    """Task status enumeration"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class SeverityLevel(Enum):
    """Severity level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class AgentStatus(Enum):
    """Agent status enumeration"""
    ACTIVE = "active"
    INACTIVE = "inactive"
    BUSY = "busy"
    ERROR = "error"

class AgentLog(db.Model):
    """Agent activity logs"""
    __tablename__ = 'agent_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    agent_name = db.Column(db.String(100), nullable=False, index=True)
    user_id = db.Column(db.String(100), index=True)
    task_id = db.Column(db.String(100), index=True)
    action = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text)
    response = db.Column(db.Text)
    status = db.Column(db.Enum(TaskStatus), default=TaskStatus.PENDING)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    execution_time = db.Column(db.Float)  # seconds
    meta_data = db.Column(db.JSON)
    
    def __repr__(self):
        return f'<AgentLog {self.agent_name}: {self.action}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'agent_name': self.agent_name,
            'user_id': self.user_id,
            'task_id': self.task_id,
            'action': self.action,
            'message': self.message,
            'response': self.response,
            'status': self.status.value if self.status else None,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'execution_time': self.execution_time,
            'meta_data': self.meta_data
        }

class SecurityEvent(db.Model):
    """Security events and incidents"""
    __tablename__ = 'security_events'
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.Enum(SeverityLevel), nullable=False, index=True)
    category = db.Column(db.String(100), nullable=False, index=True)
    source_ip = db.Column(db.String(50), index=True)
    target_ip = db.Column(db.String(50), index=True)
    agent_name = db.Column(db.String(100), nullable=False, index=True)
    status = db.Column(db.String(50), default='open', index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime)
    assigned_to = db.Column(db.String(100))
    tags = db.Column(db.JSON)
    indicators = db.Column(db.JSON)  # IOCs
    mitigation_steps = db.Column(db.Text)
    false_positive = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<SecurityEvent {self.event_id}: {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'event_id': self.event_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value if self.severity else None,
            'category': self.category,
            'source_ip': self.source_ip,
            'target_ip': self.target_ip,
            'agent_name': self.agent_name,
            'status': self.status,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'assigned_to': self.assigned_to,
            'tags': self.tags,
            'indicators': self.indicators,
            'mitigation_steps': self.mitigation_steps,
            'false_positive': self.false_positive
        }

class ThreatIntelligence(db.Model):
    """Threat intelligence data"""
    __tablename__ = 'threat_intelligence'
    
    id = db.Column(db.Integer, primary_key=True)
    ioc_type = db.Column(db.String(50), nullable=False, index=True)  # ip, domain, hash, etc.
    ioc_value = db.Column(db.String(500), nullable=False, index=True)
    threat_type = db.Column(db.String(100), nullable=False, index=True)
    confidence = db.Column(db.Integer, default=50)  # 0-100
    severity = db.Column(db.Enum(SeverityLevel), nullable=False, index=True)
    source = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    tags = db.Column(db.JSON)
    ttps = db.Column(db.JSON)  # Tactics, Techniques, Procedures
    references = db.Column(db.JSON)
    active = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<ThreatIntelligence {self.ioc_type}: {self.ioc_value}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'ioc_type': self.ioc_type,
            'ioc_value': self.ioc_value,
            'threat_type': self.threat_type,
            'confidence': self.confidence,
            'severity': self.severity.value if self.severity else None,
            'source': self.source,
            'description': self.description,
            'first_seen': self.first_seen.isoformat() if self.first_seen else None,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'tags': self.tags,
            'ttps': self.ttps,
            'references': self.references,
            'active': self.active
        }

class VulnerabilityAssessment(db.Model):
    """Vulnerability assessment results"""
    __tablename__ = 'vulnerability_assessments'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    target = db.Column(db.String(200), nullable=False, index=True)
    vulnerability_id = db.Column(db.String(100), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.Enum(SeverityLevel), nullable=False, index=True)
    cvss_score = db.Column(db.Float)
    cve_id = db.Column(db.String(20), index=True)
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    solution = db.Column(db.Text)
    references = db.Column(db.JSON)
    evidence = db.Column(db.Text)
    scan_date = db.Column(db.DateTime, default=datetime.utcnow)
    verified = db.Column(db.Boolean, default=False)
    false_positive = db.Column(db.Boolean, default=False)
    remediated = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<VulnerabilityAssessment {self.vulnerability_id}: {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'target': self.target,
            'vulnerability_id': self.vulnerability_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.value if self.severity else None,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'port': self.port,
            'service': self.service,
            'solution': self.solution,
            'references': self.references,
            'evidence': self.evidence,
            'scan_date': self.scan_date.isoformat() if self.scan_date else None,
            'verified': self.verified,
            'false_positive': self.false_positive,
            'remediated': self.remediated
        }

class NetworkAsset(db.Model):
    """Network assets and inventory"""
    __tablename__ = 'network_assets'
    
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(50), unique=True, nullable=False, index=True)
    hostname = db.Column(db.String(200), index=True)
    mac_address = db.Column(db.String(18), index=True)
    os_name = db.Column(db.String(100))
    os_version = db.Column(db.String(100))
    device_type = db.Column(db.String(100))
    open_ports = db.Column(db.JSON)
    services = db.Column(db.JSON)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    first_discovered = db.Column(db.DateTime, default=datetime.utcnow)
    risk_score = db.Column(db.Integer, default=0)
    tags = db.Column(db.JSON)
    location = db.Column(db.String(200))
    owner = db.Column(db.String(100))
    criticality = db.Column(db.String(50), default='medium')
    monitoring = db.Column(db.Boolean, default=True)
    
    def __repr__(self):
        return f'<NetworkAsset {self.ip_address}: {self.hostname}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'mac_address': self.mac_address,
            'os_name': self.os_name,
            'os_version': self.os_version,
            'device_type': self.device_type,
            'open_ports': self.open_ports,
            'services': self.services,
            'last_seen': self.last_seen.isoformat() if self.last_seen else None,
            'first_discovered': self.first_discovered.isoformat() if self.first_discovered else None,
            'risk_score': self.risk_score,
            'tags': self.tags,
            'location': self.location,
            'owner': self.owner,
            'criticality': self.criticality,
            'monitoring': self.monitoring
        }

class MalwareAnalysis(db.Model):
    """Malware analysis results"""
    __tablename__ = 'malware_analysis'
    
    id = db.Column(db.Integer, primary_key=True)
    file_hash = db.Column(db.String(128), unique=True, nullable=False, index=True)
    file_name = db.Column(db.String(200), nullable=False)
    file_size = db.Column(db.Integer)
    file_type = db.Column(db.String(100))
    analysis_date = db.Column(db.DateTime, default=datetime.utcnow)
    is_malicious = db.Column(db.Boolean, default=False)
    malware_family = db.Column(db.String(100))
    threat_score = db.Column(db.Integer, default=0)  # 0-100
    yara_matches = db.Column(db.JSON)
    behavioral_analysis = db.Column(db.JSON)
    network_activity = db.Column(db.JSON)
    file_operations = db.Column(db.JSON)
    registry_changes = db.Column(db.JSON)
    api_calls = db.Column(db.JSON)
    strings_extracted = db.Column(db.JSON)
    antivirus_results = db.Column(db.JSON)
    sandbox_report = db.Column(db.JSON)
    
    def __repr__(self):
        return f'<MalwareAnalysis {self.file_hash}: {self.file_name}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'file_hash': self.file_hash,
            'file_name': self.file_name,
            'file_size': self.file_size,
            'file_type': self.file_type,
            'analysis_date': self.analysis_date.isoformat() if self.analysis_date else None,
            'is_malicious': self.is_malicious,
            'malware_family': self.malware_family,
            'threat_score': self.threat_score,
            'yara_matches': self.yara_matches,
            'behavioral_analysis': self.behavioral_analysis,
            'network_activity': self.network_activity,
            'file_operations': self.file_operations,
            'registry_changes': self.registry_changes,
            'api_calls': self.api_calls,
            'strings_extracted': self.strings_extracted,
            'antivirus_results': self.antivirus_results,
            'sandbox_report': self.sandbox_report
        }

class ComplianceCheck(db.Model):
    """Compliance check results"""
    __tablename__ = 'compliance_checks'
    
    id = db.Column(db.Integer, primary_key=True)
    check_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    framework = db.Column(db.String(50), nullable=False, index=True)
    control_id = db.Column(db.String(100), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False, index=True)  # pass, fail, not_applicable
    severity = db.Column(db.Enum(SeverityLevel), default=SeverityLevel.MEDIUM)
    evidence = db.Column(db.Text)
    remediation = db.Column(db.Text)
    check_date = db.Column(db.DateTime, default=datetime.utcnow)
    due_date = db.Column(db.DateTime)
    assigned_to = db.Column(db.String(100))
    notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<ComplianceCheck {self.check_id}: {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'check_id': self.check_id,
            'framework': self.framework,
            'control_id': self.control_id,
            'title': self.title,
            'description': self.description,
            'status': self.status,
            'severity': self.severity.value if self.severity else None,
            'evidence': self.evidence,
            'remediation': self.remediation,
            'check_date': self.check_date.isoformat() if self.check_date else None,
            'due_date': self.due_date.isoformat() if self.due_date else None,
            'assigned_to': self.assigned_to,
            'notes': self.notes
        }

class ForensicEvidence(db.Model):
    """Digital forensic evidence"""
    __tablename__ = 'forensic_evidence'
    
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    case_id = db.Column(db.String(100), nullable=False, index=True)
    evidence_type = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(200), nullable=False)
    hash_value = db.Column(db.String(128), index=True)
    file_path = db.Column(db.String(500))
    description = db.Column(db.Text)
    collected_by = db.Column(db.String(100), nullable=False)
    collection_date = db.Column(db.DateTime, default=datetime.utcnow)
    chain_of_custody = db.Column(db.JSON)
    analysis_results = db.Column(db.JSON)
    keywords = db.Column(db.JSON)
    meta_data = db.Column(db.JSON)
    integrity_verified = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<ForensicEvidence {self.evidence_id}: {self.evidence_type}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'evidence_id': self.evidence_id,
            'case_id': self.case_id,
            'evidence_type': self.evidence_type,
            'source': self.source,
            'hash_value': self.hash_value,
            'file_path': self.file_path,
            'description': self.description,
            'collected_by': self.collected_by,
            'collection_date': self.collection_date.isoformat() if self.collection_date else None,
            'chain_of_custody': self.chain_of_custody,
            'analysis_results': self.analysis_results,
            'keywords': self.keywords,
            'meta_data': self.meta_data,
            'integrity_verified': self.integrity_verified
        }

class ChatSession(db.Model):
    """Chat session tracking"""
    __tablename__ = 'chat_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), unique=True, nullable=False, index=True)
    user_id = db.Column(db.String(100), nullable=False, index=True)
    agent_name = db.Column(db.String(100), index=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    ended_at = db.Column(db.DateTime)
    message_count = db.Column(db.Integer, default=0)
    context = db.Column(db.JSON)
    
    def __repr__(self):
        return f'<ChatSession {self.session_id}: {self.user_id}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'session_id': self.session_id,
            'user_id': self.user_id,
            'agent_name': self.agent_name,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'ended_at': self.ended_at.isoformat() if self.ended_at else None,
            'message_count': self.message_count,
            'context': self.context
        }

def init_db(app):
    """Initialize database"""
    db.init_app(app)
    
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Create initial data if needed
        create_initial_data()

def create_initial_data():
    """Create initial data if database is empty"""
    try:
        # Check if we have any agents logged
        if not AgentLog.query.first():
            # Create initial system log
            initial_log = AgentLog(
                agent_name='system',
                action='system_startup',
                message='Intratech Cybersecurity Suite initialized',
                status=TaskStatus.COMPLETED
            )
            db.session.add(initial_log)
            db.session.commit()
            
    except Exception as e:
        print(f"Error creating initial data: {e}")
        db.session.rollback()

def get_db_stats():
    """Get database statistics"""
    return {
        'agent_logs': AgentLog.query.count(),
        'security_events': SecurityEvent.query.count(),
        'threat_intelligence': ThreatIntelligence.query.count(),
        'vulnerability_assessments': VulnerabilityAssessment.query.count(),
        'network_assets': NetworkAsset.query.count(),
        'malware_analysis': MalwareAnalysis.query.count(),
        'compliance_checks': ComplianceCheck.query.count(),
        'forensic_evidence': ForensicEvidence.query.count(),
        'chat_sessions': ChatSession.query.count()
    }

# Helper functions for database operations
def create_security_event(event_data):
    """Create a new security event"""
    event = SecurityEvent(
        event_id=event_data.get('event_id', str(uuid.uuid4())),
        **event_data
    )
    db.session.add(event)
    db.session.commit()
    return event

def create_threat_intel(intel_data):
    """Create new threat intelligence entry"""
    intel = ThreatIntelligence(**intel_data)
    db.session.add(intel)
    db.session.commit()
    return intel

def log_agent_activity(agent_name, action, **kwargs):
    """Log agent activity"""
    log = AgentLog(
        agent_name=agent_name,
        action=action,
        **kwargs
    )
    db.session.add(log)
    db.session.commit()
    return log