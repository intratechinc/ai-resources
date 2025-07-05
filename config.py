#!/usr/bin/env python3
"""
Configuration file for Intratech Cybersecurity Suite
"""

import os
from datetime import timedelta

class Config:
    """Application configuration"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'intratech-cybersecurity-suite-2024'
    DEBUG = os.environ.get('DEBUG', 'True').lower() == 'true'
    
    # Database Configuration
    DATABASE_URL = os.environ.get('DATABASE_URL') or 'sqlite:///cybersecurity_suite.db'
    SQLALCHEMY_DATABASE_URI = DATABASE_URL
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # Redis Configuration (for caching and task queue)
    REDIS_URL = os.environ.get('REDIS_URL') or 'redis://localhost:6379/0'
    
    # AI/LLM Configuration
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY')
    DEFAULT_LLM_MODEL = 'gpt-4-turbo-preview'
    
    # Security API Keys
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    CENSYS_API_ID = os.environ.get('CENSYS_API_ID')
    CENSYS_API_SECRET = os.environ.get('CENSYS_API_SECRET')
    
    # Notification Configuration
    SLACK_WEBHOOK_URL = os.environ.get('SLACK_WEBHOOK_URL')
    EMAIL_SMTP_SERVER = os.environ.get('EMAIL_SMTP_SERVER')
    EMAIL_SMTP_PORT = int(os.environ.get('EMAIL_SMTP_PORT', 587))
    EMAIL_USERNAME = os.environ.get('EMAIL_USERNAME')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD')
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/cybersecurity_suite.log')
    
    # Agent Configuration
    AGENT_UPDATE_INTERVAL = int(os.environ.get('AGENT_UPDATE_INTERVAL', 60))  # seconds
    MAX_CONCURRENT_TASKS = int(os.environ.get('MAX_CONCURRENT_TASKS', 10))
    TASK_TIMEOUT = int(os.environ.get('TASK_TIMEOUT', 300))  # seconds
    
    # Security Scanning Configuration
    NMAP_SCAN_TIMEOUT = int(os.environ.get('NMAP_SCAN_TIMEOUT', 300))
    VULN_SCAN_THREADS = int(os.environ.get('VULN_SCAN_THREADS', 5))
    PENTEST_TIMEOUT = int(os.environ.get('PENTEST_TIMEOUT', 3600))  # 1 hour
    
    # Threat Intelligence Configuration
    THREAT_INTEL_UPDATE_INTERVAL = int(os.environ.get('THREAT_INTEL_UPDATE_INTERVAL', 3600))  # 1 hour
    IOC_RETENTION_DAYS = int(os.environ.get('IOC_RETENTION_DAYS', 90))
    
    # Network Monitoring Configuration
    NETWORK_SCAN_INTERVAL = int(os.environ.get('NETWORK_SCAN_INTERVAL', 300))  # 5 minutes
    PACKET_CAPTURE_DURATION = int(os.environ.get('PACKET_CAPTURE_DURATION', 60))  # 1 minute
    
    # Compliance Configuration
    COMPLIANCE_SCAN_INTERVAL = int(os.environ.get('COMPLIANCE_SCAN_INTERVAL', 86400))  # 24 hours
    COMPLIANCE_FRAMEWORKS = ['SOC2', 'ISO27001', 'NIST', 'GDPR', 'HIPAA']
    
    # File Upload Configuration
    MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB
    UPLOAD_FOLDER = os.environ.get('UPLOAD_FOLDER', 'uploads/')
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'exe', 'dll', 'bin'}
    
    # JWT Configuration
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or SECRET_KEY
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(days=30)
    
    # Rate Limiting
    RATE_LIMIT_ENABLED = os.environ.get('RATE_LIMIT_ENABLED', 'True').lower() == 'true'
    RATE_LIMIT_DEFAULT = os.environ.get('RATE_LIMIT_DEFAULT', '100 per hour')
    
    # CORS Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*').split(',')
    
    # WebSocket Configuration
    WEBSOCKET_PING_INTERVAL = int(os.environ.get('WEBSOCKET_PING_INTERVAL', 25))
    WEBSOCKET_PING_TIMEOUT = int(os.environ.get('WEBSOCKET_PING_TIMEOUT', 60))
    
    # MCP Server Configuration
    MCP_SERVERS = {
        'shodan': {
            'enabled': bool(SHODAN_API_KEY),
            'endpoint': 'https://api.shodan.io',
            'timeout': 30
        },
        'virustotal': {
            'enabled': bool(VIRUSTOTAL_API_KEY),
            'endpoint': 'https://www.virustotal.com/api/v3',
            'timeout': 30
        },
        'nuclei': {
            'enabled': True,
            'binary_path': os.environ.get('NUCLEI_PATH', '/usr/local/bin/nuclei'),
            'templates_path': os.environ.get('NUCLEI_TEMPLATES_PATH', './nuclei-templates')
        },
        'nmap': {
            'enabled': True,
            'binary_path': os.environ.get('NMAP_PATH', '/usr/bin/nmap'),
            'timeout': NMAP_SCAN_TIMEOUT
        }
    }
    
    # Agent Specialization Configuration
    AGENT_CONFIGS = {
        'coordinator': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.3,
            'max_tokens': 2000
        },
        'threat_intelligence': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.2,
            'max_tokens': 1500,
            'feed_urls': [
                'https://feeds.feedburner.com/TheHackersNews',
                'https://krebsonsecurity.com/feed/',
                'https://threatpost.com/feed/'
            ]
        },
        'vulnerability_scanner': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.1,
            'max_tokens': 1000,
            'scan_profiles': ['basic', 'comprehensive', 'stealth']
        },
        'penetration_testing': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.4,
            'max_tokens': 2000,
            'allowed_techniques': ['reconnaissance', 'scanning', 'enumeration']
        },
        'incident_response': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.2,
            'max_tokens': 1500,
            'escalation_thresholds': {
                'low': 1,
                'medium': 3,
                'high': 5,
                'critical': 8
            }
        },
        'osint': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.3,
            'max_tokens': 1500,
            'sources': ['social_media', 'public_records', 'leak_databases']
        },
        'malware_analysis': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.1,
            'max_tokens': 2000,
            'sandbox_timeout': 300
        },
        'network_security': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.2,
            'max_tokens': 1000,
            'monitoring_interfaces': ['eth0', 'wlan0']
        },
        'compliance': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.1,
            'max_tokens': 1500,
            'frameworks': COMPLIANCE_FRAMEWORKS
        },
        'forensics': {
            'model': 'gpt-4-turbo-preview',
            'temperature': 0.1,
            'max_tokens': 2000,
            'evidence_chain': True
        }
    }
    
    @staticmethod
    def get_agent_config(agent_type):
        """Get configuration for specific agent type"""
        return Config.AGENT_CONFIGS.get(agent_type, {})
    
    @staticmethod
    def get_mcp_server_config(server_type):
        """Get MCP server configuration"""
        return Config.MCP_SERVERS.get(server_type, {})
    
    @staticmethod
    def is_development():
        """Check if running in development mode"""
        return Config.DEBUG
    
    @staticmethod
    def validate_required_keys():
        """Validate that required API keys are present"""
        required_keys = []
        
        if not Config.OPENAI_API_KEY:
            required_keys.append('OPENAI_API_KEY')
        
        if required_keys:
            raise ValueError(f"Missing required environment variables: {', '.join(required_keys)}")
    
    @staticmethod
    def get_database_url():
        """Get database URL with proper formatting"""
        url = Config.DATABASE_URL
        if url.startswith('postgres://'):
            url = url.replace('postgres://', 'postgresql://', 1)
        return url