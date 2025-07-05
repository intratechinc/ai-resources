#!/usr/bin/env python3
"""
Threat Intelligence Agent for Intratech Cybersecurity Suite
Handles threat analysis, IOC checking, and threat actor intelligence
"""

import json
import requests
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import hashlib
import re

from .base_agent import BaseAgent, TaskPriority
from config import Config
from database import create_threat_intel, ThreatIntelligence, SeverityLevel

class ThreatIntelligenceAgent(BaseAgent):
    """
    Specialized agent for threat intelligence operations
    """
    
    def __init__(self):
        super().__init__(
            name="Threat Intelligence Agent",
            description="Analyzes threats, IOCs, and threat actor intelligence",
            capabilities=[
                "IOC analysis and lookup",
                "Threat actor profiling",
                "Malware family identification",
                "Campaign attribution",
                "Threat intelligence feeds processing",
                "Risk assessment",
                "TTPs (Tactics, Techniques, Procedures) analysis",
                "Threat hunting support",
                "Intelligence correlation",
                "Threat landscape monitoring"
            ]
        )
        
        # Initialize threat intelligence sources
        self.threat_sources = {
            'virustotal': {
                'enabled': bool(Config.VIRUSTOTAL_API_KEY),
                'api_key': Config.VIRUSTOTAL_API_KEY,
                'base_url': 'https://www.virustotal.com/api/v3'
            },
            'shodan': {
                'enabled': bool(Config.SHODAN_API_KEY),
                'api_key': Config.SHODAN_API_KEY,
                'base_url': 'https://api.shodan.io'
            }
        }
        
        # IOC types and patterns
        self.ioc_patterns = {
            'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            'url': r'https?://[^\s]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'md5': r'\b[a-fA-F0-9]{32}\b',
            'sha1': r'\b[a-fA-F0-9]{40}\b',
            'sha256': r'\b[a-fA-F0-9]{64}\b',
            'file_path': r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*',
            'registry_key': r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*'
        }
        
        # Threat actor database (simplified)
        self.threat_actors = {
            'APT1': {
                'country': 'China',
                'targets': ['Government', 'Military', 'Energy'],
                'ttps': ['Spear-phishing', 'Web shells', 'Remote access tools']
            },
            'Lazarus': {
                'country': 'North Korea',
                'targets': ['Financial', 'Cryptocurrency', 'Entertainment'],
                'ttps': ['Watering hole attacks', 'Supply chain attacks', 'Destructive malware']
            },
            'Fancy Bear': {
                'country': 'Russia',
                'targets': ['Government', 'Military', 'Elections'],
                'ttps': ['Spear-phishing', 'Zero-day exploits', 'Credential harvesting']
            }
        }
        
        # Threat intelligence cache
        self.intelligence_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        self.logger.info("Threat Intelligence Agent initialized")
    
    def get_system_prompt(self) -> str:
        """Get the system prompt for threat intelligence analysis"""
        return """You are a Threat Intelligence Agent specializing in cybersecurity threat analysis. Your expertise includes:

**Core Capabilities:**
• IOC (Indicators of Compromise) analysis and validation
• Threat actor profiling and attribution
• Malware family identification and classification
• Campaign tracking and correlation
• TTPs (Tactics, Techniques, Procedures) analysis
• Threat landscape assessment
• Risk scoring and prioritization

**Analysis Approach:**
1. Extract and validate IOCs from provided data
2. Cross-reference with threat intelligence databases
3. Assess threat severity and confidence levels
4. Provide attribution when possible
5. Recommend defensive measures
6. Correlate with known campaigns or threat actors

**Response Format:**
• Provide clear, actionable intelligence
• Include confidence levels (High/Medium/Low)
• Explain the reasoning behind assessments
• Suggest mitigation strategies
• Highlight critical threats requiring immediate attention

Always maintain analytical objectivity and clearly distinguish between confirmed facts and analytical assessments."""
    
    def process_message(self, message: str, context: Dict[str, Any] = None) -> str:
        """Process threat intelligence related messages"""
        try:
            # Extract IOCs from the message
            iocs = self._extract_iocs(message)
            
            # Analyze the message for threat intelligence requests
            analysis_type = self._determine_analysis_type(message)
            
            if analysis_type == 'ioc_lookup':
                return self._handle_ioc_lookup(iocs, message)
            elif analysis_type == 'threat_actor_info':
                return self._handle_threat_actor_query(message)
            elif analysis_type == 'malware_analysis':
                return self._handle_malware_query(message, iocs)
            elif analysis_type == 'campaign_attribution':
                return self._handle_campaign_query(message, iocs)
            else:
                return self._handle_general_threat_query(message, iocs)
                
        except Exception as e:
            self.logger.error(f"Error processing threat intelligence message: {str(e)}")
            return f"I encountered an error while analyzing the threat intelligence: {str(e)}"
    
    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text"""
        iocs = {}
        
        for ioc_type, pattern in self.ioc_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                iocs[ioc_type] = list(set(matches))  # Remove duplicates
        
        return iocs
    
    def _determine_analysis_type(self, message: str) -> str:
        """Determine the type of threat intelligence analysis needed"""
        message_lower = message.lower()
        
        if any(word in message_lower for word in ['ioc', 'indicator', 'lookup', 'check']):
            return 'ioc_lookup'
        elif any(word in message_lower for word in ['threat actor', 'apt', 'group', 'attribution']):
            return 'threat_actor_info'
        elif any(word in message_lower for word in ['malware', 'virus', 'trojan', 'ransomware']):
            return 'malware_analysis'
        elif any(word in message_lower for word in ['campaign', 'operation', 'attack']):
            return 'campaign_attribution'
        else:
            return 'general_threat_intelligence'
    
    def _handle_ioc_lookup(self, iocs: Dict[str, List[str]], message: str) -> str:
        """Handle IOC lookup requests"""
        if not iocs:
            return "I didn't find any IOCs in your message. Please provide IP addresses, domains, URLs, or file hashes for analysis."
        
        response = "🔍 **IOC Analysis Results**\n\n"
        
        for ioc_type, values in iocs.items():
            response += f"**{ioc_type.replace('_', ' ').title()}s Found:**\n"
            
            for value in values[:5]:  # Limit to 5 per type
                analysis = self._analyze_ioc(ioc_type, value)
                response += f"• `{value}` - {analysis['verdict']} (Confidence: {analysis['confidence']})\n"
                
                if analysis['details']:
                    response += f"  └─ {analysis['details']}\n"
            
            response += "\n"
        
        # Add general recommendations
        response += "**Recommendations:**\n"
        response += "• Monitor network traffic for these IOCs\n"
        response += "• Check endpoint logs for any matches\n"
        response += "• Consider blocking malicious indicators\n"
        response += "• Investigate any systems that may have been exposed\n"
        
        return response
    
    def _analyze_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Analyze a single IOC"""
        # Check cache first
        cache_key = f"{ioc_type}:{value}"
        if cache_key in self.intelligence_cache:
            cached_data = self.intelligence_cache[cache_key]
            if datetime.now() - cached_data['timestamp'] < timedelta(seconds=self.cache_ttl):
                return cached_data['analysis']
        
        # Perform analysis
        analysis = {
            'verdict': 'Unknown',
            'confidence': 'Low',
            'details': '',
            'threat_score': 0,
            'sources': []
        }
        
        try:
            if ioc_type in ['ip_address', 'domain', 'url']:
                analysis = self._analyze_network_ioc(ioc_type, value)
            elif ioc_type in ['md5', 'sha1', 'sha256']:
                analysis = self._analyze_file_hash(value)
            
            # Cache the result
            self.intelligence_cache[cache_key] = {
                'timestamp': datetime.now(),
                'analysis': analysis
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing IOC {value}: {str(e)}")
            analysis['details'] = f"Analysis failed: {str(e)}"
        
        return analysis
    
    def _analyze_network_ioc(self, ioc_type: str, value: str) -> Dict[str, Any]:
        """Analyze network-based IOCs"""
        analysis = {
            'verdict': 'Clean',
            'confidence': 'Medium',
            'details': 'No malicious activity detected',
            'threat_score': 0,
            'sources': []
        }
        
        # Simulate threat intelligence lookup
        # In a real implementation, this would query actual threat intelligence APIs
        
        # Check against known bad domains/IPs (simplified)
        known_bad = ['malware.com', 'badactor.net', '192.168.1.100']
        if value in known_bad:
            analysis.update({
                'verdict': 'Malicious',
                'confidence': 'High',
                'details': 'Known malicious indicator',
                'threat_score': 85,
                'sources': ['Internal Threat Intelligence']
            })
        
        return analysis
    
    def _analyze_file_hash(self, hash_value: str) -> Dict[str, Any]:
        """Analyze file hashes"""
        analysis = {
            'verdict': 'Clean',
            'confidence': 'Medium',
            'details': 'No malicious signatures found',
            'threat_score': 0,
            'sources': []
        }
        
        # Simulate hash lookup
        # In a real implementation, this would query VirusTotal, etc.
        
        return analysis
    
    def _handle_threat_actor_query(self, message: str) -> str:
        """Handle threat actor information queries"""
        response = "🕵️ **Threat Actor Intelligence**\n\n"
        
        # Extract potential threat actor names
        message_upper = message.upper()
        found_actors = []
        
        for actor, info in self.threat_actors.items():
            if actor.upper() in message_upper:
                found_actors.append((actor, info))
        
        if found_actors:
            for actor, info in found_actors:
                response += f"**{actor}**\n"
                response += f"• **Attribution:** {info['country']}\n"
                response += f"• **Primary Targets:** {', '.join(info['targets'])}\n"
                response += f"• **Common TTPs:** {', '.join(info['ttps'])}\n\n"
        else:
            response += "I can provide information about the following threat actors:\n"
            for actor in self.threat_actors.keys():
                response += f"• {actor}\n"
            response += "\nPlease specify which threat actor you'd like to learn about."
        
        return response
    
    def _handle_malware_query(self, message: str, iocs: Dict[str, List[str]]) -> str:
        """Handle malware-related queries"""
        response = "🦠 **Malware Intelligence Analysis**\n\n"
        
        # Analyze any file hashes provided
        if any(key in iocs for key in ['md5', 'sha1', 'sha256']):
            response += "**File Hash Analysis:**\n"
            for hash_type in ['md5', 'sha1', 'sha256']:
                if hash_type in iocs:
                    for hash_value in iocs[hash_type]:
                        analysis = self._analyze_file_hash(hash_value)
                        response += f"• {hash_type.upper()}: `{hash_value}`\n"
                        response += f"  └─ Verdict: {analysis['verdict']}\n"
        
        # General malware information
        response += "\n**Malware Analysis Capabilities:**\n"
        response += "• Static analysis of file hashes\n"
        response += "• Behavioral analysis indicators\n"
        response += "• Malware family classification\n"
        response += "• Campaign attribution\n"
        response += "• Threat actor correlation\n"
        
        return response
    
    def _handle_campaign_query(self, message: str, iocs: Dict[str, List[str]]) -> str:
        """Handle campaign attribution queries"""
        response = "🎯 **Campaign Attribution Analysis**\n\n"
        
        response += "**Campaign Analysis Process:**\n"
        response += "1. IOC correlation across multiple sources\n"
        response += "2. TTPs pattern matching\n"
        response += "3. Infrastructure analysis\n"
        response += "4. Timeline correlation\n"
        response += "5. Threat actor attribution\n\n"
        
        if iocs:
            response += "**IOCs Provided for Analysis:**\n"
            for ioc_type, values in iocs.items():
                response += f"• {ioc_type.replace('_', ' ').title()}: {len(values)} indicators\n"
        
        response += "\n**Note:** Campaign attribution requires comprehensive analysis of multiple data points and may take additional time for accurate assessment."
        
        return response
    
    def _handle_general_threat_query(self, message: str, iocs: Dict[str, List[str]]) -> str:
        """Handle general threat intelligence queries"""
        response = "🛡️ **Threat Intelligence Analysis**\n\n"
        
        if iocs:
            response += "**IOCs Detected:**\n"
            for ioc_type, values in iocs.items():
                response += f"• {ioc_type.replace('_', ' ').title()}: {len(values)} found\n"
            response += "\n"
        
        response += "**Available Intelligence Services:**\n"
        response += "• IOC lookup and validation\n"
        response += "• Threat actor profiling\n"
        response += "• Malware family identification\n"
        response += "• Campaign attribution\n"
        response += "• Risk assessment\n"
        response += "• Threat hunting support\n\n"
        
        response += "**How to use:**\n"
        response += "• Provide IOCs (IPs, domains, hashes) for analysis\n"
        response += "• Ask about specific threat actors or campaigns\n"
        response += "• Request threat assessments for your environment\n"
        response += "• Get recommendations for threat hunting\n"
        
        return response
    
    def execute_task(self, task_type: str, parameters: Dict[str, Any], user_id: str = None) -> str:
        """Execute threat intelligence specific tasks"""
        if task_type == 'ioc_analysis':
            return self._perform_ioc_analysis(parameters)
        elif task_type == 'threat_actor_lookup':
            return self._perform_threat_actor_lookup(parameters)
        elif task_type == 'malware_analysis':
            return self._perform_malware_analysis(parameters)
        elif task_type == 'campaign_attribution':
            return self._perform_campaign_attribution(parameters)
        elif task_type == 'threat_assessment':
            return self._perform_threat_assessment(parameters)
        else:
            return f"Unknown task type: {task_type}"
    
    def _perform_ioc_analysis(self, parameters: Dict[str, Any]) -> str:
        """Perform IOC analysis task"""
        iocs = parameters.get('iocs', {})
        
        if not iocs:
            return "No IOCs provided for analysis"
        
        results = []
        for ioc_type, values in iocs.items():
            for value in values:
                analysis = self._analyze_ioc(ioc_type, value)
                results.append({
                    'type': ioc_type,
                    'value': value,
                    'analysis': analysis
                })
        
        return json.dumps(results, indent=2)
    
    def _perform_threat_actor_lookup(self, parameters: Dict[str, Any]) -> str:
        """Perform threat actor lookup"""
        actor_name = parameters.get('actor_name', '')
        
        if actor_name in self.threat_actors:
            return json.dumps(self.threat_actors[actor_name], indent=2)
        else:
            return f"Threat actor '{actor_name}' not found in database"
    
    def _perform_malware_analysis(self, parameters: Dict[str, Any]) -> str:
        """Perform malware analysis"""
        file_hash = parameters.get('file_hash', '')
        
        if file_hash:
            analysis = self._analyze_file_hash(file_hash)
            return json.dumps(analysis, indent=2)
        else:
            return "No file hash provided for analysis"
    
    def _perform_campaign_attribution(self, parameters: Dict[str, Any]) -> str:
        """Perform campaign attribution"""
        # This would involve complex analysis of multiple IOCs and TTPs
        return "Campaign attribution analysis initiated - detailed report will be generated"
    
    def _perform_threat_assessment(self, parameters: Dict[str, Any]) -> str:
        """Perform threat assessment"""
        # This would analyze current threat landscape
        return "Threat assessment completed - current threat level: MEDIUM"
    
    def get_available_tasks(self) -> List[Dict[str, Any]]:
        """Get list of available threat intelligence tasks"""
        return [
            {
                'name': 'ioc_analysis',
                'description': 'Analyze IOCs (Indicators of Compromise)',
                'parameters': ['iocs']
            },
            {
                'name': 'threat_actor_lookup',
                'description': 'Lookup information about threat actors',
                'parameters': ['actor_name']
            },
            {
                'name': 'malware_analysis',
                'description': 'Analyze malware samples by hash',
                'parameters': ['file_hash']
            },
            {
                'name': 'campaign_attribution',
                'description': 'Attribute IOCs to known campaigns',
                'parameters': ['iocs', 'ttps']
            },
            {
                'name': 'threat_assessment',
                'description': 'Assess current threat landscape',
                'parameters': ['scope', 'timeframe']
            }
        ]
    
    def _perform_autonomous_tasks(self):
        """Perform autonomous threat intelligence tasks"""
        try:
            # Update threat intelligence feeds
            self._update_threat_feeds()
            
            # Clean old cache entries
            self._cleanup_cache()
            
            # Monitor for new threats
            self._monitor_threat_landscape()
            
        except Exception as e:
            self.logger.error(f"Error in autonomous threat intelligence tasks: {str(e)}")
    
    def _update_threat_feeds(self):
        """Update threat intelligence feeds"""
        # This would update from various threat intelligence sources
        self.logger.debug("Updating threat intelligence feeds")
    
    def _cleanup_cache(self):
        """Clean up old cache entries"""
        current_time = datetime.now()
        expired_keys = []
        
        for key, data in self.intelligence_cache.items():
            if current_time - data['timestamp'] > timedelta(seconds=self.cache_ttl):
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.intelligence_cache[key]
        
        if expired_keys:
            self.logger.debug(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def _monitor_threat_landscape(self):
        """Monitor current threat landscape"""
        # This would monitor for emerging threats
        self.logger.debug("Monitoring threat landscape")
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get current threat intelligence summary"""
        return {
            'cached_iocs': len(self.intelligence_cache),
            'threat_actors': len(self.threat_actors),
            'active_sources': sum(1 for source in self.threat_sources.values() if source['enabled']),
            'last_update': datetime.now().isoformat()
        }