#!/usr/bin/env python3
"""
Cybersecurity Tools and Commands Module
Comprehensive toolkit for AI agents to perform security operations
"""

import subprocess
import json
import requests
import socket
import os
import hashlib
import base64
import re
from datetime import datetime
from typing import Dict, List, Any, Optional
import dns.resolver
import whois
from urllib.parse import urlparse
import ssl
import nmap
import shodan
from config import Config

class CybersecurityTools:
    """Comprehensive cybersecurity tools for AI agents"""
    
    def __init__(self):
        self.shodan_api = None
        if Config.SHODAN_API_KEY:
            self.shodan_api = shodan.Shodan(Config.SHODAN_API_KEY)
        
        # Initialize tool paths
        self.nmap_path = Config.MCP_SERVERS.get('nmap', {}).get('binary_path', '/usr/bin/nmap')
        self.nuclei_path = Config.MCP_SERVERS.get('nuclei', {}).get('binary_path', '/usr/local/bin/nuclei')
        
    # ==================== NETWORK SCANNING TOOLS ====================
    
    def nmap_scan(self, target: str, scan_type: str = "basic", ports: str = None) -> Dict[str, Any]:
        """Perform network scanning with Nmap"""
        try:
            scan_profiles = {
                "basic": ["-sS", "-O", "-sV"],
                "stealth": ["-sS", "-T2", "-f"],
                "aggressive": ["-A", "-T4"],
                "vulnerability": ["--script=vuln"],
                "discovery": ["-sn"],
                "port_scan": ["-p-", "--open"],
                "service_scan": ["-sV", "-sC"]
            }
            
            cmd = [self.nmap_path] + scan_profiles.get(scan_type, scan_profiles["basic"])
            
            if ports:
                cmd.extend(["-p", ports])
            
            cmd.append(target)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            return {
                "tool": "nmap",
                "target": target,
                "scan_type": scan_type,
                "command": " ".join(cmd),
                "output": result.stdout,
                "errors": result.stderr,
                "return_code": result.returncode,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"Nmap scan failed: {str(e)}"}
    
    def port_scan(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """Quick port scanning"""
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432, 3306]
        
        open_ports = []
        closed_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                if result == 0:
                    open_ports.append(port)
                else:
                    closed_ports.append(port)
                sock.close()
            except Exception:
                closed_ports.append(port)
        
        return {
            "tool": "port_scanner",
            "host": host,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "total_scanned": len(ports),
            "timestamp": datetime.now().isoformat()
        }
    
    # ==================== VULNERABILITY SCANNING ====================
    
    def nuclei_scan(self, target: str, template_tags: List[str] = None) -> Dict[str, Any]:
        """Vulnerability scanning with Nuclei"""
        try:
            cmd = [self.nuclei_path, "-u", target, "-json"]
            
            if template_tags:
                cmd.extend(["-tags", ",".join(template_tags)])
            else:
                cmd.extend(["-tags", "cve,oast,tech,default-logins"])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            vulnerabilities = []
            if result.stdout:
                for line in result.stdout.strip().split('\n'):
                    try:
                        vuln = json.loads(line)
                        vulnerabilities.append(vuln)
                    except json.JSONDecodeError:
                        continue
            
            return {
                "tool": "nuclei",
                "target": target,
                "vulnerabilities": vulnerabilities,
                "total_found": len(vulnerabilities),
                "command": " ".join(cmd),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"Nuclei scan failed: {str(e)}"}
    
    def ssl_check(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """SSL/TLS certificate analysis"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
            return {
                "tool": "ssl_checker",
                "hostname": hostname,
                "port": port,
                "certificate": {
                    "subject": dict(x[0] for x in cert['subject']),
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "version": cert['version'],
                    "serial_number": cert['serialNumber'],
                    "not_before": cert['notBefore'],
                    "not_after": cert['notAfter'],
                    "san": cert.get('subjectAltName', [])
                },
                "cipher_suite": {
                    "name": cipher[0],
                    "version": cipher[1],
                    "bits": cipher[2]
                },
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"SSL check failed: {str(e)}"}
    
    # ==================== THREAT INTELLIGENCE ====================
    
    def shodan_lookup(self, query: str, query_type: str = "ip") -> Dict[str, Any]:
        """Shodan intelligence gathering"""
        if not self.shodan_api:
            return {"error": "Shodan API key not configured"}
        
        try:
            if query_type == "ip":
                result = self.shodan_api.host(query)
            elif query_type == "search":
                result = self.shodan_api.search(query, limit=10)
            else:
                return {"error": f"Unknown query type: {query_type}"}
            
            return {
                "tool": "shodan",
                "query": query,
                "query_type": query_type,
                "result": result,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"Shodan lookup failed: {str(e)}"}
    
    def domain_analysis(self, domain: str) -> Dict[str, Any]:
        """Comprehensive domain analysis"""
        results = {
            "tool": "domain_analyzer",
            "domain": domain,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # DNS Resolution
            try:
                dns_results = {}
                record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
                for record_type in record_types:
                    try:
                        answers = dns.resolver.resolve(domain, record_type)
                        dns_results[record_type] = [str(rdata) for rdata in answers]
                    except:
                        dns_results[record_type] = []
                results["dns"] = dns_results
            except Exception as e:
                results["dns_error"] = str(e)
            
            # WHOIS Lookup
            try:
                whois_result = whois.whois(domain)
                results["whois"] = {
                    "registrar": whois_result.registrar,
                    "creation_date": str(whois_result.creation_date),
                    "expiration_date": str(whois_result.expiration_date),
                    "name_servers": whois_result.name_servers,
                    "status": whois_result.status
                }
            except Exception as e:
                results["whois_error"] = str(e)
            
            # Subdomain enumeration (basic)
            subdomains = self._enumerate_subdomains(domain)
            results["subdomains"] = subdomains
            
            return results
            
        except Exception as e:
            results["error"] = str(e)
            return results
    
    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Basic subdomain enumeration"""
        common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'app', 'blog', 'shop']
        found_subs = []
        
        for sub in common_subs:
            try:
                subdomain = f"{sub}.{domain}"
                socket.gethostbyname(subdomain)
                found_subs.append(subdomain)
            except:
                continue
        
        return found_subs
    
    # ==================== MALWARE ANALYSIS ====================
    
    def file_hash_analysis(self, file_path: str) -> Dict[str, Any]:
        """Calculate file hashes for malware analysis"""
        try:
            hashes = {}
            
            with open(file_path, 'rb') as f:
                content = f.read()
                
            hashes['md5'] = hashlib.md5(content).hexdigest()
            hashes['sha1'] = hashlib.sha1(content).hexdigest()
            hashes['sha256'] = hashlib.sha256(content).hexdigest()
            
            # File metadata
            stat = os.stat(file_path)
            
            return {
                "tool": "file_analyzer",
                "file_path": file_path,
                "hashes": hashes,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"File analysis failed: {str(e)}"}
    
    def virustotal_lookup(self, hash_value: str) -> Dict[str, Any]:
        """VirusTotal hash lookup (requires API key)"""
        if not Config.VIRUSTOTAL_API_KEY:
            return {"error": "VirusTotal API key not configured"}
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            headers = {"x-apikey": Config.VIRUSTOTAL_API_KEY}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            return {
                "tool": "virustotal",
                "hash": hash_value,
                "result": response.json() if response.status_code == 200 else None,
                "status_code": response.status_code,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"VirusTotal lookup failed: {str(e)}"}
    
    # ==================== NETWORK FORENSICS ====================
    
    def packet_capture(self, interface: str = "eth0", count: int = 100) -> Dict[str, Any]:
        """Network packet capture (requires root/sudo)"""
        try:
            cmd = ["tcpdump", "-i", interface, "-c", str(count), "-w", "/tmp/capture.pcap"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            return {
                "tool": "tcpdump",
                "interface": interface,
                "packet_count": count,
                "capture_file": "/tmp/capture.pcap",
                "output": result.stderr,  # tcpdump outputs to stderr
                "return_code": result.returncode,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"Packet capture failed: {str(e)}"}
    
    def network_connections(self) -> Dict[str, Any]:
        """List active network connections"""
        try:
            cmd = ["netstat", "-tuln"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            connections = []
            for line in result.stdout.split('\n')[2:]:  # Skip headers
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        connections.append({
                            "protocol": parts[0],
                            "local_address": parts[3],
                            "state": parts[5] if len(parts) > 5 else "N/A"
                        })
            
            return {
                "tool": "netstat",
                "connections": connections,
                "total_connections": len(connections),
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"Network connections check failed: {str(e)}"}
    
    # ==================== OSINT TOOLS ====================
    
    def email_analysis(self, email: str) -> Dict[str, Any]:
        """Email address analysis and OSINT"""
        domain = email.split('@')[1] if '@' in email else None
        
        result = {
            "tool": "email_analyzer",
            "email": email,
            "domain": domain,
            "timestamp": datetime.now().isoformat()
        }
        
        if domain:
            # Domain analysis
            result["domain_info"] = self.domain_analysis(domain)
            
            # Check for common patterns
            result["analysis"] = {
                "is_disposable": domain in self._get_disposable_domains(),
                "domain_age": "unknown",  # Would need additional API
                "mx_records": result["domain_info"].get("dns", {}).get("MX", [])
            }
        
        return result
    
    def _get_disposable_domains(self) -> List[str]:
        """List of known disposable email domains"""
        return [
            "10minutemail.com", "guerrillamail.com", "mailinator.com",
            "tempmail.org", "yopmail.com", "throwaway.email"
        ]
    
    def ip_geolocation(self, ip: str) -> Dict[str, Any]:
        """IP geolocation lookup"""
        try:
            # Using ipapi.co for geolocation (free tier)
            response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=10)
            
            return {
                "tool": "ip_geolocation",
                "ip": ip,
                "location": response.json() if response.status_code == 200 else None,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"IP geolocation failed: {str(e)}"}
    
    # ==================== COMPLIANCE TOOLS ====================
    
    def security_headers_check(self, url: str) -> Dict[str, Any]:
        """Check security headers on a website"""
        try:
            response = requests.get(url, timeout=10, allow_redirects=True)
            headers = response.headers
            
            security_headers = {
                "Content-Security-Policy": headers.get("Content-Security-Policy"),
                "X-Frame-Options": headers.get("X-Frame-Options"),
                "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
                "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
                "X-XSS-Protection": headers.get("X-XSS-Protection"),
                "Referrer-Policy": headers.get("Referrer-Policy"),
                "Permissions-Policy": headers.get("Permissions-Policy")
            }
            
            # Security assessment
            score = 0
            recommendations = []
            
            for header, value in security_headers.items():
                if value:
                    score += 1
                else:
                    recommendations.append(f"Missing {header}")
            
            return {
                "tool": "security_headers",
                "url": url,
                "headers": security_headers,
                "score": f"{score}/7",
                "recommendations": recommendations,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {"error": f"Security headers check failed: {str(e)}"}
    
    # ==================== PENETRATION TESTING ====================
    
    def web_directory_scan(self, url: str, wordlist: List[str] = None) -> Dict[str, Any]:
        """Web directory and file discovery"""
        if not wordlist:
            wordlist = [
                "admin", "login", "dashboard", "config", "backup",
                "test", "dev", "api", "docs", "robots.txt", ".git",
                "wp-admin", "phpmyadmin", "cpanel"
            ]
        
        found_paths = []
        
        for path in wordlist:
            try:
                test_url = f"{url.rstrip('/')}/{path}"
                response = requests.get(test_url, timeout=5, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    found_paths.append({
                        "path": path,
                        "url": test_url,
                        "status_code": response.status_code,
                        "size": len(response.content)
                    })
                    
            except:
                continue
        
        return {
            "tool": "directory_scanner",
            "target_url": url,
            "found_paths": found_paths,
            "total_found": len(found_paths),
            "timestamp": datetime.now().isoformat()
        }
    
    def sql_injection_test(self, url: str, parameters: Dict[str, str] = None) -> Dict[str, Any]:
        """Basic SQL injection testing"""
        if not parameters:
            return {"error": "No parameters provided for testing"}
        
        sql_payloads = [
            "'", "''", "`", "``", ",", '"', '""', "/", "//", "\\", "\\\\",
            "1'", "1''", "1`", "1``", "1,", '1"', '1""', "1/", "1//", "1\\", "1\\\\",
            "'OR'1'='1", "'OR'1'='1'--", "'OR'1'='1'/*", "1'OR'1'='1",
            "admin'--", "admin'/*", "' UNION SELECT NULL--"
        ]
        
        vulnerabilities = []
        
        for param, value in parameters.items():
            for payload in sql_payloads[:5]:  # Limit to avoid overwhelming
                try:
                    test_params = parameters.copy()
                    test_params[param] = payload
                    
                    response = requests.get(url, params=test_params, timeout=10)
                    
                    # Look for SQL error indicators
                    error_indicators = [
                        "sql syntax", "mysql_fetch", "postgresql", "oracle",
                        "sqlite", "sql server", "syntax error", "quoted string"
                    ]
                    
                    for indicator in error_indicators:
                        if indicator.lower() in response.text.lower():
                            vulnerabilities.append({
                                "parameter": param,
                                "payload": payload,
                                "indicator": indicator,
                                "response_length": len(response.text)
                            })
                            break
                            
                except:
                    continue
        
        return {
            "tool": "sqli_tester",
            "url": url,
            "parameters_tested": list(parameters.keys()),
            "vulnerabilities": vulnerabilities,
            "risk_level": "High" if vulnerabilities else "Low",
            "timestamp": datetime.now().isoformat()
        }

# ==================== COMMAND EXECUTION HELPERS ====================

class CommandExecutor:
    """Safe command execution for cybersecurity tools"""
    
    @staticmethod
    def execute_command(command: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Execute system command safely"""
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            
            return {
                "command": " ".join(command),
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "success": result.returncode == 0,
                "timestamp": datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {
                "command": " ".join(command),
                "error": "Command timed out",
                "timeout": timeout,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "command": " ".join(command),
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

# Global tools instance
cybersec_tools = CybersecurityTools()