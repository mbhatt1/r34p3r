"""
Security Scanning Tools

Integrated battle-tested scanning tools from VibePenTester and Rogue frameworks.
Provides comprehensive vulnerability scanning capabilities.

Based on proven implementations from open-source security testing frameworks.
"""

import asyncio
import aiohttp
import socket
import ssl
import subprocess
import json
import re
import time
import random
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime

class SecurityScanner:
    """Battle-tested security scanning tools"""
    
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

    async def scan_headers(self, target_url: str, check_hsts: bool = True, check_csp: bool = True, check_xframe: bool = True) -> Dict[str, Any]:
        """Analyze HTTP headers for security issues"""
        try:
            async with self.session.get(target_url) as response:
                headers = dict(response.headers)
                
                security_headers = {
                    "X-Frame-Options": headers.get("X-Frame-Options"),
                    "X-XSS-Protection": headers.get("X-XSS-Protection"),
                    "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
                    "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
                    "Content-Security-Policy": headers.get("Content-Security-Policy"),
                    "X-Permitted-Cross-Domain-Policies": headers.get("X-Permitted-Cross-Domain-Policies"),
                    "Referrer-Policy": headers.get("Referrer-Policy"),
                    "Feature-Policy": headers.get("Feature-Policy"),
                    "Permissions-Policy": headers.get("Permissions-Policy")
                }
                
                missing_headers = []
                if check_hsts and not security_headers.get("Strict-Transport-Security"):
                    missing_headers.append("Strict-Transport-Security")
                if check_csp and not security_headers.get("Content-Security-Policy"):
                    missing_headers.append("Content-Security-Policy")
                if check_xframe and not security_headers.get("X-Frame-Options"):
                    missing_headers.append("X-Frame-Options")
                
                has_issues = len(missing_headers) > 0
                
                return {
                    "security_issue_found": has_issues,
                    "issue_type": "Missing Security Headers" if has_issues else None,
                    "target_url": target_url,
                    "missing_headers": missing_headers,
                    "security_headers": security_headers,
                    "severity": "medium" if has_issues else "info",
                    "description": f"Missing security headers: {', '.join(missing_headers)}" if has_issues else "All security headers present",
                    "timestamp": datetime.now().isoformat()
                }
        except Exception as e:
            return {
                "security_issue_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

    async def scan_ssl_tls(self, target_host: str, target_port: int = 443) -> Dict[str, Any]:
        """Analyze SSL/TLS configuration for security issues"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target_host, target_port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    protocol = ssock.version()
                    
                    issues = []
                    
                    # Check protocol version
                    if protocol in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        issues.append(f"Insecure protocol: {protocol}")
                    
                    # Check cipher strength
                    if cipher and len(cipher) >= 3:
                        cipher_name = cipher[0]
                        if any(weak in cipher_name.upper() for weak in ['RC4', 'DES', 'MD5', 'NULL']):
                            issues.append(f"Weak cipher: {cipher_name}")
                    
                    # Check certificate
                    if cert:
                        # Check expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.now():
                            issues.append("Certificate expired")
                        
                        # Check self-signed
                        if cert.get('issuer') == cert.get('subject'):
                            issues.append("Self-signed certificate")
                    
                    has_issues = len(issues) > 0
                    
                    return {
                        "security_issue_found": has_issues,
                        "issue_type": "SSL/TLS Configuration Issues" if has_issues else None,
                        "target_host": target_host,
                        "target_port": target_port,
                        "protocol": protocol,
                        "cipher": cipher,
                        "issues": issues,
                        "severity": "high" if has_issues else "info",
                        "timestamp": datetime.now().isoformat()
                    }
        except Exception as e:
            return {
                "security_issue_found": False,
                "error": str(e),
                "target_host": target_host,
                "target_port": target_port,
                "timestamp": datetime.now().isoformat()
            }

    async def brute_force_directories(self, base_url: str, wordlist: List[str] = None, extensions: List[str] = None) -> Dict[str, Any]:
        """Brute force directories and files using wordlists"""
        if not wordlist:
            wordlist = [
                "admin", "administrator", "login", "wp-admin", "phpmyadmin",
                "backup", "config", "test", "dev", "staging", "api", "v1", "v2",
                "uploads", "images", "files", "documents", "tmp", "temp",
                "dashboard", "panel", "control", "manage", "system"
            ]
        
        if not extensions:
            extensions = ["", ".php", ".html", ".js", ".txt", ".xml", ".json", ".bak", ".old"]
        
        discovered_urls = []
        
        for directory in wordlist:
            for ext in extensions:
                path = f"{directory}{ext}"
                full_url = urljoin(base_url, path)
                
                try:
                    async with self.session.get(full_url, allow_redirects=False) as response:
                        if response.status in [200, 301, 302, 403]:
                            discovered_urls.append({
                                "url": full_url,
                                "status": response.status,
                                "size": len(await response.text()) if response.status == 200 else 0
                            })
                except:
                    continue
        
        return {
            "urls": discovered_urls,
            "base_url": base_url,
            "discovered_count": len(discovered_urls),
            "timestamp": datetime.now().isoformat()
        }

    async def crawl_website(self, url: str, max_depth: int = 2, max_pages: int = 20) -> Dict[str, Any]:
        """Crawl website to discover links and content"""
        discovered_urls = set([url])
        to_crawl = [url]
        crawled = set()
        depth = 0
        
        while to_crawl and depth < max_depth and len(crawled) < max_pages:
            current_batch = to_crawl.copy()
            to_crawl.clear()
            
            for current_url in current_batch:
                if current_url in crawled:
                    continue
                
                try:
                    async with self.session.get(current_url) as response:
                        if response.status == 200:
                            content = await response.text()
                            crawled.add(current_url)
                            
                            # Extract links using regex
                            link_pattern = r'href=[\'"]([^\'"]*)[\'"]'
                            links = re.findall(link_pattern, content, re.IGNORECASE)
                            
                            for link in links:
                                if link.startswith('http'):
                                    full_url = link
                                elif link.startswith('/'):
                                    full_url = urljoin(url, link)
                                else:
                                    full_url = urljoin(current_url, link)
                                
                                # Only add internal links
                                if urlparse(full_url).netloc == urlparse(url).netloc:
                                    if full_url not in discovered_urls:
                                        discovered_urls.add(full_url)
                                        to_crawl.append(full_url)
                except:
                    continue
            
            depth += 1
        
        return {
            "urls": list(discovered_urls),
            "crawled_count": len(crawled),
            "max_depth": max_depth,
            "max_pages": max_pages,
            "base_url": url,
            "timestamp": datetime.now().isoformat()
        }

    async def analyze_page_content(self, target_url: str) -> Dict[str, Any]:
        """Analyze page content for security issues"""
        try:
            async with self.session.get(target_url) as response:
                content = await response.text()
                
                issues = []
                
                # Check for sensitive information in comments
                comment_pattern = r'<!--(.*?)-->'
                comments = re.findall(comment_pattern, content, re.DOTALL | re.IGNORECASE)
                
                sensitive_patterns = [
                    r'password', r'secret', r'key', r'token', r'api[_-]?key',
                    r'database', r'db[_-]?pass', r'admin', r'root', r'TODO',
                    r'FIXME', r'DEBUG', r'username', r'email'
                ]
                
                for comment in comments:
                    for pattern in sensitive_patterns:
                        if re.search(pattern, comment, re.IGNORECASE):
                            issues.append(f"Sensitive information in comment: {comment.strip()[:100]}...")
                            break
                
                # Check for inline JavaScript with sensitive data
                js_pattern = r'<script[^>]*>(.*?)</script>'
                scripts = re.findall(js_pattern, content, re.DOTALL | re.IGNORECASE)
                
                for script in scripts:
                    for pattern in sensitive_patterns:
                        if re.search(pattern, script, re.IGNORECASE):
                            issues.append(f"Sensitive information in JavaScript: {script.strip()[:100]}...")
                            break
                
                # Check for forms without CSRF protection
                form_pattern = r'<form[^>]*>(.*?)</form>'
                forms = re.findall(form_pattern, content, re.DOTALL | re.IGNORECASE)
                
                for form in forms:
                    if not re.search(r'csrf|token|_token', form, re.IGNORECASE):
                        issues.append("Form without apparent CSRF protection")
                
                has_issues = len(issues) > 0
                
                return {
                    "security_issue_found": has_issues,
                    "issue_type": "Page Content Security Issues" if has_issues else None,
                    "target_url": target_url,
                    "issues": issues,
                    "severity": "medium" if has_issues else "info",
                    "timestamp": datetime.now().isoformat()
                }
        except Exception as e:
            return {
                "security_issue_found": False,
                "error": str(e),
                "target_url": target_url,
                "timestamp": datetime.now().isoformat()
            }

    async def enumerate_subdomains(self, domain: str, wordlist: List[str] = None) -> Dict[str, Any]:
        """Enumerate subdomains using DNS resolution"""
        if not wordlist:
            wordlist = [
                "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
                "app", "blog", "shop", "store", "support", "help", "docs",
                "portal", "secure", "vpn", "remote", "cdn", "static", "assets"
            ]
        
        discovered_subdomains = []
        
        for subdomain in wordlist:
            full_domain = f"{subdomain}.{domain}"
            try:
                # Try to resolve the subdomain
                socket.gethostbyname(full_domain)
                discovered_subdomains.append(full_domain)
            except socket.gaierror:
                continue
        
        return {
            "subdomains": discovered_subdomains,
            "domain": domain,
            "discovered_count": len(discovered_subdomains),
            "timestamp": datetime.now().isoformat()
        }

    async def port_scan(self, host: str, ports: List[int] = None) -> Dict[str, Any]:
        """Scan ports on target host"""
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3306, 3389, 5432, 5900]
        
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    # Try to get service banner
                    banner = await self._get_banner(host, port)
                    open_ports.append({
                        "port": port,
                        "service": self._identify_service(port),
                        "banner": banner
                    })
            except:
                continue
        
        return {
            "host": host,
            "open_ports": open_ports,
            "scanned_ports": len(ports),
            "timestamp": datetime.now().isoformat()
        }

    async def _get_banner(self, host: str, port: int) -> str:
        """Get service banner from port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=3
            )
            
            # Send HTTP request for web services
            if port in [80, 443, 8080, 8443]:
                writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
                await writer.drain()
            
            # Read response
            data = await asyncio.wait_for(reader.read(1024), timeout=2)
            writer.close()
            await writer.wait_closed()
            
            return data.decode('utf-8', errors='ignore').strip()
        except:
            return None

    def _identify_service(self, port: int) -> str:
        """Identify service by port number"""
        port_services = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
            443: "HTTPS", 993: "IMAPS", 995: "POP3S", 3306: "MySQL",
            3389: "RDP", 5432: "PostgreSQL", 5900: "VNC"
        }
        return port_services.get(port, "Unknown")

# Utility functions for compatibility with existing agents
async def scan_headers(target_url: str, **kwargs) -> Dict[str, Any]:
    """Wrapper function for header scanning"""
    async with SecurityScanner() as scanner:
        return await scanner.scan_headers(target_url, **kwargs)

async def scan_ssl_tls(target_host: str, target_port: int = 443) -> Dict[str, Any]:
    """Wrapper function for SSL/TLS scanning"""
    async with SecurityScanner() as scanner:
        return await scanner.scan_ssl_tls(target_host, target_port)

async def brute_force_directories(base_url: str, **kwargs) -> Dict[str, Any]:
    """Wrapper function for directory brute forcing"""
    async with SecurityScanner() as scanner:
        return await scanner.brute_force_directories(base_url, **kwargs)

async def crawl_website(url: str, **kwargs) -> Dict[str, Any]:
    """Wrapper function for website crawling"""
    async with SecurityScanner() as scanner:
        return await scanner.crawl_website(url, **kwargs)

async def analyze_page_content(target_url: str) -> Dict[str, Any]:
    """Wrapper function for page content analysis"""
    async with SecurityScanner() as scanner:
        return await scanner.analyze_page_content(target_url)

async def enumerate_subdomains(domain: str, **kwargs) -> Dict[str, Any]:
    """Wrapper function for subdomain enumeration"""
    async with SecurityScanner() as scanner:
        return await scanner.enumerate_subdomains(domain, **kwargs)

async def port_scan(host: str, **kwargs) -> Dict[str, Any]:
    """Wrapper function for port scanning"""
    async with SecurityScanner() as scanner:
        return await scanner.port_scan(host, **kwargs)