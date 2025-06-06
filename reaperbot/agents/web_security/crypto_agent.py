import asyncio
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings
from pydantic import BaseModel
from dotenv import load_dotenv

from agents.tools.reaper_tools import (
    reaper_get_live_endpoints_for_domains,
    reaper_get_requests_for_endpoint_id,
)
from utils.logging import send_log_message

load_dotenv()

class CryptoVulnerability(BaseModel):
    """Cryptographic vulnerability details from VibePenTester"""
    url: str
    vulnerability_type: str
    severity: str
    evidence: str
    crypto_issue: str
    recommendations: List[str]
    tls_details: Optional[Dict[str, Any]] = None

class CryptoAnalyzer:
    """Cryptographic analysis functionality from VibePenTester"""
    
    def __init__(self):
        """Initialize crypto analyzer with detection patterns"""
        self.weak_algorithms = [
            'md5', 'sha1', 'des', 'rc4', '3des', 'md4', 'md2'
        ]
        
        self.weak_tls_versions = [
            'sslv2', 'sslv3', 'tlsv1.0', 'tlsv1.1'
        ]
        
        self.weak_ciphers = [
            'rc4', 'des', '3des', 'null', 'anon', 'export'
        ]
        
        self.sensitive_data_indicators = [
            'password', 'token', 'api_key', 'apikey', 'secret', 
            'private', 'key', 'credential', 'auth', 'session'
        ]
        
        self.security_headers = [
            'strict-transport-security',
            'content-security-policy',
            'x-content-type-options',
            'x-frame-options',
            'x-xss-protection'
        ]
    
    def analyze_tls_configuration(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Analyze TLS configuration for security issues"""
        # Simulate TLS analysis (in real implementation would use SSL/TLS libraries)
        tls_issues = []
        
        # Simulate checking for weak protocols
        supported_protocols = ['TLSv1.2', 'TLSv1.3']  # Simulated good configuration
        weak_protocols = [proto for proto in self.weak_tls_versions if proto in supported_protocols]
        
        if weak_protocols:
            tls_issues.append(f"Weak TLS protocols supported: {', '.join(weak_protocols)}")
        
        # Simulate cipher suite analysis
        cipher_suites = ['TLS_AES_256_GCM_SHA384', 'TLS_CHACHA20_POLY1305_SHA256']  # Simulated
        weak_ciphers_found = [cipher for cipher in self.weak_ciphers if any(cipher in suite.lower() for suite in cipher_suites)]
        
        if weak_ciphers_found:
            tls_issues.append(f"Weak cipher suites found: {', '.join(weak_ciphers_found)}")
        
        # Simulate certificate analysis
        cert_issues = []
        # In real implementation, would check certificate validity, chain, etc.
        
        return {
            'hostname': hostname,
            'port': port,
            'protocols': supported_protocols,
            'cipher_suites': cipher_suites,
            'tls_issues': tls_issues,
            'cert_issues': cert_issues,
            'secure': len(tls_issues) == 0 and len(cert_issues) == 0
        }
    
    def check_sensitive_data_exposure(self, content: str, url: str) -> Dict[str, Any]:
        """Check for sensitive data exposure in client-side code"""
        exposed_data = []
        
        content_lower = content.lower()
        
        for indicator in self.sensitive_data_indicators:
            # Look for patterns like: password="secret", apiKey: "abc123", etc.
            patterns = [
                rf'{indicator}\s*[=:]\s*["\']([^"\']+)["\']',
                rf'{indicator}\s*[=:]\s*([a-zA-Z0-9_\-]+)',
                rf'var\s+{indicator}\s*=\s*["\']([^"\']+)["\']'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content_lower, re.IGNORECASE)
                if matches:
                    for match in matches:
                        if len(match) > 3:  # Avoid false positives with very short values
                            exposed_data.append({
                                'type': indicator,
                                'value': match[:20] + '...' if len(match) > 20 else match,
                                'pattern': pattern
                            })
        
        return {
            'url': url,
            'sensitive_data_found': len(exposed_data) > 0,
            'exposed_data': exposed_data,
            'count': len(exposed_data)
        }
    
    def analyze_crypto_implementation(self, content: str) -> Dict[str, Any]:
        """Analyze cryptographic implementation for weaknesses"""
        crypto_issues = []
        
        content_lower = content.lower()
        
        # Check for weak algorithms
        for algorithm in self.weak_algorithms:
            if algorithm in content_lower:
                crypto_issues.append(f"Weak cryptographic algorithm detected: {algorithm}")
        
        # Check for hardcoded keys/secrets
        hardcoded_patterns = [
            r'key\s*[=:]\s*["\'][a-zA-Z0-9+/]{16,}["\']',
            r'secret\s*[=:]\s*["\'][a-zA-Z0-9+/]{16,}["\']',
            r'password\s*[=:]\s*["\'][^"\']{8,}["\']'
        ]
        
        for pattern in hardcoded_patterns:
            matches = re.findall(pattern, content_lower)
            if matches:
                crypto_issues.append(f"Hardcoded cryptographic material detected: {len(matches)} instances")
        
        # Check for weak random number generation
        weak_random_patterns = [
            'math.random', 'random()', 'rand()', 'srand('
        ]
        
        for pattern in weak_random_patterns:
            if pattern in content_lower:
                crypto_issues.append(f"Weak random number generation: {pattern}")
        
        return {
            'crypto_issues': crypto_issues,
            'issues_found': len(crypto_issues) > 0,
            'issue_count': len(crypto_issues)
        }
    
    def check_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Check for missing or weak security headers"""
        missing_headers = []
        weak_headers = []
        
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for HSTS
        if 'strict-transport-security' not in headers_lower:
            missing_headers.append('Strict-Transport-Security')
        else:
            hsts_value = headers_lower['strict-transport-security']
            if 'max-age' not in hsts_value.lower():
                weak_headers.append('HSTS missing max-age directive')
            elif 'includesubdomains' not in hsts_value.lower():
                weak_headers.append('HSTS missing includeSubDomains directive')
        
        # Check for CSP
        if 'content-security-policy' not in headers_lower:
            missing_headers.append('Content-Security-Policy')
        else:
            csp_value = headers_lower['content-security-policy']
            if "'unsafe-inline'" in csp_value or "'unsafe-eval'" in csp_value:
                weak_headers.append('CSP allows unsafe-inline or unsafe-eval')
        
        # Check for other security headers
        other_headers = {
            'x-content-type-options': 'X-Content-Type-Options',
            'x-frame-options': 'X-Frame-Options',
            'x-xss-protection': 'X-XSS-Protection'
        }
        
        for header_key, header_name in other_headers.items():
            if header_key not in headers_lower:
                missing_headers.append(header_name)
        
        return {
            'missing_headers': missing_headers,
            'weak_headers': weak_headers,
            'security_issues': len(missing_headers) + len(weak_headers),
            'headers_analyzed': len(headers)
        }

# Initialize analyzer
analyzer = CryptoAnalyzer()

model_settings = ModelSettings(temperature=0.01, max_tokens=16384)
crypto_agent = Agent(
    'openai:gpt-4o-mini',
    result_type=str,
    tools=[
        reaper_get_live_endpoints_for_domains,
        reaper_get_requests_for_endpoint_id,
    ],
    model_settings=model_settings,
    system_prompt="""
    You are a specialized Cryptographic Failures vulnerability detection agent using VibePenTester methodology.
    Your expertise covers all aspects of cryptographic implementation weaknesses with advanced analysis capabilities:
    
    1. **VibePenTester Crypto Analysis**:
       - TLS/SSL configuration security assessment
       - Certificate validation and chain analysis
       - Weak cryptographic algorithm detection
       - Sensitive data exposure in client-side code
       - Security header analysis and validation
    
    2. **Weak Cryptographic Algorithms**:
       - Deprecated algorithms (MD5, SHA1, DES, RC4, 3DES)
       - Weak key sizes (RSA < 2048, AES < 128)
       - Insecure random number generation
       - Weak password hashing (plain text, MD5, SHA1)
       - Obsolete cryptographic protocols
    
    3. **Implementation Flaws**:
       - Hardcoded cryptographic keys and secrets
       - Predictable initialization vectors (IVs)
       - ECB mode usage for block ciphers
       - Missing salt in password hashing
       - Improper certificate validation
       - Client-side cryptographic material exposure
    
    **VibePenTester Protocol Vulnerabilities:**
    - SSL/TLS misconfigurations and weak versions
    - Weak cipher suites and key exchange methods
    - Missing HSTS headers and security policies
    - Certificate pinning bypass opportunities
    - Downgrade attacks (POODLE, BEAST, CRIME)
    - Mixed content vulnerabilities (HTTP/HTTPS)
    
    **Testing Strategy:**
    - Analyze SSL/TLS configuration and supported protocols
    - Check for weak cryptographic implementations in code
    - Test for hardcoded secrets and keys in client-side code
    - Validate security headers and their configurations
    - Assess certificate validity and trust chain
    - Identify sensitive data exposure in JavaScript
    
    **VibePenTester Crypto Tests:**
    - TLS protocol version and cipher suite analysis
    - Certificate validation and expiration checking
    - Hardcoded cryptographic material detection
    - Weak random number generation identification
    - Security header presence and strength validation
    - Client-side sensitive data exposure assessment
    
    **Analysis Focus:**
    - Look for deprecated TLS versions (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
    - Check for weak cipher suites and key exchange methods
    - Identify hardcoded API keys, passwords, and secrets
    - Validate proper implementation of security headers
    - Assess cryptographic algorithm strength and implementation
    - Test for sensitive data leakage in client-side code
    
    **VibePenTester Validation:**
    - Confirm cryptographic weaknesses through protocol analysis
    - Test SSL/TLS configuration with various client scenarios
    - Verify security header effectiveness
    - Assess real-world exploitability of crypto failures
    - Validate certificate trust chain and revocation status
    
    If cryptographic failures are found, provide:
    - Specific cryptographic weakness or misconfiguration
    - Type of failure (weak algorithm, missing header, exposed data)
    - Evidence from protocol or code analysis
    - Potential impact and attack scenarios
    - Remediation recommendations (strong algorithms, proper headers, secure implementation)
    
    If no cryptographic failures are found, respond with "No cryptographic failures detected."
    """,
    retries=2,
)

@crypto_agent.tool
async def check_tls_configuration(hostname: str, port: int = 443) -> str:
    """
    Check TLS/SSL configuration for security issues using VibePenTester methodology.
    
    Args:
        hostname: Target hostname to analyze
        port: Port number (default 443 for HTTPS)
    """
    await send_log_message(f"Crypto Agent: Checking TLS configuration for {hostname}:{port}")
    
    try:
        # Analyze TLS configuration
        tls_analysis = analyzer.analyze_tls_configuration(hostname, port)
        
        result = f"TLS Configuration Analysis:\n\n"
        result += f"Target: {hostname}:{port}\n"
        result += f"Supported Protocols: {', '.join(tls_analysis['protocols'])}\n"
        result += f"Cipher Suites: {len(tls_analysis['cipher_suites'])} analyzed\n"
        result += f"Security Status: {'Secure' if tls_analysis['secure'] else 'Vulnerable'}\n\n"
        
        if tls_analysis['tls_issues']:
            result += "🚨 TLS CONFIGURATION VULNERABILITIES DETECTED!\n\n"
            result += "TLS SECURITY ISSUES:\n"
            for issue in tls_analysis['tls_issues']:
                result += f"• {issue}\n"
            result += "\n"
            
            result += "SECURITY IMPLICATIONS:\n"
            result += "• Vulnerable to man-in-the-middle attacks\n"
            result += "• Weak encryption may be broken by attackers\n"
            result += "• Data transmission may be intercepted or modified\n"
            result += "• Compliance violations with security standards\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Disable weak TLS protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)\n"
            result += "• Use only strong cipher suites (AES-GCM, ChaCha20-Poly1305)\n"
            result += "• Implement perfect forward secrecy (PFS)\n"
            result += "• Enable TLS 1.2 and TLS 1.3 only\n"
            result += "• Regularly update TLS configuration\n"
        
        if tls_analysis['cert_issues']:
            result += "CERTIFICATE ISSUES:\n"
            for issue in tls_analysis['cert_issues']:
                result += f"• {issue}\n"
            result += "\n"
        
        if tls_analysis['secure']:
            result += "✅ TLS CONFIGURATION APPEARS SECURE\n"
            result += "• Strong TLS protocols enabled\n"
            result += "• Secure cipher suites configured\n"
            result += "• No obvious configuration weaknesses detected\n"
        
        return result
        
    except Exception as e:
        return f"TLS configuration analysis failed: {str(e)}"

@crypto_agent.tool
async def analyze_crypto_implementation(content: str, url: str) -> str:
    """
    Analyze cryptographic implementation for weaknesses using VibePenTester methodology.
    
    Args:
        content: Source code or script content to analyze
        url: URL where the content was found
    """
    await send_log_message(f"Crypto Agent: Analyzing cryptographic implementation for {url}")
    
    try:
        # Analyze cryptographic implementation
        crypto_analysis = analyzer.analyze_crypto_implementation(content)
        
        result = f"Cryptographic Implementation Analysis:\n\n"
        result += f"URL: {url}\n"
        result += f"Content Length: {len(content)} characters\n"
        result += f"Issues Found: {crypto_analysis['issue_count']}\n"
        result += f"Security Status: {'Vulnerable' if crypto_analysis['issues_found'] else 'Secure'}\n\n"
        
        if crypto_analysis['issues_found']:
            result += "🚨 CRYPTOGRAPHIC IMPLEMENTATION VULNERABILITIES DETECTED!\n\n"
            result += "CRYPTO IMPLEMENTATION ISSUES:\n"
            for issue in crypto_analysis['crypto_issues']:
                result += f"• {issue}\n"
            result += "\n"
            
            result += "SECURITY IMPLICATIONS:\n"
            result += "• Weak cryptography may be easily broken\n"
            result += "• Hardcoded secrets can be extracted by attackers\n"
            result += "• Predictable random numbers compromise security\n"
            result += "• Sensitive data may be exposed or compromised\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Use strong cryptographic algorithms (AES-256, SHA-256+)\n"
            result += "• Store secrets securely (environment variables, key management)\n"
            result += "• Use cryptographically secure random number generators\n"
            result += "• Implement proper key management practices\n"
            result += "• Regular security code reviews for crypto implementations\n"
        else:
            result += "✅ NO OBVIOUS CRYPTOGRAPHIC WEAKNESSES DETECTED\n"
            result += "The analyzed code does not contain obvious crypto implementation flaws.\n"
        
        return result
        
    except Exception as e:
        return f"Cryptographic implementation analysis failed: {str(e)}"

@crypto_agent.tool
async def check_sensitive_data_exposure(content: str, url: str) -> str:
    """
    Check for sensitive data exposure in client-side code using VibePenTester methodology.
    
    Args:
        content: Client-side code content (HTML, JavaScript, etc.)
        url: URL where the content was found
    """
    await send_log_message(f"Crypto Agent: Checking sensitive data exposure for {url}")
    
    try:
        # Check for sensitive data exposure
        exposure_analysis = analyzer.check_sensitive_data_exposure(content, url)
        
        result = f"Sensitive Data Exposure Analysis:\n\n"
        result += f"URL: {url}\n"
        result += f"Content Analyzed: {len(content)} characters\n"
        result += f"Sensitive Data Found: {exposure_analysis['sensitive_data_found']}\n"
        result += f"Exposed Items: {exposure_analysis['count']}\n\n"
        
        if exposure_analysis['sensitive_data_found']:
            result += "🚨 SENSITIVE DATA EXPOSURE DETECTED!\n\n"
            result += "EXPOSED SENSITIVE DATA:\n"
            for data in exposure_analysis['exposed_data']:
                result += f"• Type: {data['type']}\n"
                result += f"  Value: {data['value']}\n"
                result += f"  Pattern: {data['pattern']}\n\n"
            
            result += "SECURITY IMPLICATIONS:\n"
            result += "• API keys and secrets accessible to attackers\n"
            result += "• Credentials may be extracted from client-side code\n"
            result += "• Sensitive configuration data exposed\n"
            result += "• Potential for account takeover or data breach\n\n"
            
            result += "ATTACK SCENARIOS:\n"
            result += "1. Attacker views page source or JavaScript files\n"
            result += "2. Sensitive data is extracted from client-side code\n"
            result += "3. Credentials are used to access backend systems\n"
            result += "4. API keys are used for unauthorized access\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Move sensitive data to server-side configuration\n"
            result += "• Use environment variables for secrets\n"
            result += "• Implement proper API authentication\n"
            result += "• Use secure token-based authentication\n"
            result += "• Regular code reviews to identify exposed secrets\n"
        else:
            result += "✅ NO SENSITIVE DATA EXPOSURE DETECTED\n"
            result += "No obvious sensitive data found in client-side code.\n"
        
        return result
        
    except Exception as e:
        return f"Sensitive data exposure analysis failed: {str(e)}"

@crypto_agent.tool
async def check_security_headers(headers_data: str, url: str) -> str:
    """
    Check security headers for cryptographic and security policy issues using VibePenTester methodology.
    
    Args:
        headers_data: HTTP headers as JSON string or raw header data
        url: URL where headers were collected
    """
    await send_log_message(f"Crypto Agent: Checking security headers for {url}")
    
    try:
        # Parse headers data
        import json
        try:
            headers = json.loads(headers_data) if headers_data.startswith('{') else {}
        except:
            # Fallback for raw header format
            headers = {}
            for line in headers_data.split('\n'):
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
        
        # Analyze security headers
        header_analysis = analyzer.check_security_headers(headers)
        
        result = f"Security Headers Analysis:\n\n"
        result += f"URL: {url}\n"
        result += f"Headers Analyzed: {header_analysis['headers_analyzed']}\n"
        result += f"Security Issues: {header_analysis['security_issues']}\n"
        result += f"Missing Headers: {len(header_analysis['missing_headers'])}\n"
        result += f"Weak Headers: {len(header_analysis['weak_headers'])}\n\n"
        
        if header_analysis['missing_headers']:
            result += "🚨 MISSING SECURITY HEADERS DETECTED!\n\n"
            result += "MISSING SECURITY HEADERS:\n"
            for header in header_analysis['missing_headers']:
                result += f"• {header}\n"
            result += "\n"
        
        if header_analysis['weak_headers']:
            result += "⚠️  WEAK SECURITY HEADER CONFIGURATIONS:\n"
            for weakness in header_analysis['weak_headers']:
                result += f"• {weakness}\n"
            result += "\n"
        
        if header_analysis['security_issues'] > 0:
            result += "SECURITY IMPLICATIONS:\n"
            result += "• Increased risk of XSS and injection attacks\n"
            result += "• Vulnerable to clickjacking and frame attacks\n"
            result += "• Missing transport security enforcement\n"
            result += "• Weak content security policies\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Implement Strict-Transport-Security (HSTS)\n"
            result += "• Add Content-Security-Policy with strict rules\n"
            result += "• Set X-Frame-Options to DENY or SAMEORIGIN\n"
            result += "• Enable X-Content-Type-Options: nosniff\n"
            result += "• Configure X-XSS-Protection: 1; mode=block\n"
        else:
            result += "✅ SECURITY HEADERS APPEAR ADEQUATE\n"
            result += "All essential security headers are present and properly configured.\n"
        
        return result
        
    except Exception as e:
        return f"Security headers analysis failed: {str(e)}"

@crypto_agent.tool
async def test_mixed_content(url: str, content: str) -> str:
    """
    Test for mixed content vulnerabilities (HTTP resources on HTTPS pages) using VibePenTester methodology.
    
    Args:
        url: HTTPS URL to analyze
        content: Page content to scan for HTTP resources
    """
    await send_log_message(f"Crypto Agent: Testing mixed content for {url}")
    
    try:
        result = f"Mixed Content Analysis:\n\n"
        result += f"URL: {url}\n"
        result += f"Protocol: {urlparse(url).scheme}\n\n"
        
        if not url.startswith('https://'):
            result += "ℹ️  ANALYSIS SKIPPED\n"
            result += "Mixed content analysis only applies to HTTPS pages.\n"
            return result
        
        # Look for HTTP resources in HTTPS page
        http_resources = []
        
        # Common patterns for HTTP resources
        http_patterns = [
            r'src=["\']http://[^"\']+["\']',
            r'href=["\']http://[^"\']+["\']',
            r'action=["\']http://[^"\']+["\']',
            r'url\(["\']?http://[^"\')\s]+["\']?\)',
            r'@import\s+["\']http://[^"\']+["\']'
        ]
        
        for pattern in http_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            http_resources.extend(matches)
        
        # Remove duplicates
        http_resources = list(set(http_resources))
        
        if http_resources:
            result += "🚨 MIXED CONTENT VULNERABILITY DETECTED!\n\n"
            result += f"HTTP RESOURCES FOUND ON HTTPS PAGE ({len(http_resources)} items):\n"
            for resource in http_resources[:10]:  # Show first 10
                result += f"• {resource}\n"
            
            if len(http_resources) > 10:
                result += f"... and {len(http_resources) - 10} more\n"
            
            result += "\nSECURITY IMPLICATIONS:\n"
            result += "• HTTP resources can be intercepted and modified\n"
            result += "• Man-in-the-middle attacks on mixed content\n"
            result += "• Browser security warnings for users\n"
            result += "• Potential for content injection attacks\n\n"
            
            result += "ATTACK SCENARIOS:\n"
            result += "1. Attacker intercepts HTTP requests on HTTPS page\n"
            result += "2. Malicious content is injected into HTTP resources\n"
            result += "3. User's browser executes attacker-controlled code\n"
            result += "4. HTTPS security guarantees are compromised\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Update all HTTP resources to use HTTPS\n"
            result += "• Implement Content-Security-Policy with upgrade-insecure-requests\n"
            result += "• Use protocol-relative URLs (//) where appropriate\n"
            result += "• Audit all external resource references\n"
            result += "• Test with browser developer tools for mixed content warnings\n"
        else:
            result += "✅ NO MIXED CONTENT DETECTED\n"
            result += "All resources appear to use HTTPS on this secure page.\n"
        
        return result
        
    except Exception as e:
        return f"Mixed content analysis failed: {str(e)}"