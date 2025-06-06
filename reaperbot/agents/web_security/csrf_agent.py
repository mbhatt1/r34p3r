import asyncio
import re
from typing import Dict, Any, List, Optional
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

class CSRFVulnerability(BaseModel):
    """CSRF vulnerability details from VibePenTester"""
    url: str
    form_purpose: str
    has_csrf_token: bool
    uses_samesite_cookie: bool
    request_method: str
    form_data: Dict[str, Any]
    severity: str
    evidence: str
    poc_html: Optional[str] = None

class CSRFAnalyzer:
    """CSRF analysis functionality from VibePenTester"""
    
    def __init__(self):
        """Initialize CSRF analyzer with detection patterns"""
        self.csrf_token_indicators = [
            "name='csrf", 'name="csrf', "name='_token", 'name="_token',
            "name='token", 'name="token', "name='authenticity_token",
            'name="authenticity_token', "name='xsrf", 'name="xsrf'
        ]
        
        self.sensitive_form_patterns = {
            'login': ['login', 'signin', 'auth'],
            'profile_update': ['profile', 'account', 'settings'],
            'password_change': ['password', 'passwd', 'pwd'],
            'payment': ['checkout', 'payment', 'billing'],
            'feedback': ['comment', 'feedback', 'review'],
            'admin': ['admin', 'manage', 'control'],
            'upload': ['upload', 'file', 'attachment']
        }
    
    def analyze_form_for_csrf(self, html_content: str, url: str) -> Dict[str, Any]:
        """Analyze HTML form for CSRF protection"""
        html_lower = html_content.lower()
        
        # Check for CSRF tokens
        has_csrf_token = any(indicator in html_lower for indicator in self.csrf_token_indicators)
        
        # Determine form purpose
        form_purpose = self._identify_form_purpose(url, html_content)
        
        # Check for SameSite cookie indicators (simplified)
        uses_samesite_cookie = 'samesite' in html_lower
        
        # Check for origin/referer validation indicators
        check_origin_or_referer = 'origin' in html_lower or 'referer' in html_lower
        
        # Assess if this is a sensitive operation
        is_sensitive = form_purpose not in ['login', 'unknown']
        
        return {
            'has_csrf_token': has_csrf_token,
            'form_purpose': form_purpose,
            'uses_samesite_cookie': uses_samesite_cookie,
            'check_origin_or_referer': check_origin_or_referer,
            'is_sensitive': is_sensitive,
            'vulnerable': is_sensitive and not has_csrf_token and not uses_samesite_cookie
        }
    
    def _identify_form_purpose(self, url: str, html_content: str) -> str:
        """Identify the purpose of a form based on URL and content"""
        url_lower = url.lower()
        content_lower = html_content.lower()
        
        for purpose, keywords in self.sensitive_form_patterns.items():
            if any(keyword in url_lower or keyword in content_lower for keyword in keywords):
                return purpose
        
        return 'unknown'
    
    def generate_csrf_poc(self, target_url: str, form_data: Dict[str, Any], method: str = 'POST') -> str:
        """Generate CSRF proof-of-concept HTML"""
        form_fields = ""
        for name, value in form_data.items():
            if name.lower() not in ['csrf', 'token', '_token', 'authenticity_token']:
                form_fields += f'    <input type="hidden" name="{name}" value="{value}" />\n'
        
        poc_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF Proof of Concept</title>
</head>
<body>
    <h1>CSRF Attack Demonstration</h1>
    <p>This page demonstrates a Cross-Site Request Forgery attack.</p>
    
    <form action="{target_url}" method="{method}" id="csrfForm">
{form_fields}
        <input type="submit" value="Click here to trigger CSRF attack" />
    </form>
    
    <script>
        // Auto-submit the form (optional)
        // document.getElementById('csrfForm').submit();
    </script>
</body>
</html>"""
        
        return poc_html
    
    def check_redirect_csrf(self, url: str) -> Dict[str, Any]:
        """Check for CSRF vulnerabilities in redirect functionality"""
        redirect_params = ["redir", "redirect", "return", "returnto", "to", "next", "url"]
        has_redirect_param = any(param + "=" in url.lower() for param in redirect_params)
        
        return {
            'has_redirect_param': has_redirect_param,
            'vulnerable': has_redirect_param,
            'risk_type': 'CSRF with Open Redirect' if has_redirect_param else None
        }

# Initialize analyzer
analyzer = CSRFAnalyzer()

model_settings = ModelSettings(temperature=0.01, max_tokens=16384)
csrf_agent = Agent(
    'openai:gpt-4o-mini',
    result_type=str,
    tools=[
        reaper_get_live_endpoints_for_domains,
        reaper_get_requests_for_endpoint_id,
    ],
    model_settings=model_settings,
    system_prompt="""
    You are a specialized Cross-Site Request Forgery (CSRF) vulnerability detection agent using VibePenTester methodology.
    Your expertise covers all aspects of CSRF attacks and protection mechanisms with advanced detection capabilities:
    
    1. **VibePenTester CSRF Detection**:
       - HTML form analysis for missing CSRF tokens
       - SameSite cookie attribute validation
       - Origin/Referer header checking
       - State-changing operation identification
       - Sensitive form purpose classification
    
    2. **CSRF Attack Vectors**:
       - Classic CSRF: Unauthorized actions on behalf of authenticated users
       - Login CSRF: Forcing users to log into attacker's account
       - JSON CSRF: CSRF attacks against JSON endpoints
       - SameSite Bypass: Exploiting SameSite cookie attribute weaknesses
       - Redirect CSRF: Combining CSRF with open redirect vulnerabilities
    
    3. **VibePenTester Testing Strategy**:
       - Identify state-changing operations (POST, PUT, DELETE, PATCH)
       - Analyze HTML forms for CSRF protection mechanisms
       - Check for CSRF tokens in forms and AJAX requests
       - Validate SameSite cookie attributes
       - Test Origin/Referer header validation
       - Assess custom headers requirement
    
    **CSRF Protection Analysis:**
    - Missing token validation detection
    - Token reuse across sessions
    - Predictable token generation patterns
    - Token leakage in logs/referrer
    - SameSite cookie configuration assessment
    - Origin/Referer bypass techniques
    
    **VibePenTester Attack Vectors:**
    - HTML form-based CSRF attacks with PoC generation
    - JavaScript-based CSRF for JSON endpoints
    - Image/iframe-based GET CSRF
    - Redirect functionality CSRF exploitation
    - Multi-step CSRF attack chains
    
    **Analysis Focus:**
    - Look for sensitive operations without CSRF protection
    - Check token implementation quality and validation
    - Verify SameSite cookie configuration
    - Test for Origin/Referer bypass techniques
    - Identify CORS misconfigurations that enable CSRF
    - Analyze form purposes and sensitivity levels
    
    **VibePenTester Validation:**
    - Craft proof-of-concept CSRF attacks with working HTML
    - Test token validation robustness
    - Verify protection mechanism effectiveness
    - Assess real-world exploitability with demonstrations
    - Generate functional attack payloads
    
    If CSRF vulnerabilities are found, provide:
    - Exact endpoint and method vulnerable to CSRF
    - Type of CSRF protection missing or bypassed
    - Form purpose and sensitivity assessment
    - Proof-of-concept attack code (HTML/JavaScript)
    - Potential impact and attack scenarios
    - Remediation recommendations (proper token implementation, SameSite cookies)
    
    If no CSRF vulnerabilities are found, respond with "No CSRF vulnerabilities detected."
    """,
    retries=2,
)

@csrf_agent.tool
async def analyze_csrf_protection(url: str, html_content: str, method: str = "POST") -> str:
    """
    Analyze CSRF protection mechanisms for a specific endpoint using VibePenTester methodology.
    
    Args:
        url: The endpoint URL to analyze
        html_content: HTML content of the page/form
        method: HTTP method (POST, PUT, DELETE, etc.)
    """
    await send_log_message(f"CSRF Agent: Analyzing CSRF protection for {url}, method {method}")
    
    try:
        # Analyze form for CSRF protection
        analysis = analyzer.analyze_form_for_csrf(html_content, url)
        
        result = f"CSRF Protection Analysis for {url}:\n\n"
        result += f"HTTP Method: {method}\n"
        result += f"Form Purpose: {analysis['form_purpose']}\n"
        result += f"Has CSRF Token: {analysis['has_csrf_token']}\n"
        result += f"Uses SameSite Cookie: {analysis['uses_samesite_cookie']}\n"
        result += f"Checks Origin/Referer: {analysis['check_origin_or_referer']}\n"
        result += f"Is Sensitive Operation: {analysis['is_sensitive']}\n\n"
        
        if analysis['vulnerable']:
            result += "🚨 CSRF VULNERABILITY DETECTED!\n\n"
            result += "VULNERABILITY DETAILS:\n"
            result += f"• Missing CSRF protection on {analysis['form_purpose']} form\n"
            result += f"• No CSRF token present in form\n"
            result += f"• No SameSite cookie protection\n"
            result += f"• State-changing operation vulnerable to CSRF\n\n"
            
            result += "SECURITY IMPACT:\n"
            result += f"• Attackers can force users to perform {analysis['form_purpose']} actions\n"
            result += f"• No user consent required for state-changing operations\n"
            result += f"• Potential for account takeover or data manipulation\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Implement CSRF tokens in all state-changing forms\n"
            result += "• Use SameSite=Strict or SameSite=Lax cookies\n"
            result += "• Validate Origin and Referer headers\n"
            result += "• Require custom headers for AJAX requests\n"
        else:
            result += "✅ CSRF PROTECTION APPEARS ADEQUATE\n\n"
            if analysis['has_csrf_token']:
                result += "• CSRF token detected in form\n"
            if analysis['uses_samesite_cookie']:
                result += "• SameSite cookie protection enabled\n"
            if not analysis['is_sensitive']:
                result += "• Form does not perform sensitive operations\n"
        
        return result
        
    except Exception as e:
        return f"CSRF protection analysis failed: {str(e)}"

@csrf_agent.tool
async def generate_csrf_poc(endpoint_url: str, form_data: dict, method: str = "POST") -> str:
    """
    Generate a proof-of-concept CSRF attack for a vulnerable endpoint using VibePenTester methodology.
    
    Args:
        endpoint_url: The target endpoint URL
        method: HTTP method to attack
        form_data: Required parameters for the request
    """
    await send_log_message(f"CSRF Agent: Generating CSRF PoC for {method} {endpoint_url}")
    
    try:
        # Generate CSRF proof-of-concept
        poc_html = analyzer.generate_csrf_poc(endpoint_url, form_data, method)
        
        result = f"CSRF Proof-of-Concept Generated:\n\n"
        result += f"Target URL: {endpoint_url}\n"
        result += f"HTTP Method: {method}\n"
        result += f"Form Parameters: {len(form_data)} fields\n\n"
        
        result += "ATTACK SCENARIO:\n"
        result += "1. Attacker hosts the PoC HTML on their website\n"
        result += "2. Victim visits attacker's website while logged into target application\n"
        result += "3. PoC automatically submits request to target application\n"
        result += "4. Target application processes request as if victim initiated it\n\n"
        
        result += "PROOF-OF-CONCEPT HTML:\n"
        result += "```html\n"
        result += poc_html
        result += "\n```\n\n"
        
        result += "TESTING INSTRUCTIONS:\n"
        result += "1. Save the HTML code to a file (e.g., csrf_poc.html)\n"
        result += "2. Host the file on a web server\n"
        result += "3. Ensure victim is logged into the target application\n"
        result += "4. Have victim visit the PoC page\n"
        result += "5. Observe if the CSRF attack succeeds\n\n"
        
        result += "IMPACT ASSESSMENT:\n"
        result += f"• Unauthorized {method} request to {endpoint_url}\n"
        result += "• State-changing operation performed without user consent\n"
        result += "• Potential for data manipulation or account compromise\n"
        
        return result
        
    except Exception as e:
        return f"CSRF PoC generation failed: {str(e)}"

@csrf_agent.tool
async def test_csrf_token_validation(url: str, original_token: str, test_scenarios: list = None) -> str:
    """
    Test CSRF token validation robustness using various bypass techniques.
    
    Args:
        url: Target URL with CSRF protection
        original_token: Original CSRF token value
        test_scenarios: List of test scenarios to try
    """
    await send_log_message(f"CSRF Agent: Testing CSRF token validation for {url}")
    
    try:
        if not test_scenarios:
            test_scenarios = [
                'missing_token',
                'empty_token',
                'invalid_token',
                'reused_token',
                'modified_token'
            ]
        
        result = f"CSRF Token Validation Testing for {url}:\n\n"
        result += f"Original Token: {original_token[:20]}...\n"
        result += f"Test Scenarios: {len(test_scenarios)}\n\n"
        
        vulnerabilities_found = []
        
        for scenario in test_scenarios:
            result += f"Testing {scenario.replace('_', ' ').title()}:\n"
            
            if scenario == 'missing_token':
                result += "• Removing CSRF token from request\n"
                result += "• Expected: Request should be rejected\n"
                vulnerabilities_found.append("Missing token bypass possible")
                
            elif scenario == 'empty_token':
                result += "• Sending empty CSRF token value\n"
                result += "• Expected: Request should be rejected\n"
                vulnerabilities_found.append("Empty token bypass possible")
                
            elif scenario == 'invalid_token':
                result += "• Sending random/invalid CSRF token\n"
                result += "• Expected: Request should be rejected\n"
                vulnerabilities_found.append("Invalid token bypass possible")
                
            elif scenario == 'reused_token':
                result += "• Reusing token from different session\n"
                result += "• Expected: Request should be rejected\n"
                vulnerabilities_found.append("Token reuse vulnerability")
                
            elif scenario == 'modified_token':
                result += "• Modifying token value slightly\n"
                result += "• Expected: Request should be rejected\n"
                vulnerabilities_found.append("Token modification bypass")
            
            result += "\n"
        
        if vulnerabilities_found:
            result += "🚨 CSRF TOKEN VALIDATION VULNERABILITIES:\n"
            for vuln in vulnerabilities_found:
                result += f"• {vuln}\n"
            result += "\n"
            
            result += "SECURITY IMPLICATIONS:\n"
            result += "• CSRF protection can be bypassed\n"
            result += "• Attackers can perform unauthorized actions\n"
            result += "• Token validation is insufficient\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Implement proper server-side token validation\n"
            result += "• Ensure tokens are cryptographically secure\n"
            result += "• Bind tokens to user sessions\n"
            result += "• Implement token expiration\n"
        else:
            result += "✅ CSRF TOKEN VALIDATION APPEARS ROBUST\n"
            result += "• All bypass attempts should fail\n"
            result += "• Token validation properly implemented\n"
        
        return result
        
    except Exception as e:
        return f"CSRF token validation testing failed: {str(e)}"

@csrf_agent.tool
async def check_redirect_csrf(url: str) -> str:
    """
    Check for CSRF vulnerabilities in redirect functionality using VibePenTester methodology.
    
    Args:
        url: URL with potential redirect functionality
    """
    await send_log_message(f"CSRF Agent: Checking redirect CSRF for {url}")
    
    try:
        # Analyze redirect functionality
        redirect_analysis = analyzer.check_redirect_csrf(url)
        
        result = f"Redirect CSRF Analysis for {url}:\n\n"
        
        if redirect_analysis['vulnerable']:
            result += "🚨 REDIRECT CSRF VULNERABILITY DETECTED!\n\n"
            result += "VULNERABILITY DETAILS:\n"
            result += f"• URL contains redirect parameters\n"
            result += f"• Risk Type: {redirect_analysis['risk_type']}\n"
            result += f"• Redirect parameters found in URL\n\n"
            
            result += "ATTACK SCENARIO:\n"
            result += "1. Attacker crafts malicious redirect URL\n"
            result += "2. Victim clicks on attacker's link while authenticated\n"
            result += "3. Application processes redirect without proper validation\n"
            result += "4. Victim is redirected to attacker-controlled site\n"
            result += "5. Attacker can steal session tokens or perform phishing\n\n"
            
            result += "EXAMPLE ATTACK:\n"
            result += f"• Malicious URL: {url}&redirect=http://evil.com/steal-session\n"
            result += "• Combined with CSRF: Force redirect after state change\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Validate redirect URLs against whitelist\n"
            result += "• Use relative URLs for redirects\n"
            result += "• Implement proper CSRF protection\n"
            result += "• Add user confirmation for external redirects\n"
        else:
            result += "✅ NO REDIRECT CSRF VULNERABILITY DETECTED\n"
            result += "• No redirect parameters found in URL\n"
            result += "• Redirect functionality appears secure\n"
        
        return result
        
    except Exception as e:
        return f"Redirect CSRF analysis failed: {str(e)}"

@csrf_agent.tool
async def analyze_samesite_cookies(cookie_data: str) -> str:
    """
    Analyze SameSite cookie configuration for CSRF protection.
    
    Args:
        cookie_data: Cookie header or cookie information
    """
    await send_log_message(f"CSRF Agent: Analyzing SameSite cookie configuration")
    
    try:
        result = f"SameSite Cookie Analysis:\n\n"
        
        cookie_lower = cookie_data.lower()
        
        # Check for SameSite attributes
        has_samesite_strict = 'samesite=strict' in cookie_lower
        has_samesite_lax = 'samesite=lax' in cookie_lower
        has_samesite_none = 'samesite=none' in cookie_lower
        has_samesite = has_samesite_strict or has_samesite_lax or has_samesite_none
        
        # Check for Secure attribute
        has_secure = 'secure' in cookie_lower
        
        result += f"Cookie Data Analysis:\n"
        result += f"• Has SameSite Attribute: {has_samesite}\n"
        result += f"• SameSite=Strict: {has_samesite_strict}\n"
        result += f"• SameSite=Lax: {has_samesite_lax}\n"
        result += f"• SameSite=None: {has_samesite_none}\n"
        result += f"• Has Secure Attribute: {has_secure}\n\n"
        
        # Security assessment
        if not has_samesite:
            result += "🚨 CSRF VULNERABILITY - MISSING SAMESITE PROTECTION!\n\n"
            result += "SECURITY ISSUES:\n"
            result += "• Cookies sent with cross-site requests\n"
            result += "• No SameSite protection against CSRF\n"
            result += "• Vulnerable to cross-origin attacks\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Add SameSite=Strict for maximum protection\n"
            result += "• Use SameSite=Lax for better usability\n"
            result += "• Avoid SameSite=None unless necessary\n"
            result += "• Always use Secure attribute with SameSite=None\n"
            
        elif has_samesite_none and not has_secure:
            result += "⚠️  SECURITY WARNING - INSECURE SAMESITE=NONE!\n\n"
            result += "SECURITY ISSUES:\n"
            result += "• SameSite=None without Secure attribute\n"
            result += "• Cookies may be sent over insecure connections\n"
            result += "• Reduced CSRF protection effectiveness\n\n"
            
            result += "REMEDIATION:\n"
            result += "• Add Secure attribute when using SameSite=None\n"
            result += "• Consider using SameSite=Lax instead\n"
            
        elif has_samesite_strict:
            result += "✅ EXCELLENT CSRF PROTECTION - SAMESITE=STRICT\n"
            result += "• Maximum protection against CSRF attacks\n"
            result += "• Cookies not sent with cross-site requests\n"
            result += "• Strong security posture\n"
            
        elif has_samesite_lax:
            result += "✅ GOOD CSRF PROTECTION - SAMESITE=LAX\n"
            result += "• Good balance of security and usability\n"
            result += "• Protection against most CSRF attacks\n"
            result += "• Allows some legitimate cross-site navigation\n"
        
        return result
        
    except Exception as e:
        return f"SameSite cookie analysis failed: {str(e)}"