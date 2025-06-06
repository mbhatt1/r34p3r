"""
Reaper Security Tools

Integrated battle-tested security tools from proven frameworks:
- VibePenTester: Web application security testing
- Rogue: AI-powered vulnerability scanning with browser automation
- Baby Naptime: Binary vulnerability analysis
- CodeShield: Static code analysis for security vulnerabilities
- RedFlag: Security code review tools

All tools have been adapted for the Reaper framework while maintaining
their core functionality and effectiveness.
"""

from .browser_tools import BrowserAutomationTools
from .scanning_tools import SecurityScanner
from .security_tools import SecurityTester
from .rogue_tools import RogueTools
from .binary_tools import BinaryAnalyzer
from .code_analysis_tools import CodeAnalyzer

# Browser automation tools
from .browser_tools import (
    BrowserAutomationTools
)

# Scanning tools
from .scanning_tools import (
    scan_headers,
    scan_ssl_tls,
    brute_force_directories,
    crawl_website,
    analyze_page_content,
    enumerate_subdomains,
    port_scan
)

# Security testing tools
from .security_tools import (
    test_xss_payload,
    test_sqli_payload,
    check_csrf_protection,
    test_ssrf_vulnerability,
    test_access_control,
    check_session_security,
    generate_xss_payloads,
    generate_sqli_payloads
)

# Rogue framework tools
from .rogue_tools import (
    execute_js,
    click_element,
    fill_form,
    navigate_to,
    execute_python_code
)

# Binary analysis tools
from .binary_tools import (
    analyze_binary_file,
    check_memory_corruption,
    create_exploit_template
)

# Code analysis tools
from .code_analysis_tools import (
    analyze_code_file,
    scan_code_repository,
    generate_report
)

__all__ = [
    # Classes
    'BrowserAutomationTools',
    'SecurityScanner',
    'SecurityTester',
    'RogueTools',
    'BinaryAnalyzer',
    'CodeAnalyzer',
    
    # Scanning functions
    'scan_headers',
    'scan_ssl_tls',
    'brute_force_directories',
    'crawl_website',
    'analyze_page_content',
    'enumerate_subdomains',
    'port_scan',
    
    # Security testing functions
    'test_xss_payload',
    'test_sqli_payload',
    'check_csrf_protection',
    'test_ssrf_vulnerability',
    'test_access_control',
    'check_session_security',
    'generate_xss_payloads',
    'generate_sqli_payloads',
    
    # Rogue tools
    'execute_js',
    'click_element',
    'fill_form',
    'navigate_to',
    'execute_python_code',
    
    # Binary analysis
    'analyze_binary_file',
    'check_memory_corruption',
    'create_exploit_template',
    
    # Code analysis
    'analyze_code_file',
    'scan_code_repository',
    'generate_report',
]

# Tool categories for easy access
BROWSER_TOOLS = [
    'BrowserAutomationTools',
    'execute_js',
    'click_element',
    'fill_form',
    'navigate_to'
]

SCANNING_TOOLS = [
    'SecurityScanner',
    'scan_headers',
    'scan_ssl_tls',
    'brute_force_directories',
    'crawl_website',
    'analyze_page_content',
    'enumerate_subdomains',
    'port_scan'
]

SECURITY_TESTING_TOOLS = [
    'SecurityTester',
    'test_xss_payload',
    'test_sqli_payload',
    'check_csrf_protection',
    'test_ssrf_vulnerability',
    'test_access_control',
    'check_session_security',
    'generate_xss_payloads',
    'generate_sqli_payloads'
]

BINARY_ANALYSIS_TOOLS = [
    'BinaryAnalyzer',
    'analyze_binary_file',
    'check_memory_corruption',
    'create_exploit_template'
]

CODE_ANALYSIS_TOOLS = [
    'CodeAnalyzer',
    'analyze_code_file',
    'scan_code_repository',
    'generate_report'
]

ROGUE_TOOLS = [
    'RogueTools',
    'execute_python_code'
]

def get_available_tools():
    """Get list of all available tools"""
    return {
        'browser_tools': BROWSER_TOOLS,
        'scanning_tools': SCANNING_TOOLS,
        'security_testing_tools': SECURITY_TESTING_TOOLS,
        'binary_analysis_tools': BINARY_ANALYSIS_TOOLS,
        'code_analysis_tools': CODE_ANALYSIS_TOOLS,
        'rogue_tools': ROGUE_TOOLS
    }

def get_tool_info():
    """Get information about tool sources and capabilities"""
    return {
        'browser_tools': {
            'source': 'Playwright-based browser automation',
            'capabilities': ['Page navigation', 'Element interaction', 'JavaScript execution', 'Form filling']
        },
        'scanning_tools': {
            'source': 'VibePenTester framework',
            'capabilities': ['Header analysis', 'SSL/TLS scanning', 'Directory enumeration', 'Subdomain discovery']
        },
        'security_testing_tools': {
            'source': 'VibePenTester OWASP Top 10 testing',
            'capabilities': ['XSS testing', 'SQL injection', 'CSRF detection', 'SSRF testing', 'Access control']
        },
        'binary_analysis_tools': {
            'source': 'Baby Naptime binary analysis',
            'capabilities': ['Static analysis', 'Dynamic analysis', 'Memory corruption detection', 'Exploit generation']
        },
        'code_analysis_tools': {
            'source': 'CodeShield and RedFlag frameworks',
            'capabilities': ['Pattern-based detection', 'Semgrep integration', 'Multi-language support', 'Security metrics']
        },
        'rogue_tools': {
            'source': 'Rogue AI-powered scanner',
            'capabilities': ['Browser automation', 'JavaScript execution', 'Python code execution', 'Dynamic testing']
        }
    }