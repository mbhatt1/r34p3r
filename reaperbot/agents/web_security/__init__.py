"""
Web Security Agents Module

This module contains specialized agents for detecting various web application vulnerabilities
based on the OWASP Top 10 and other common security issues.
"""

from .xss_agent import xss_agent
from .sqli_agent import sqli_agent
from .csrf_agent import csrf_agent
from .ssrf_agent import ssrf_agent
from .auth_agent import auth_agent
from .crypto_agent import crypto_agent

__all__ = [
    'xss_agent',
    'sqli_agent', 
    'csrf_agent',
    'ssrf_agent',
    'auth_agent',
    'crypto_agent'
]