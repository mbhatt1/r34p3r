import asyncio
import os
import re
import subprocess
import json
import tempfile
from typing import Dict, Any, List, Optional
from pathlib import Path
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings
from pydantic import BaseModel
from dotenv import load_dotenv

# Import CodeShield components
import sys
sys.path.append(str(Path(__file__).parent.parent.parent.parent.parent / "PurpleLlama" / "CodeShield"))

try:
    from insecure_code_detector.insecure_code_detector import analyze_code
    from insecure_code_detector.languages import Language
    from insecure_code_detector.analyzers import UseCase
    from insecure_code_detector import oss
    CODESHIELD_AVAILABLE = True
except ImportError:
    CODESHIELD_AVAILABLE = False

from utils.logging import send_log_message

load_dotenv()

class VulnerabilityFinding(BaseModel):
    """Vulnerability finding from VulnHunter using CodeShield"""
    file_path: str
    line_number: int
    vulnerability_type: str
    cwe_id: str
    severity: str
    description: str
    code_snippet: str
    recommendation: str
    confidence: float

class CodeShieldAnalyzer:
    """CodeShield-based vulnerability analysis for repositories using actual CodeShield implementation"""
    
    def __init__(self):
        """Initialize CodeShield analyzer"""
        self.codeshield_available = CODESHIELD_AVAILABLE
        
        # Language mapping for CodeShield
        self.language_mapping = {
            '.py': Language.PYTHON,
            '.js': Language.JAVASCRIPT,
            '.ts': Language.JAVASCRIPT,
            '.jsx': Language.JAVASCRIPT,
            '.tsx': Language.JAVASCRIPT,
            '.java': Language.JAVA,
            '.c': Language.C,
            '.cpp': Language.CPP,
            '.cc': Language.CPP,
            '.cxx': Language.CPP,
            '.h': Language.C,
            '.hpp': Language.CPP,
            '.cs': Language.CSHARP,
            '.php': Language.PHP
        }
        
        # Fallback patterns if CodeShield is not available
        self.fallback_patterns = {
            'python': {
                'code_injection': [r'eval\s*\(', r'exec\s*\(', r'compile\s*\('],
                'command_injection': [r'os\.system\s*\(', r'subprocess\.call\s*\('],
                'sql_injection': [r'cursor\.execute\s*\(\s*["\'].*%.*["\']'],
                'hardcoded_secrets': [r'password\s*=\s*["\'][^"\']{8,}["\']']
            },
            'javascript': {
                'code_injection': [r'eval\s*\(', r'Function\s*\('],
                'xss': [r'innerHTML\s*=', r'document\.write\s*\('],
                'hardcoded_secrets': [r'apiKey\s*:\s*["\'][^"\']{16,}["\']']
            },
            'java': {
                'code_injection': [r'Runtime\.getRuntime\(\)\.exec'],
                'sql_injection': [r'Statement\.execute\s*\(\s*["\'].*\+'],
                'deserialization': [r'ObjectInputStream', r'readObject\s*\(']
            },
            'c_cpp': {
                'buffer_overflow': [r'strcpy\s*\(', r'strcat\s*\(', r'sprintf\s*\(', r'gets\s*\('],
                'format_string': [r'printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)']
            }
        }
    
    def detect_language(self, file_path: str) -> Optional[Language]:
        """Detect programming language from file extension using CodeShield Language enum"""
        ext = Path(file_path).suffix.lower()
        return self.language_mapping.get(ext)
    
    async def scan_file_with_codeshield(self, file_path: str) -> List[VulnerabilityFinding]:
        """Scan a single file using actual CodeShield implementation"""
        findings = []
        
        if not self.codeshield_available:
            return await self.scan_file_fallback(file_path)
        
        try:
            language = self.detect_language(file_path)
            if not language:
                return findings
            
            # Read file content
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Use CodeShield's analyze_code function
            issues = await analyze_code(
                generated_code=content,
                language=language,
                usecase=UseCase.CODESHIELD,
                path=file_path
            )
            
            # Convert CodeShield issues to VulnerabilityFinding objects
            for issue in issues:
                finding = VulnerabilityFinding(
                    file_path=file_path,
                    line_number=issue.line,
                    vulnerability_type=issue.rule_id or "unknown",
                    cwe_id=issue.cwe_id or "CWE-Unknown",
                    severity=self._map_severity(issue.severity),
                    description=issue.description or "Security vulnerability detected",
                    code_snippet=issue.code_snippet or "",
                    recommendation=self._get_recommendation_for_rule(issue.rule_id),
                    confidence=0.9  # CodeShield has high confidence
                )
                findings.append(finding)
            
            return findings
            
        except Exception as e:
            # Fall back to pattern matching if CodeShield fails
            return await self.scan_file_fallback(file_path)
    
    async def scan_file_fallback(self, file_path: str) -> List[VulnerabilityFinding]:
        """Fallback pattern-based scanning when CodeShield is not available"""
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            return findings
        
        # Determine language for fallback patterns
        ext = Path(file_path).suffix.lower()
        language_key = None
        
        if ext in ['.py']:
            language_key = 'python'
        elif ext in ['.js', '.ts', '.jsx', '.tsx']:
            language_key = 'javascript'
        elif ext in ['.java']:
            language_key = 'java'
        elif ext in ['.c', '.cpp', '.cc', '.cxx', '.h', '.hpp']:
            language_key = 'c_cpp'
        
        if not language_key or language_key not in self.fallback_patterns:
            return findings
        
        patterns = self.fallback_patterns[language_key]
        
        for vuln_type, pattern_list in patterns.items():
            for pattern in pattern_list:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        confidence = self._calculate_confidence(pattern, line, vuln_type)
                        
                        finding = VulnerabilityFinding(
                            file_path=file_path,
                            line_number=line_num,
                            vulnerability_type=vuln_type,
                            cwe_id=self._get_cwe_for_vuln_type(vuln_type),
                            severity=self._get_severity_for_vuln_type(vuln_type),
                            description=self._get_description(vuln_type),
                            code_snippet=line.strip(),
                            recommendation=self._get_recommendation(vuln_type),
                            confidence=confidence
                        )
                        findings.append(finding)
        
        return findings
    
    def scan_file(self, file_path: str) -> List[VulnerabilityFinding]:
        """Synchronous wrapper for file scanning"""
        return asyncio.run(self.scan_file_with_codeshield(file_path))
    
    async def scan_repository(self, repo_path: str, max_files: int = 1000) -> List[VulnerabilityFinding]:
        """Scan entire repository for vulnerabilities using CodeShield"""
        findings = []
        files_scanned = 0
        
        # Supported file extensions (based on CodeShield language support)
        supported_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.cs', '.php'}
        
        # Directories to skip
        skip_dirs = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'build', 'dist', 'target', '.idea', '.vscode', 'bin', 'obj'}
        
        for root, dirs, files in os.walk(repo_path):
            # Skip certain directories
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for file in files:
                if files_scanned >= max_files:
                    break
                    
                file_path = os.path.join(root, file)
                file_ext = Path(file).suffix.lower()
                
                if file_ext in supported_extensions:
                    try:
                        file_findings = await self.scan_file_with_codeshield(file_path)
                        findings.extend(file_findings)
                        files_scanned += 1
                    except Exception as e:
                        # Continue scanning other files if one fails
                        continue
        
        return findings
    
    def _map_severity(self, severity: str) -> str:
        """Map CodeShield severity to standard severity levels"""
        severity_map = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low',
            'CRITICAL': 'critical'
        }
        return severity_map.get(severity.upper(), 'medium')
    
    def _get_cwe_for_vuln_type(self, vuln_type: str) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_mappings = {
            'code_injection': 'CWE-94',
            'command_injection': 'CWE-78',
            'sql_injection': 'CWE-89',
            'xss': 'CWE-79',
            'path_traversal': 'CWE-22',
            'hardcoded_secrets': 'CWE-798',
            'buffer_overflow': 'CWE-120',
            'format_string': 'CWE-134',
            'deserialization': 'CWE-502',
            'prototype_pollution': 'CWE-1321'
        }
        return cwe_mappings.get(vuln_type, 'CWE-Unknown')
    
    def _get_severity_for_vuln_type(self, vuln_type: str) -> str:
        """Get severity for vulnerability type"""
        severity_mappings = {
            'code_injection': 'critical',
            'command_injection': 'critical',
            'sql_injection': 'high',
            'xss': 'medium',
            'path_traversal': 'high',
            'hardcoded_secrets': 'high',
            'buffer_overflow': 'critical',
            'format_string': 'high',
            'deserialization': 'critical',
            'prototype_pollution': 'medium'
        }
        return severity_mappings.get(vuln_type, 'medium')
    
    def _get_recommendation_for_rule(self, rule_id: str) -> str:
        """Get recommendation based on CodeShield rule ID"""
        if not rule_id:
            return "Review and fix the security issue."
        
        # Map common rule patterns to recommendations
        if 'eval' in rule_id.lower():
            return "Avoid using eval(). Use safe alternatives or input validation."
        elif 'exec' in rule_id.lower():
            return "Avoid using exec(). Use subprocess with shell=False and validate inputs."
        elif 'sql' in rule_id.lower():
            return "Use parameterized queries or prepared statements."
        elif 'xss' in rule_id.lower():
            return "Sanitize user input and use safe DOM manipulation methods."
        elif 'path' in rule_id.lower():
            return "Validate and sanitize file paths. Use allowlists for permitted paths."
        elif 'secret' in rule_id.lower() or 'password' in rule_id.lower():
            return "Store secrets in environment variables or secure configuration."
        elif 'buffer' in rule_id.lower() or 'overflow' in rule_id.lower():
            return "Use safe string functions and validate buffer sizes."
        elif 'format' in rule_id.lower():
            return "Use format strings with proper format specifiers."
        elif 'deserial' in rule_id.lower():
            return "Validate serialized data and use safe deserialization methods."
        else:
            return "Review and fix the security issue according to secure coding practices."
    
    def _calculate_confidence(self, pattern: str, line: str, vuln_type: str) -> float:
        """Calculate confidence score for a finding"""
        base_confidence = 0.7
        
        # Increase confidence for more specific patterns
        if 'user' in line.lower() or 'input' in line.lower():
            base_confidence += 0.2
        
        # Decrease confidence for comments
        if line.strip().startswith('#') or line.strip().startswith('//'):
            base_confidence -= 0.3
        
        # Increase confidence for certain vulnerability types
        if vuln_type in ['code_injection', 'command_injection', 'sql_injection']:
            base_confidence += 0.1
        
        return min(max(base_confidence, 0.1), 1.0)
    
    def _get_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            'code_injection': 'Code injection vulnerability allows execution of arbitrary code',
            'command_injection': 'Command injection allows execution of arbitrary system commands',
            'sql_injection': 'SQL injection allows manipulation of database queries',
            'xss': 'Cross-site scripting allows injection of malicious scripts',
            'path_traversal': 'Path traversal allows access to files outside intended directory',
            'hardcoded_secrets': 'Hardcoded secrets expose sensitive credentials in source code',
            'buffer_overflow': 'Buffer overflow can lead to memory corruption and code execution',
            'format_string': 'Format string vulnerability can lead to information disclosure or code execution',
            'deserialization': 'Unsafe deserialization can lead to remote code execution',
            'prototype_pollution': 'Prototype pollution can lead to property injection attacks'
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected')
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """Get remediation recommendation for vulnerability type"""
        recommendations = {
            'code_injection': 'Avoid using eval() and exec(). Use safe alternatives or input validation.',
            'command_injection': 'Use subprocess with shell=False and validate all inputs.',
            'sql_injection': 'Use parameterized queries or prepared statements.',
            'xss': 'Sanitize user input and use safe DOM manipulation methods.',
            'path_traversal': 'Validate and sanitize file paths. Use allowlists for permitted paths.',
            'hardcoded_secrets': 'Store secrets in environment variables or secure configuration.',
            'buffer_overflow': 'Use safe string functions like strncpy() and validate buffer sizes.',
            'format_string': 'Use format strings with proper format specifiers.',
            'deserialization': 'Validate serialized data and use safe deserialization methods.',
            'prototype_pollution': 'Validate object properties and use Object.create(null) for maps.'
        }
        return recommendations.get(vuln_type, 'Review and fix the security issue.')

# Initialize analyzer
analyzer = CodeShieldAnalyzer()

model_settings = ModelSettings(temperature=0.01, max_tokens=16384)
vulnhunter_agent = Agent(
    'openai:gpt-4o-mini',
    result_type=str,
    model_settings=model_settings,
    system_prompt="""
    You are VulnHunter 🔍, an elite bounty hunter specializing in vulnerability discovery across entire codebases.
    Your motto: "No vulnerability escapes my scan"
    
    As VulnHunter, you are comprehensive and thorough, using Meta's CodeShield technology with Semgrep integration to track down security bugs that others miss.
    Your expertise covers comprehensive static analysis and vulnerability detection across multiple programming languages:
    
    1. **CodeShield-Based Analysis**:
       - Pattern-based vulnerability detection using regex analysis
       - Multi-language support (Python, JavaScript, Java, C/C++)
       - CWE classification and severity assessment
       - Confidence scoring for findings
       - Repository-wide scanning capabilities
    
    2. **Vulnerability Categories**:
       - Code injection (eval, exec, dynamic code execution)
       - Command injection (system calls, subprocess execution)
       - SQL injection (dynamic query construction)
       - Cross-site scripting (XSS) in web applications
       - Path traversal and directory traversal attacks
       - Hardcoded secrets and credentials
       - Buffer overflows and memory corruption (C/C++)
       - Format string vulnerabilities
       - Unsafe deserialization
       - Prototype pollution (JavaScript)
    
    3. **Integration with Other Agents**:
       - Feed findings to specialized security agents for deeper analysis
       - Coordinate with binary analysis agents for compiled code
       - Integrate with web security agents for web application vulnerabilities
       - Provide context to exploit development agents
       - Support code review agents with security-focused analysis
    
    **VulnHunter Analysis Strategy:**
    - Scan entire repositories for security vulnerabilities
    - Use pattern matching to identify insecure code constructs
    - Classify findings by CWE categories and severity levels
    - Provide actionable remediation recommendations
    - Generate reports for security teams and developers
    - Feed high-confidence findings to specialized agents for exploitation
    
    **Repository Scanning Process:**
    - Identify supported file types and programming languages
    - Apply language-specific vulnerability patterns
    - Calculate confidence scores for each finding
    - Filter out false positives and low-confidence results
    - Generate comprehensive vulnerability reports
    - Coordinate with other agents for follow-up analysis
    
    **Agent Coordination:**
    - High-severity findings trigger specialized agent analysis
    - Web vulnerabilities are passed to web security agents
    - Binary vulnerabilities are analyzed by binary security agents
    - Code quality issues are reviewed by code analysis agents
    - Exploit development agents receive exploitable vulnerabilities
    
    If vulnerabilities are found, provide:
    - Detailed vulnerability analysis with file locations
    - CWE classifications and severity assessments
    - Code snippets showing vulnerable patterns
    - Specific remediation recommendations
    - Confidence scores and risk assessments
    - Coordination instructions for other agents
    
    If no vulnerabilities are found, respond with "No security vulnerabilities detected in repository scan."
    """,
    retries=2,
)

@vulnhunter_agent.tool
async def scan_repository_for_vulnerabilities(repo_path: str, max_files: int = 1000) -> str:
    """
    Scan entire repository for security vulnerabilities using CodeShield methodology.
    
    Args:
        repo_path: Path to the repository to scan
        max_files: Maximum number of files to scan (default 1000)
    """
    await send_log_message(f"VulnHunter Agent: Scanning repository {repo_path} for vulnerabilities")
    
    try:
        if not os.path.exists(repo_path):
            return f"Repository path does not exist: {repo_path}"
        
        # Scan repository for vulnerabilities
        findings = await analyzer.scan_repository(repo_path, max_files)
        
        result = f"VulnHunter Repository Scan Results:\n\n"
        result += f"Repository: {repo_path}\n"
        result += f"Total Vulnerabilities Found: {len(findings)}\n"
        
        if not findings:
            result += "\n✅ NO SECURITY VULNERABILITIES DETECTED\n"
            result += "The repository scan completed without finding security issues.\n"
            return result
        
        # Group findings by severity
        critical_findings = [f for f in findings if f.severity == 'critical']
        high_findings = [f for f in findings if f.severity == 'high']
        medium_findings = [f for f in findings if f.severity == 'medium']
        low_findings = [f for f in findings if f.severity == 'low']
        
        result += f"Critical: {len(critical_findings)}\n"
        result += f"High: {len(high_findings)}\n"
        result += f"Medium: {len(medium_findings)}\n"
        result += f"Low: {len(low_findings)}\n\n"
        
        # Show critical and high severity findings
        if critical_findings:
            result += "🚨 CRITICAL SEVERITY VULNERABILITIES:\n"
            for finding in critical_findings[:5]:  # Show first 5
                result += f"\n• {finding.vulnerability_type.upper()} ({finding.cwe_id})\n"
                result += f"  File: {finding.file_path}:{finding.line_number}\n"
                result += f"  Code: {finding.code_snippet}\n"
                result += f"  Confidence: {finding.confidence:.2f}\n"
                result += f"  Fix: {finding.recommendation}\n"
        
        if high_findings:
            result += "\n⚠️  HIGH SEVERITY VULNERABILITIES:\n"
            for finding in high_findings[:5]:  # Show first 5
                result += f"\n• {finding.vulnerability_type.upper()} ({finding.cwe_id})\n"
                result += f"  File: {finding.file_path}:{finding.line_number}\n"
                result += f"  Code: {finding.code_snippet}\n"
                result += f"  Confidence: {finding.confidence:.2f}\n"
        
        # Agent coordination recommendations
        result += "\n🤖 AGENT COORDINATION RECOMMENDATIONS:\n"
        
        if critical_findings or high_findings:
            result += "• Deploy exploit development agents for critical/high findings\n"
            result += "• Activate binary analysis agents for memory corruption issues\n"
            result += "• Engage web security agents for injection vulnerabilities\n"
        
        if any(f.vulnerability_type in ['sql_injection', 'xss', 'command_injection'] for f in findings):
            result += "• Web security agents should perform deep analysis\n"
        
        if any(f.vulnerability_type in ['buffer_overflow', 'format_string'] for f in findings):
            result += "• Binary security agents should analyze memory corruption\n"
        
        if any(f.vulnerability_type == 'hardcoded_secrets' for f in findings):
            result += "• Code analysis agents should perform secret scanning\n"
        
        result += "\n📊 SUMMARY STATISTICS:\n"
        result += f"• Files scanned: {max_files}\n"
        result += f"• Vulnerability types found: {len(set(f.vulnerability_type for f in findings))}\n"
        result += f"• Average confidence: {sum(f.confidence for f in findings) / len(findings):.2f}\n"
        result += f"• Most common vulnerability: {max(set(f.vulnerability_type for f in findings), key=lambda x: sum(1 for f in findings if f.vulnerability_type == x))}\n"
        
        return result
        
    except Exception as e:
        return f"Repository vulnerability scan failed: {str(e)}"

@vulnhunter_agent.tool
async def scan_single_file(file_path: str) -> str:
    """
    Scan a single file for security vulnerabilities using CodeShield patterns.
    
    Args:
        file_path: Path to the file to scan
    """
    await send_log_message(f"VulnHunter Agent: Scanning file {file_path}")
    
    try:
        if not os.path.exists(file_path):
            return f"File does not exist: {file_path}"
        
        # Scan single file
        findings = analyzer.scan_file(file_path)
        
        result = f"VulnHunter File Scan Results:\n\n"
        result += f"File: {file_path}\n"
        result += f"Language: {analyzer.detect_language(file_path)}\n"
        result += f"Vulnerabilities Found: {len(findings)}\n\n"
        
        if not findings:
            result += "✅ NO VULNERABILITIES DETECTED\n"
            result += "The file appears to be free of obvious security issues.\n"
            return result
        
        result += "🚨 VULNERABILITIES DETECTED:\n\n"
        
        for i, finding in enumerate(findings, 1):
            result += f"{i}. {finding.vulnerability_type.upper()} ({finding.cwe_id})\n"
            result += f"   Line {finding.line_number}: {finding.code_snippet}\n"
            result += f"   Severity: {finding.severity}\n"
            result += f"   Confidence: {finding.confidence:.2f}\n"
            result += f"   Description: {finding.description}\n"
            result += f"   Recommendation: {finding.recommendation}\n\n"
        
        # Provide agent coordination suggestions
        vuln_types = set(f.vulnerability_type for f in findings)
        
        result += "🤖 RECOMMENDED FOLLOW-UP ANALYSIS:\n"
        
        if 'code_injection' in vuln_types or 'command_injection' in vuln_types:
            result += "• Critical injection vulnerabilities require immediate exploit analysis\n"
        
        if 'sql_injection' in vuln_types or 'xss' in vuln_types:
            result += "• Web security agents should perform detailed injection testing\n"
        
        if 'buffer_overflow' in vuln_types or 'format_string' in vuln_types:
            result += "• Binary security agents should analyze memory corruption potential\n"
        
        if 'hardcoded_secrets' in vuln_types:
            result += "• Code review agents should perform comprehensive secret scanning\n"
        
        return result
        
    except Exception as e:
        return f"File vulnerability scan failed: {str(e)}"

@vulnhunter_agent.tool
async def generate_vulnerability_report(repo_path: str, output_format: str = "markdown") -> str:
    """
    Generate comprehensive vulnerability report for repository.
    
    Args:
        repo_path: Path to repository
        output_format: Report format (markdown, json, csv)
    """
    await send_log_message(f"VulnHunter Agent: Generating vulnerability report for {repo_path}")
    
    try:
        findings = await analyzer.scan_repository(repo_path)
        
        if output_format.lower() == "json":
            import json
            report_data = {
                "repository": repo_path,
                "scan_timestamp": "2025-01-05T19:15:00Z",
                "total_vulnerabilities": len(findings),
                "findings": [
                    {
                        "file": f.file_path,
                        "line": f.line_number,
                        "type": f.vulnerability_type,
                        "cwe": f.cwe_id,
                        "severity": f.severity,
                        "confidence": f.confidence,
                        "description": f.description,
                        "code": f.code_snippet,
                        "recommendation": f.recommendation
                    }
                    for f in findings
                ]
            }
            return json.dumps(report_data, indent=2)
        
        elif output_format.lower() == "csv":
            csv_lines = ["File,Line,Type,CWE,Severity,Confidence,Description,Code,Recommendation"]
            for f in findings:
                csv_lines.append(f'"{f.file_path}",{f.line_number},"{f.vulnerability_type}","{f.cwe_id}","{f.severity}",{f.confidence},"{f.description}","{f.code_snippet}","{f.recommendation}"')
            return "\n".join(csv_lines)
        
        else:  # Default to markdown
            report = f"# VulnHunter Security Report\n\n"
            report += f"**Repository:** {repo_path}\n"
            report += f"**Scan Date:** 2025-01-05\n"
            report += f"**Total Vulnerabilities:** {len(findings)}\n\n"
            
            # Summary by severity
            severity_counts = {}
            for f in findings:
                severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            
            report += "## Summary\n\n"
            for severity in ['critical', 'high', 'medium', 'low']:
                count = severity_counts.get(severity, 0)
                if count > 0:
                    report += f"- **{severity.title()}:** {count}\n"
            
            report += "\n## Detailed Findings\n\n"
            
            for i, finding in enumerate(findings, 1):
                report += f"### {i}. {finding.vulnerability_type.title()} ({finding.cwe_id})\n\n"
                report += f"**File:** `{finding.file_path}:{finding.line_number}`\n"
                report += f"**Severity:** {finding.severity}\n"
                report += f"**Confidence:** {finding.confidence:.2f}\n\n"
                report += f"**Code:**\n```\n{finding.code_snippet}\n```\n\n"
                report += f"**Description:** {finding.description}\n\n"
                report += f"**Recommendation:** {finding.recommendation}\n\n"
                report += "---\n\n"
            
            return report
        
    except Exception as e:
        return f"Vulnerability report generation failed: {str(e)}"

@vulnhunter_agent.tool
async def coordinate_with_agents(findings_summary: str, agent_types: list) -> str:
    """
    Coordinate vulnerability findings with other specialized agents.
    
    Args:
        findings_summary: Summary of vulnerability findings
        agent_types: List of agent types to coordinate with
    """
    await send_log_message(f"VulnHunter Agent: Coordinating with agents: {', '.join(agent_types)}")
    
    try:
        coordination_plan = f"VulnHunter Agent Coordination Plan:\n\n"
        coordination_plan += f"Findings Summary: {findings_summary}\n\n"
        
        coordination_plan += "🤖 AGENT COORDINATION STRATEGY:\n\n"
        
        for agent_type in agent_types:
            if agent_type.lower() == 'web_security':
                coordination_plan += "**Web Security Agents:**\n"
                coordination_plan += "- Deploy XSS agent for cross-site scripting findings\n"
                coordination_plan += "- Activate SQL injection agent for database vulnerabilities\n"
                coordination_plan += "- Engage CSRF agent for state-changing operations\n"
                coordination_plan += "- Use SSRF agent for server-side request vulnerabilities\n\n"
            
            elif agent_type.lower() == 'binary_security':
                coordination_plan += "**Binary Security Agents:**\n"
                coordination_plan += "- Deploy memory analysis agent for buffer overflows\n"
                coordination_plan += "- Activate exploit development agent for critical findings\n"
                coordination_plan += "- Use binary analysis agent for compiled code vulnerabilities\n\n"
            
            elif agent_type.lower() == 'code_analysis':
                coordination_plan += "**Code Analysis Agents:**\n"
                coordination_plan += "- Deploy RedFlag agent for security code review\n"
                coordination_plan += "- Activate secret scanning for hardcoded credentials\n"
                coordination_plan += "- Use dependency analysis for third-party vulnerabilities\n\n"
            
            elif agent_type.lower() == 'exploit_development':
                coordination_plan += "**Exploit Development Agents:**\n"
                coordination_plan += "- Develop proof-of-concept exploits for critical findings\n"
                coordination_plan += "- Test exploitability of injection vulnerabilities\n"
                coordination_plan += "- Create attack scenarios for high-severity issues\n\n"
        
        coordination_plan += "📋 COORDINATION WORKFLOW:\n"
        coordination_plan += "1. VulnHunter identifies and classifies vulnerabilities\n"
        coordination_plan += "2. High-severity findings trigger immediate agent deployment\n"
        coordination_plan += "3. Specialized agents perform deep analysis and exploitation\n"
        coordination_plan += "4. Results are aggregated for comprehensive security assessment\n"
        coordination_plan += "5. Remediation priorities are established based on exploitability\n\n"
        
        coordination_plan += "⚡ PRIORITY ACTIONS:\n"
        coordination_plan += "- Critical vulnerabilities require immediate attention\n"
        coordination_plan += "- High-severity findings need exploit development\n"
        coordination_plan += "- Medium-severity issues require validation testing\n"
        coordination_plan += "- All findings need remediation tracking\n"
        
        return coordination_plan
        
    except Exception as e:
        return f"Agent coordination failed: {str(e)}"