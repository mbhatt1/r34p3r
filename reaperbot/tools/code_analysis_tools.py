"""
Code Analysis Tools

Integrated battle-tested code analysis tools from CodeShield and RedFlag frameworks.
Provides comprehensive static code analysis for security vulnerabilities.

Based on proven implementations from Meta's CodeShield and Addepar's RedFlag.
"""

import re
import os
import json
import subprocess
import tempfile
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

class CodeAnalyzer:
    """Code analysis tools from CodeShield and RedFlag frameworks"""
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.semgrep_available = self._check_semgrep()
        
        # Security patterns from CodeShield
        self.security_patterns = {
            "python": {
                "sql_injection": [
                    r"execute\s*\(\s*[\"'].*%.*[\"']\s*%",
                    r"cursor\.execute\s*\(\s*[\"'].*\+.*[\"']\s*\)",
                    r"query\s*=\s*[\"'].*%.*[\"']\s*%",
                ],
                "command_injection": [
                    r"os\.system\s*\(\s*.*\+",
                    r"subprocess\.(call|run|Popen)\s*\(\s*.*\+",
                    r"eval\s*\(\s*.*input",
                    r"exec\s*\(\s*.*input",
                ],
                "path_traversal": [
                    r"open\s*\(\s*.*\+.*[\"']\.\./",
                    r"file\s*=\s*.*\+.*[\"']\.\./",
                ],
                "hardcoded_secrets": [
                    r"password\s*=\s*[\"'][^\"']{8,}[\"']",
                    r"api[_-]?key\s*=\s*[\"'][^\"']{20,}[\"']",
                    r"secret\s*=\s*[\"'][^\"']{16,}[\"']",
                    r"token\s*=\s*[\"'][^\"']{20,}[\"']",
                ],
                "weak_crypto": [
                    r"hashlib\.md5\s*\(",
                    r"hashlib\.sha1\s*\(",
                    r"Crypto\.Cipher\.DES",
                    r"ssl_context\.check_hostname\s*=\s*False",
                ],
                "deserialization": [
                    r"pickle\.loads?\s*\(",
                    r"yaml\.load\s*\(",
                    r"marshal\.loads?\s*\(",
                ],
            },
            "javascript": {
                "xss": [
                    r"innerHTML\s*=\s*.*\+",
                    r"document\.write\s*\(\s*.*\+",
                    r"eval\s*\(\s*.*\+",
                ],
                "sql_injection": [
                    r"query\s*=\s*[\"'].*\+.*[\"']",
                    r"execute\s*\(\s*[\"'].*\+.*[\"']\s*\)",
                ],
                "command_injection": [
                    r"exec\s*\(\s*.*\+",
                    r"child_process\.exec\s*\(\s*.*\+",
                ],
                "hardcoded_secrets": [
                    r"password\s*[:=]\s*[\"'][^\"']{8,}[\"']",
                    r"apiKey\s*[:=]\s*[\"'][^\"']{20,}[\"']",
                    r"secret\s*[:=]\s*[\"'][^\"']{16,}[\"']",
                ],
                "prototype_pollution": [
                    r"__proto__\s*\[",
                    r"constructor\.prototype",
                ],
            },
            "java": {
                "sql_injection": [
                    r"Statement\.execute\s*\(\s*.*\+",
                    r"createQuery\s*\(\s*[\"'].*\+.*[\"']\s*\)",
                ],
                "command_injection": [
                    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*.*\+",
                    r"ProcessBuilder\s*\(\s*.*\+",
                ],
                "deserialization": [
                    r"ObjectInputStream\.readObject\s*\(",
                    r"XMLDecoder\.readObject\s*\(",
                ],
                "path_traversal": [
                    r"new\s+File\s*\(\s*.*\+.*\"\.\./",
                    r"Files\.newInputStream\s*\(\s*.*\+",
                ],
                "weak_crypto": [
                    r"MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']\s*\)",
                    r"MessageDigest\.getInstance\s*\(\s*[\"']SHA1[\"']\s*\)",
                    r"Cipher\.getInstance\s*\(\s*[\"']DES[\"']\s*\)",
                ],
            }
        }
    
    def _check_semgrep(self) -> bool:
        """Check if Semgrep is available"""
        try:
            subprocess.run(['semgrep', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def analyze_code(self, code_path: str, language: str = None) -> Dict[str, Any]:
        """Comprehensive code analysis"""
        if not os.path.exists(code_path):
            return {"error": f"Code path not found: {code_path}"}
        
        # Auto-detect language if not provided
        if not language:
            language = self._detect_language(code_path)
        
        results = {
            "code_path": code_path,
            "language": language,
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": [],
            "metrics": {}
        }
        
        # Pattern-based analysis
        pattern_vulns = self._pattern_analysis(code_path, language)
        results["vulnerabilities"].extend(pattern_vulns)
        
        # Semgrep analysis if available
        if self.semgrep_available:
            semgrep_vulns = self._semgrep_analysis(code_path)
            results["vulnerabilities"].extend(semgrep_vulns)
        
        # Code metrics
        results["metrics"] = self._calculate_metrics(code_path)
        
        return results
    
    def _detect_language(self, code_path: str) -> str:
        """Auto-detect programming language"""
        if os.path.isfile(code_path):
            ext = Path(code_path).suffix.lower()
            ext_map = {
                '.py': 'python',
                '.js': 'javascript',
                '.ts': 'typescript',
                '.java': 'java',
                '.cpp': 'cpp',
                '.c': 'c',
                '.cs': 'csharp',
                '.php': 'php',
                '.rb': 'ruby',
                '.go': 'go',
                '.rs': 'rust',
            }
            return ext_map.get(ext, 'unknown')
        else:
            # Directory - try to detect from files
            for root, dirs, files in os.walk(code_path):
                for file in files:
                    ext = Path(file).suffix.lower()
                    if ext in ['.py', '.js', '.java', '.cpp', '.c']:
                        return {'.py': 'python', '.js': 'javascript', '.java': 'java', 
                               '.cpp': 'cpp', '.c': 'c'}.get(ext, 'unknown')
            return 'unknown'
    
    def _pattern_analysis(self, code_path: str, language: str) -> List[Dict[str, Any]]:
        """Pattern-based vulnerability detection"""
        vulnerabilities = []
        
        if language not in self.security_patterns:
            return vulnerabilities
        
        patterns = self.security_patterns[language]
        
        if os.path.isfile(code_path):
            files_to_analyze = [code_path]
        else:
            files_to_analyze = []
            for root, dirs, files in os.walk(code_path):
                for file in files:
                    if self._is_code_file(file, language):
                        files_to_analyze.append(os.path.join(root, file))
        
        for file_path in files_to_analyze:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                for vuln_type, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            vulnerabilities.append({
                                "type": vuln_type.replace('_', ' ').title(),
                                "severity": self._get_severity(vuln_type),
                                "file": file_path,
                                "line": line_num,
                                "code": match.group(0),
                                "pattern": pattern,
                                "description": self._get_description(vuln_type),
                                "recommendation": self._get_recommendation(vuln_type)
                            })
            
            except Exception as e:
                continue
        
        return vulnerabilities
    
    def _is_code_file(self, filename: str, language: str) -> bool:
        """Check if file is a code file for the given language"""
        ext = Path(filename).suffix.lower()
        language_extensions = {
            'python': ['.py'],
            'javascript': ['.js', '.jsx'],
            'typescript': ['.ts', '.tsx'],
            'java': ['.java'],
            'cpp': ['.cpp', '.cc', '.cxx'],
            'c': ['.c'],
            'csharp': ['.cs'],
            'php': ['.php'],
            'ruby': ['.rb'],
            'go': ['.go'],
            'rust': ['.rs'],
        }
        
        return ext in language_extensions.get(language, [])
    
    def _get_severity(self, vuln_type: str) -> str:
        """Get severity level for vulnerability type"""
        severity_map = {
            'sql_injection': 'critical',
            'command_injection': 'critical',
            'xss': 'high',
            'path_traversal': 'high',
            'deserialization': 'high',
            'hardcoded_secrets': 'medium',
            'weak_crypto': 'medium',
            'prototype_pollution': 'medium',
        }
        return severity_map.get(vuln_type, 'low')
    
    def _get_description(self, vuln_type: str) -> str:
        """Get description for vulnerability type"""
        descriptions = {
            'sql_injection': 'SQL injection vulnerability allows attackers to execute arbitrary SQL commands',
            'command_injection': 'Command injection allows attackers to execute arbitrary system commands',
            'xss': 'Cross-site scripting vulnerability allows injection of malicious scripts',
            'path_traversal': 'Path traversal vulnerability allows access to files outside intended directory',
            'deserialization': 'Insecure deserialization can lead to remote code execution',
            'hardcoded_secrets': 'Hardcoded credentials pose security risks if code is exposed',
            'weak_crypto': 'Weak cryptographic algorithms are vulnerable to attacks',
            'prototype_pollution': 'Prototype pollution can lead to property injection attacks',
        }
        return descriptions.get(vuln_type, 'Security vulnerability detected')
    
    def _get_recommendation(self, vuln_type: str) -> str:
        """Get recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'command_injection': 'Validate and sanitize all user input, use safe APIs',
            'xss': 'Encode output, validate input, use Content Security Policy',
            'path_traversal': 'Validate file paths, use allowlists for permitted files',
            'deserialization': 'Avoid deserializing untrusted data, use safe serialization formats',
            'hardcoded_secrets': 'Use environment variables or secure configuration management',
            'weak_crypto': 'Use strong cryptographic algorithms (SHA-256, AES-256)',
            'prototype_pollution': 'Validate object properties, use Map instead of objects',
        }
        return recommendations.get(vuln_type, 'Review and fix the security issue')
    
    def _semgrep_analysis(self, code_path: str) -> List[Dict[str, Any]]:
        """Semgrep-based analysis"""
        vulnerabilities = []
        
        try:
            # Run Semgrep with security rules
            result = subprocess.run([
                'semgrep', '--config=auto', '--json', '--quiet', code_path
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                semgrep_output = json.loads(result.stdout)
                
                for finding in semgrep_output.get('results', []):
                    vulnerabilities.append({
                        "type": "Semgrep Finding",
                        "severity": finding.get('extra', {}).get('severity', 'medium'),
                        "file": finding.get('path', ''),
                        "line": finding.get('start', {}).get('line', 0),
                        "rule_id": finding.get('check_id', ''),
                        "message": finding.get('extra', {}).get('message', ''),
                        "code": finding.get('extra', {}).get('lines', ''),
                        "tool": "semgrep"
                    })
        
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass
        
        return vulnerabilities
    
    def _calculate_metrics(self, code_path: str) -> Dict[str, Any]:
        """Calculate code metrics"""
        metrics = {
            "total_files": 0,
            "total_lines": 0,
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
            "complexity_score": 0
        }
        
        if os.path.isfile(code_path):
            files_to_analyze = [code_path]
        else:
            files_to_analyze = []
            for root, dirs, files in os.walk(code_path):
                for file in files:
                    if any(file.endswith(ext) for ext in ['.py', '.js', '.java', '.cpp', '.c']):
                        files_to_analyze.append(os.path.join(root, file))
        
        metrics["total_files"] = len(files_to_analyze)
        
        for file_path in files_to_analyze:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = f.readlines()
                
                metrics["total_lines"] += len(lines)
                
                for line in lines:
                    stripped = line.strip()
                    if not stripped:
                        metrics["blank_lines"] += 1
                    elif stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*'):
                        metrics["comment_lines"] += 1
                    else:
                        metrics["code_lines"] += 1
                        
                        # Simple complexity calculation
                        complexity_keywords = ['if', 'else', 'elif', 'for', 'while', 'try', 'except', 'catch']
                        for keyword in complexity_keywords:
                            if keyword in stripped:
                                metrics["complexity_score"] += 1
            
            except Exception:
                continue
        
        return metrics
    
    def scan_repository(self, repo_path: str) -> Dict[str, Any]:
        """Scan entire repository for vulnerabilities"""
        if not os.path.exists(repo_path):
            return {"error": f"Repository path not found: {repo_path}"}
        
        results = {
            "repository_path": repo_path,
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_files_scanned": 0,
                "vulnerabilities_found": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
                "low_issues": 0
            },
            "vulnerabilities": [],
            "file_analysis": {}
        }
        
        # Detect languages in repository
        languages = set()
        code_files = []
        
        for root, dirs, files in os.walk(repo_path):
            # Skip common non-code directories
            dirs[:] = [d for d in dirs if d not in ['.git', 'node_modules', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                file_path = os.path.join(root, file)
                language = self._detect_language(file_path)
                if language != 'unknown':
                    languages.add(language)
                    code_files.append((file_path, language))
        
        results["summary"]["total_files_scanned"] = len(code_files)
        
        # Analyze each file
        for file_path, language in code_files:
            file_analysis = self.analyze_code(file_path, language)
            
            if "vulnerabilities" in file_analysis:
                results["vulnerabilities"].extend(file_analysis["vulnerabilities"])
                results["file_analysis"][file_path] = {
                    "language": language,
                    "vulnerability_count": len(file_analysis["vulnerabilities"]),
                    "metrics": file_analysis.get("metrics", {})
                }
        
        # Calculate summary statistics
        results["summary"]["vulnerabilities_found"] = len(results["vulnerabilities"])
        
        for vuln in results["vulnerabilities"]:
            severity = vuln.get("severity", "low")
            if severity == "critical":
                results["summary"]["critical_issues"] += 1
            elif severity == "high":
                results["summary"]["high_issues"] += 1
            elif severity == "medium":
                results["summary"]["medium_issues"] += 1
            else:
                results["summary"]["low_issues"] += 1
        
        return results
    
    def generate_security_report(self, analysis_results: Dict[str, Any]) -> str:
        """Generate human-readable security report"""
        report = []
        report.append("# Security Analysis Report")
        report.append(f"Generated: {analysis_results.get('timestamp', 'Unknown')}")
        report.append("")
        
        # Summary
        if "summary" in analysis_results:
            summary = analysis_results["summary"]
            report.append("## Summary")
            report.append(f"- Files Scanned: {summary.get('total_files_scanned', 0)}")
            report.append(f"- Vulnerabilities Found: {summary.get('vulnerabilities_found', 0)}")
            report.append(f"- Critical Issues: {summary.get('critical_issues', 0)}")
            report.append(f"- High Issues: {summary.get('high_issues', 0)}")
            report.append(f"- Medium Issues: {summary.get('medium_issues', 0)}")
            report.append(f"- Low Issues: {summary.get('low_issues', 0)}")
            report.append("")
        
        # Vulnerabilities
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        if vulnerabilities:
            report.append("## Vulnerabilities")
            
            # Group by severity
            by_severity = {}
            for vuln in vulnerabilities:
                severity = vuln.get("severity", "low")
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(vuln)
            
            for severity in ["critical", "high", "medium", "low"]:
                if severity in by_severity:
                    report.append(f"### {severity.title()} Severity")
                    for vuln in by_severity[severity]:
                        report.append(f"- **{vuln.get('type', 'Unknown')}** in {vuln.get('file', 'Unknown file')}")
                        report.append(f"  - Line: {vuln.get('line', 'Unknown')}")
                        report.append(f"  - Description: {vuln.get('description', 'No description')}")
                        report.append(f"  - Recommendation: {vuln.get('recommendation', 'No recommendation')}")
                        report.append("")
        
        return "\n".join(report)

# Utility functions for compatibility with existing agents
def analyze_code_file(file_path: str, language: str = None) -> Dict[str, Any]:
    """Analyze single code file"""
    analyzer = CodeAnalyzer()
    return analyzer.analyze_code(file_path, language)

def scan_code_repository(repo_path: str) -> Dict[str, Any]:
    """Scan entire code repository"""
    analyzer = CodeAnalyzer()
    return analyzer.scan_repository(repo_path)

def generate_report(analysis_results: Dict[str, Any]) -> str:
    """Generate security report"""
    analyzer = CodeAnalyzer()
    return analyzer.generate_security_report(analysis_results)