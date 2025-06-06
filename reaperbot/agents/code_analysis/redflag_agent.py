import asyncio
import json
import re
from typing import Dict, Any, List, Optional
from pathlib import Path
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings
from pydantic import BaseModel, Field
from dotenv import load_dotenv

from utils.logging import send_log_message

load_dotenv()

class ReviewResult(BaseModel):
    """RedFlag review result model"""
    result: bool = Field(description="True if PR should be reviewed, otherwise false")
    reasoning: str = Field(description="Step-by-step reasoning for the decision")
    files: List[str] = Field(description="Files that contain code requiring review")
    risk_level: str = Field(description="Risk level: Critical, High, Medium, Low")
    security_concerns: List[str] = Field(description="Specific security concerns identified")

class TestPlan(BaseModel):
    """RedFlag test plan model"""
    test_plan: str = Field(description="The security test plan created")
    reasoning: str = Field(description="Reasoning for the test plan")
    test_categories: List[str] = Field(description="Categories of security tests to perform")

class RedFlagAnalyzer:
    """RedFlag code analysis functionality"""
    
    def __init__(self):
        """Initialize RedFlag analyzer with security patterns"""
        self.high_risk_patterns = {
            # Authentication and Authorization
            'auth_patterns': [
                r'(login|authenticate|authorize|permission|role|admin)',
                r'(jwt|token|session|cookie|auth)',
                r'(password|credential|secret|key)',
                r'(oauth|saml|ldap|active.?directory)'
            ],
            
            # Input Validation and Injection
            'injection_patterns': [
                r'(sql|query|execute|prepare)',
                r'(eval|exec|system|shell|command)',
                r'(input|param|request|form|user)',
                r'(sanitize|validate|escape|filter)'
            ],
            
            # Cryptography
            'crypto_patterns': [
                r'(encrypt|decrypt|hash|crypto|cipher)',
                r'(aes|rsa|sha|md5|bcrypt|scrypt)',
                r'(random|entropy|nonce|salt)',
                r'(certificate|tls|ssl|https)'
            ],
            
            # File and Network Operations
            'file_network_patterns': [
                r'(file|path|directory|upload|download)',
                r'(http|url|request|response|api)',
                r'(socket|network|connection|proxy)',
                r'(cors|csrf|xss|header)'
            ],
            
            # Dangerous Functions
            'dangerous_functions': [
                r'(eval|exec|system|shell_exec|passthru)',
                r'(unserialize|pickle|yaml\.load)',
                r'(innerHTML|document\.write|eval)',
                r'(strcpy|strcat|sprintf|gets)'
            ]
        }
        
        self.security_keywords = [
            'security', 'vulnerability', 'exploit', 'attack', 'malicious',
            'injection', 'xss', 'csrf', 'sqli', 'rce', 'lfi', 'rfi',
            'privilege', 'escalation', 'bypass', 'authentication',
            'authorization', 'access', 'control', 'permission'
        ]
    
    def analyze_file_for_security_risks(self, file_path: str) -> Dict[str, Any]:
        """Analyze a single file for security risks"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            risks = {
                'file_path': file_path,
                'risk_level': 'Low',
                'security_concerns': [],
                'pattern_matches': {},
                'line_count': len(content.split('\n')),
                'requires_review': False
            }
            
            # Check each pattern category
            total_matches = 0
            for category, patterns in self.high_risk_patterns.items():
                matches = []
                for pattern in patterns:
                    pattern_matches = re.finditer(pattern, content, re.IGNORECASE)
                    for match in pattern_matches:
                        line_num = content[:match.start()].count('\n') + 1
                        matches.append({
                            'pattern': pattern,
                            'match': match.group(),
                            'line': line_num,
                            'context': self._get_line_context(content, line_num)
                        })
                
                if matches:
                    risks['pattern_matches'][category] = matches
                    total_matches += len(matches)
            
            # Determine risk level based on matches
            if total_matches >= 10:
                risks['risk_level'] = 'Critical'
                risks['requires_review'] = True
            elif total_matches >= 5:
                risks['risk_level'] = 'High'
                risks['requires_review'] = True
            elif total_matches >= 2:
                risks['risk_level'] = 'Medium'
                risks['requires_review'] = True
            
            # Generate security concerns
            risks['security_concerns'] = self._generate_security_concerns(risks['pattern_matches'])
            
            return risks
            
        except Exception as e:
            return {
                'file_path': file_path,
                'error': str(e),
                'risk_level': 'Unknown',
                'requires_review': False
            }
    
    def _get_line_context(self, content: str, line_num: int, context_lines: int = 2) -> str:
        """Get context around a specific line"""
        lines = content.split('\n')
        start = max(0, line_num - context_lines - 1)
        end = min(len(lines), line_num + context_lines)
        
        context = []
        for i in range(start, end):
            prefix = ">>> " if i == line_num - 1 else "    "
            context.append(f"{prefix}{i+1}: {lines[i]}")
        
        return '\n'.join(context)
    
    def _generate_security_concerns(self, pattern_matches: Dict[str, List]) -> List[str]:
        """Generate human-readable security concerns from pattern matches"""
        concerns = []
        
        if 'auth_patterns' in pattern_matches:
            concerns.append("Authentication/authorization code detected - review for access control vulnerabilities")
        
        if 'injection_patterns' in pattern_matches:
            concerns.append("Potential injection vulnerabilities - review input validation and sanitization")
        
        if 'crypto_patterns' in pattern_matches:
            concerns.append("Cryptographic operations detected - review for weak algorithms and implementation flaws")
        
        if 'file_network_patterns' in pattern_matches:
            concerns.append("File/network operations detected - review for path traversal and SSRF vulnerabilities")
        
        if 'dangerous_functions' in pattern_matches:
            concerns.append("Dangerous functions detected - review for code injection and RCE vulnerabilities")
        
        return concerns
    
    def analyze_code_changes(self, diff_content: str, file_paths: List[str]) -> Dict[str, Any]:
        """Analyze code changes for security implications"""
        analysis = {
            'high_risk_files': [],
            'security_concerns': [],
            'risk_level': 'Low',
            'patterns_found': {},
            'recommendations': []
        }
        
        # Analyze diff content
        added_lines = []
        removed_lines = []
        
        for line in diff_content.split('\n'):
            if line.startswith('+') and not line.startswith('+++'):
                added_lines.append(line[1:].strip())
            elif line.startswith('-') and not line.startswith('---'):
                removed_lines.append(line[1:].strip())
        
        # Check for high-risk patterns in added code
        for category, patterns in self.high_risk_patterns.items():
            found_patterns = []
            for pattern in patterns:
                for line in added_lines:
                    if re.search(pattern, line, re.IGNORECASE):
                        found_patterns.append(line)
            
            if found_patterns:
                analysis['patterns_found'][category] = found_patterns
        
        # Assess risk level based on patterns found
        risk_score = 0
        
        if analysis['patterns_found'].get('auth_patterns'):
            risk_score += 3
            analysis['security_concerns'].append("Authentication/Authorization changes detected")
        
        if analysis['patterns_found'].get('injection_patterns'):
            risk_score += 3
            analysis['security_concerns'].append("Potential injection vulnerability patterns")
        
        if analysis['patterns_found'].get('crypto_patterns'):
            risk_score += 2
            analysis['security_concerns'].append("Cryptographic implementation changes")
        
        if analysis['patterns_found'].get('dangerous_functions'):
            risk_score += 4
            analysis['security_concerns'].append("Dangerous function usage detected")
        
        # Check for security-related keywords
        security_mentions = 0
        for line in added_lines + removed_lines:
            for keyword in self.security_keywords:
                if keyword in line.lower():
                    security_mentions += 1
                    break
        
        if security_mentions > 0:
            risk_score += 1
            analysis['security_concerns'].append(f"Security-related keywords found ({security_mentions} mentions)")
        
        # Determine risk level
        if risk_score >= 6:
            analysis['risk_level'] = 'Critical'
        elif risk_score >= 4:
            analysis['risk_level'] = 'High'
        elif risk_score >= 2:
            analysis['risk_level'] = 'Medium'
        else:
            analysis['risk_level'] = 'Low'
        
        # Identify high-risk files
        for file_path in file_paths:
            file_ext = Path(file_path).suffix.lower()
            if file_ext in ['.py', '.js', '.php', '.java', '.c', '.cpp', '.go', '.rb']:
                if any(pattern in analysis['patterns_found'] for pattern in analysis['patterns_found']):
                    analysis['high_risk_files'].append(file_path)
        
        return analysis
    
    def generate_test_plan(self, analysis_result: Dict[str, Any], code_changes: str) -> Dict[str, Any]:
        """Generate security test plan based on analysis"""
        test_plan = {
            'categories': [],
            'specific_tests': [],
            'tools_recommended': [],
            'manual_review_areas': []
        }
        
        patterns_found = analysis_result.get('patterns_found', {})
        
        # Authentication/Authorization testing
        if patterns_found.get('auth_patterns'):
            test_plan['categories'].append('Authentication & Authorization Testing')
            test_plan['specific_tests'].extend([
                'Test authentication bypass attempts',
                'Verify authorization controls',
                'Test session management',
                'Check for privilege escalation'
            ])
            test_plan['tools_recommended'].append('Burp Suite Authentication Tester')
        
        # Injection testing
        if patterns_found.get('injection_patterns'):
            test_plan['categories'].append('Injection Vulnerability Testing')
            test_plan['specific_tests'].extend([
                'SQL injection testing',
                'Command injection testing',
                'LDAP injection testing',
                'XPath injection testing'
            ])
            test_plan['tools_recommended'].extend(['SQLMap', 'Commix', 'NoSQLMap'])
        
        # Cryptography testing
        if patterns_found.get('crypto_patterns'):
            test_plan['categories'].append('Cryptographic Implementation Review')
            test_plan['specific_tests'].extend([
                'Verify encryption algorithms',
                'Test key management',
                'Check random number generation',
                'Validate certificate handling'
            ])
            test_plan['manual_review_areas'].append('Cryptographic implementation review')
        
        # File/Network testing
        if patterns_found.get('file_network_patterns'):
            test_plan['categories'].append('File & Network Security Testing')
            test_plan['specific_tests'].extend([
                'File upload security testing',
                'Path traversal testing',
                'CORS configuration testing',
                'HTTP header security testing'
            ])
            test_plan['tools_recommended'].extend(['Nikto', 'DirBuster', 'CORS Scanner'])
        
        # Dangerous functions
        if patterns_found.get('dangerous_functions'):
            test_plan['categories'].append('Code Execution Vulnerability Testing')
            test_plan['specific_tests'].extend([
                'Remote code execution testing',
                'Local file inclusion testing',
                'Deserialization vulnerability testing',
                'Buffer overflow testing'
            ])
            test_plan['manual_review_areas'].append('Manual code review for dangerous functions')
        
        return test_plan

# Initialize analyzer
analyzer = RedFlagAnalyzer()

model_settings = ModelSettings(temperature=0.01, max_tokens=16384)
redflag_agent = Agent(
    'openai:gpt-4o-mini',
    result_type=str,
    model_settings=model_settings,
    system_prompt="""
    You are a specialized AI-powered Code Security Review agent based on RedFlag methodology.
    Your expertise covers identifying high-risk code changes that require security review using advanced pattern analysis:
    
    1. **RedFlag High-Risk Code Patterns**:
       - Authentication and authorization changes with pattern matching
       - Cryptographic implementations and key management
       - Input validation modifications and injection risks
       - Database query construction and parameterization
       - File system operations and path traversal risks
       - Network communication code and CORS/CSRF issues
       - Privilege escalation opportunities and access controls
    
    2. **Security-Critical Areas Analysis**:
       - User input handling and sanitization patterns
       - SQL query construction and parameterization analysis
       - Cross-site scripting (XSS) prevention mechanisms
       - Cross-site request forgery (CSRF) protection
       - Session management implementations
       - Access control mechanisms and authorization flows
       - Error handling and information disclosure risks
    
    3. **RedFlag Code Change Analysis**:
       - Diff analysis for security implications using regex patterns
       - New vulnerability introduction detection
       - Security control removal identification
       - Dangerous function usage introduction
       - Configuration changes with security impact
       - Risk scoring based on pattern matching
    
    **RedFlag Analysis Strategy:**
    - Use pattern matching to identify security-relevant code changes
    - Analyze git diffs for high-risk modifications
    - Score risk levels based on security pattern detection
    - Flag changes that require manual security review
    - Generate targeted security test plans
    - Assess risk level based on change context and scope
    
    **Risk Assessment Criteria:**
    - Pattern-based security risk scoring
    - Scope and impact of code changes
    - Security-sensitive areas affected
    - Introduction of new attack surfaces
    - Removal or modification of security controls
    - Dangerous function usage patterns
    
    **RedFlag Focus Areas:**
    - Authentication/authorization pattern detection
    - Input validation and injection risk analysis
    - Cryptographic implementation changes
    - File/network operation security risks
    - Dangerous function usage identification
    - Security keyword and context analysis
    
    **Output Requirements:**
    - Risk level assessment (Critical, High, Medium, Low) based on scoring
    - Specific security concerns identified through pattern matching
    - Targeted security testing approaches
    - Manual review requirements and focus areas
    - Potential vulnerability categories to test
    
    If high-risk code changes are found, provide:
    - Detailed risk assessment with severity level and scoring
    - Specific security concerns and potential vulnerabilities
    - Pattern-based evidence for security risks
    - Recommended security testing strategies
    - Manual review requirements and focus areas
    - Suggested security controls to verify
    
    If no high-risk changes are detected, respond with "No high-risk security changes detected in code review."
    """,
    retries=2,
)

@redflag_agent.tool
async def analyze_code_diff(diff_content: str, file_paths: list) -> str:
    """
    Analyze code diff for security-relevant changes using RedFlag methodology.
    
    Args:
        diff_content: The git diff content to analyze
        file_paths: List of file paths that were modified
    """
    await send_log_message(f"RedFlag Agent: Analyzing code diff for {len(file_paths)} files")
    
    try:
        # Perform RedFlag analysis
        analysis = analyzer.analyze_code_changes(diff_content, file_paths)
        
        result = f"RedFlag Code Diff Analysis:\n\n"
        result += f"Files Analyzed: {len(file_paths)}\n"
        result += f"Risk Level: {analysis['risk_level']}\n"
        result += f"High-Risk Files: {len(analysis['high_risk_files'])}\n\n"
        
        if analysis['security_concerns']:
            result += "SECURITY CONCERNS IDENTIFIED:\n"
            for concern in analysis['security_concerns']:
                result += f"⚠️  {concern}\n"
            result += "\n"
        
        if analysis['patterns_found']:
            result += "SECURITY PATTERNS DETECTED:\n"
            for category, patterns in analysis['patterns_found'].items():
                result += f"\n{category.replace('_', ' ').title()}:\n"
                for pattern in patterns[:3]:  # Show first 3 matches
                    result += f"  - {pattern}\n"
            result += "\n"
        
        if analysis['high_risk_files']:
            result += "HIGH-RISK FILES REQUIRING REVIEW:\n"
            for file_path in analysis['high_risk_files']:
                result += f"📁 {file_path}\n"
            result += "\n"
        
        # Generate recommendations
        if analysis['risk_level'] in ['Critical', 'High']:
            result += "IMMEDIATE ACTIONS REQUIRED:\n"
            result += "✅ Manual security review required\n"
            result += "✅ Security testing before deployment\n"
            result += "✅ Senior security engineer approval needed\n"
        elif analysis['risk_level'] == 'Medium':
            result += "RECOMMENDED ACTIONS:\n"
            result += "⚠️  Security review recommended\n"
            result += "⚠️  Automated security testing\n"
        
        return result
        
    except Exception as e:
        return f"RedFlag code diff analysis failed: {str(e)}"

@redflag_agent.tool
async def assess_security_risk(code_changes: str, change_context: str) -> str:
    """
    Assess security risk level of code changes using RedFlag scoring.
    
    Args:
        code_changes: The specific code changes to assess
        change_context: Context about the changes (commit message, PR description, etc.)
    """
    await send_log_message(f"RedFlag Agent: Assessing security risk for code changes")
    
    try:
        # Analyze the code changes
        analysis = analyzer.analyze_code_changes(code_changes, [])
        
        # Analyze context for additional risk indicators
        context_risk_score = 0
        context_lower = change_context.lower()
        
        high_risk_context_keywords = [
            'security', 'auth', 'login', 'password', 'token', 'crypto',
            'admin', 'privilege', 'permission', 'access', 'vulnerability'
        ]
        
        for keyword in high_risk_context_keywords:
            if keyword in context_lower:
                context_risk_score += 1
        
        result = f"RedFlag Security Risk Assessment:\n\n"
        result += f"Risk Level: {analysis['risk_level']}\n"
        result += f"Context Risk Indicators: {context_risk_score}\n\n"
        
        if analysis['security_concerns']:
            result += "IDENTIFIED SECURITY RISKS:\n"
            for i, concern in enumerate(analysis['security_concerns'], 1):
                result += f"{i}. {concern}\n"
            result += "\n"
        
        # Risk justification
        result += "RISK ASSESSMENT JUSTIFICATION:\n"
        if analysis['patterns_found']:
            result += f"• Security patterns detected in {len(analysis['patterns_found'])} categories\n"
        if context_risk_score > 0:
            result += f"• Security-related context keywords found ({context_risk_score})\n"
        
        # Recommendations based on risk level
        if analysis['risk_level'] == 'Critical':
            result += "\n🚨 CRITICAL RISK - IMMEDIATE ACTION REQUIRED:\n"
            result += "• Mandatory security review by senior engineer\n"
            result += "• Comprehensive security testing required\n"
            result += "• Consider security architecture review\n"
        elif analysis['risk_level'] == 'High':
            result += "\n⚠️  HIGH RISK - SECURITY REVIEW REQUIRED:\n"
            result += "• Security team review recommended\n"
            result += "• Targeted security testing needed\n"
            result += "• Additional approval required\n"
        elif analysis['risk_level'] == 'Medium':
            result += "\n⚡ MEDIUM RISK - ENHANCED TESTING RECOMMENDED:\n"
            result += "• Automated security scanning\n"
            result += "• Peer review with security focus\n"
        else:
            result += "\n✅ LOW RISK - STANDARD PROCESS:\n"
            result += "• Normal code review process\n"
            result += "• Standard testing procedures\n"
        
        return result
        
    except Exception as e:
        return f"Security risk assessment failed: {str(e)}"

@redflag_agent.tool
async def identify_security_patterns(code_content: str, language: str) -> str:
    """
    Identify security-relevant patterns in code using RedFlag pattern matching.
    
    Args:
        code_content: The code content to analyze
        language: Programming language of the code
    """
    await send_log_message(f"RedFlag Agent: Identifying security patterns in {language} code")
    
    try:
        # Analyze code for security patterns
        analysis = analyzer.analyze_code_changes(code_content, [])
        
        result = f"RedFlag Security Pattern Analysis ({language}):\n\n"
        
        if analysis['patterns_found']:
            result += "SECURITY PATTERNS DETECTED:\n\n"
            
            for category, patterns in analysis['patterns_found'].items():
                category_name = category.replace('_', ' ').title()
                result += f"{category_name}:\n"
                
                for pattern in patterns[:5]:  # Show first 5 matches
                    result += f"  🔍 {pattern}\n"
                result += "\n"
        else:
            result += "No obvious security patterns detected.\n\n"
        
        # Language-specific recommendations
        language_recommendations = {
            'python': [
                'Use parameterized queries for database operations',
                'Avoid eval() and exec() functions',
                'Validate all user inputs',
                'Use secure random number generation'
            ],
            'javascript': [
                'Sanitize DOM manipulation',
                'Avoid innerHTML with user data',
                'Use Content Security Policy',
                'Validate all API inputs'
            ],
            'java': [
                'Use PreparedStatement for SQL queries',
                'Avoid Runtime.exec() with user input',
                'Implement proper access controls',
                'Use secure cryptographic libraries'
            ],
            'php': [
                'Use prepared statements',
                'Avoid eval() and system() functions',
                'Sanitize file operations',
                'Implement CSRF protection'
            ]
        }
        
        if language.lower() in language_recommendations:
            result += f"LANGUAGE-SPECIFIC SECURITY RECOMMENDATIONS ({language}):\n"
            for rec in language_recommendations[language.lower()]:
                result += f"• {rec}\n"
        
        return result
        
    except Exception as e:
        return f"Security pattern identification failed: {str(e)}"

@redflag_agent.tool
async def generate_security_test_plan(risk_areas: list, code_changes: str) -> str:
    """
    Generate a security testing plan based on identified risks using RedFlag methodology.
    
    Args:
        risk_areas: List of identified security risk areas
        code_changes: The code changes that introduced risks
    """
    await send_log_message(f"RedFlag Agent: Generating security test plan for {len(risk_areas)} risk areas")
    
    try:
        # Analyze code changes to understand context
        analysis = analyzer.analyze_code_changes(code_changes, [])
        
        # Generate test plan based on analysis
        test_plan = analyzer.generate_test_plan(analysis, code_changes)
        
        result = f"RedFlag Security Test Plan:\n\n"
        result += f"Risk Areas Identified: {len(risk_areas)}\n"
        result += f"Test Categories: {len(test_plan['categories'])}\n\n"
        
        if test_plan['categories']:
            result += "SECURITY TESTING CATEGORIES:\n"
            for i, category in enumerate(test_plan['categories'], 1):
                result += f"{i}. {category}\n"
            result += "\n"
        
        if test_plan['specific_tests']:
            result += "SPECIFIC SECURITY TESTS:\n"
            for test in test_plan['specific_tests']:
                result += f"🧪 {test}\n"
            result += "\n"
        
        if test_plan['tools_recommended']:
            result += "RECOMMENDED SECURITY TOOLS:\n"
            for tool in test_plan['tools_recommended']:
                result += f"🔧 {tool}\n"
            result += "\n"
        
        if test_plan['manual_review_areas']:
            result += "MANUAL REVIEW AREAS:\n"
            for area in test_plan['manual_review_areas']:
                result += f"👁️  {area}\n"
            result += "\n"
        
        # Test execution priority
        result += "TEST EXECUTION PRIORITY:\n"
        if analysis['risk_level'] in ['Critical', 'High']:
            result += "1. 🚨 IMMEDIATE: Manual security review\n"
            result += "2. 🔥 HIGH: Automated vulnerability scanning\n"
            result += "3. ⚡ MEDIUM: Penetration testing\n"
            result += "4. 📋 LOW: Code quality analysis\n"
        else:
            result += "1. 🔍 Automated security scanning\n"
            result += "2. 📋 Code review with security focus\n"
            result += "3. 🧪 Targeted security testing\n"
        
        return result
        
    except Exception as e:
        return f"Security test plan generation failed: {str(e)}"

@redflag_agent.tool
async def review_pull_request(pr_title: str, pr_description: str, file_changes: list, diff_content: str) -> str:
    """
    Perform comprehensive RedFlag security review of a pull request.
    
    Args:
        pr_title: Title of the pull request
        pr_description: Description of the pull request
        file_changes: List of changed files
        diff_content: Git diff content
    """
    await send_log_message(f"RedFlag Agent: Reviewing pull request with {len(file_changes)} changed files")
    
    try:
        # Analyze the pull request
        analysis = analyzer.analyze_code_changes(diff_content, file_changes)
        
        # Analyze PR context
        context = f"{pr_title} {pr_description}"
        context_analysis = analyzer.analyze_code_changes("", [])  # Just for context keywords
        
        result = f"RedFlag Pull Request Security Review:\n\n"
        result += f"PR Title: {pr_title}\n"
        result += f"Files Changed: {len(file_changes)}\n"
        result += f"Overall Risk Level: {analysis['risk_level']}\n\n"
        
        # Review decision
        should_review = analysis['risk_level'] in ['Critical', 'High', 'Medium']
        
        result += f"REVIEW DECISION: {'REQUIRED' if should_review else 'OPTIONAL'}\n\n"
        
        if should_review:
            result += "SECURITY REVIEW REQUIRED BECAUSE:\n"
            for concern in analysis['security_concerns']:
                result += f"• {concern}\n"
            result += "\n"
            
            if analysis['high_risk_files']:
                result += "FILES REQUIRING SECURITY REVIEW:\n"
                for file_path in analysis['high_risk_files']:
                    result += f"📁 {file_path}\n"
                result += "\n"
        
        # Security patterns found
        if analysis['patterns_found']:
            result += "SECURITY PATTERNS DETECTED:\n"
            for category, patterns in analysis['patterns_found'].items():
                result += f"\n{category.replace('_', ' ').title()}:\n"
                for pattern in patterns[:2]:  # Show first 2 matches
                    result += f"  - {pattern}\n"
            result += "\n"
        
        # Recommendations
        result += "RECOMMENDATIONS:\n"
        if analysis['risk_level'] == 'Critical':
            result += "🚨 CRITICAL: Security architect review required\n"
            result += "🚨 CRITICAL: Comprehensive security testing mandatory\n"
            result += "🚨 CRITICAL: Consider security design review\n"
        elif analysis['risk_level'] == 'High':
            result += "⚠️  HIGH: Security team review required\n"
            result += "⚠️  HIGH: Targeted security testing needed\n"
            result += "⚠️  HIGH: Additional approval required\n"
        elif analysis['risk_level'] == 'Medium':
            result += "⚡ MEDIUM: Security-focused code review\n"
            result += "⚡ MEDIUM: Automated security scanning\n"
        else:
            result += "✅ LOW: Standard review process sufficient\n"
        
        return result
        
    except Exception as e:
        return f"Pull request security review failed: {str(e)}"