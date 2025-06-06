import asyncio
import subprocess
import os
import tempfile
from typing import Dict, Any, List, Optional
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings
from pydantic import BaseModel
from dotenv import load_dotenv
from clang.cindex import Index, CursorKind
import re

from utils.logging import send_log_message

load_dotenv()

# Memory vulnerability patterns
MEMORY_VULN_PATTERNS = {
    'buffer_overflow': [
        r'strcpy\s*\(',
        r'strcat\s*\(',
        r'sprintf\s*\(',
        r'gets\s*\(',
        r'scanf\s*\([^,]*,\s*[^,]*\)',
        r'memcpy\s*\([^,]*,\s*[^,]*,\s*[^)]*\)',
    ],
    'format_string': [
        r'printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
        r'fprintf\s*\(\s*[^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
        r'sprintf\s*\(\s*[^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
        r'snprintf\s*\(\s*[^,]+,\s*[^,]+,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',
    ],
    'use_after_free': [
        r'free\s*\([^)]+\)',
        r'delete\s+[^;]+',
    ],
    'double_free': [
        r'free\s*\([^)]+\).*?free\s*\(',
        r'delete\s+[^;]+;.*?delete\s+',
    ],
    'null_pointer_dereference': [
        r'malloc\s*\([^)]+\)\s*;[^}]*\*',
        r'calloc\s*\([^)]+\)\s*;[^}]*\*',
        r'realloc\s*\([^)]+\)\s*;[^}]*\*',
    ],
    'integer_overflow': [
        r'malloc\s*\(\s*[^)]*\*[^)]*\)',
        r'calloc\s*\(\s*[^,]*\*[^,]*,',
        r'new\s+[^[]*\[[^]]*\*[^]]*\]',
    ]
}

class MemoryAnalysisResult(BaseModel):
    """Result of memory corruption analysis from Baby Naptime"""
    file_path: str
    function_name: Optional[str] = None
    vulnerability_type: str
    memory_layout: Dict[str, Any]
    corruption_details: List[str]
    exploitation_potential: str
    recommendations: List[str]

class MemoryAnalyzer:
    """Memory analysis functionality from Baby Naptime with libclang integration"""
    
    def __init__(self):
        """Initialize memory analyzer with clang and GDB"""
        self.index = Index.create()
        try:
            subprocess.run(['gdb', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("GDB not found - required for memory analysis")
    
    def get_function_body(self, filename: str, function_name: str) -> Dict:
        """Extract function body using libclang for analysis"""
        if not filename.endswith('.c') and not filename.endswith('.cpp') and not filename.endswith('.h'):
            raise ValueError("Only .c, .cpp and .h files are supported")
        
        if not os.path.exists(filename):
            raise FileNotFoundError(f"File not found: {filename}")

        # For .h files, return the full file
        if filename.endswith('.h'):
            with open(filename, 'r') as f:
                file_lines = f.readlines()
            numbered_lines = [
                f"{i+1}: {line.rstrip()}" 
                for i, line in enumerate(file_lines)
            ]
            return {
                'filename': filename,
                'name': function_name,
                'type': 'header',
                'source': '\n'.join(numbered_lines),
                'lines': [line.strip() for line in file_lines if line.strip()]
            }

        # Parse the source file
        tu = self.index.parse(filename, args=['-x', 'c++'])
        if not tu:
            raise ValueError(f"Failed to parse {filename}")

        # Find the target function
        function_node = None
        for node in tu.cursor.walk_preorder():
            if (node.kind == CursorKind.FUNCTION_DECL and 
                node.spelling == function_name):
                function_node = node
                break

        if not function_node:
            raise ValueError(f"Function '{function_name}' not found in {filename}")

        # Get the function's source range
        start = function_node.extent.start
        end = function_node.extent.end
        
        # Read the original file to get the complete source
        with open(filename, 'r') as f:
            file_lines = f.readlines()

        # Extract function lines with line numbers
        function_lines = file_lines[start.line-1:end.line]
        numbered_lines = [
            f"{i+start.line}: {line.rstrip()}"
            for i, line in enumerate(function_lines)
        ]

        return {
            'filename': filename,
            'name': function_name,
            'type': 'function',
            'source': '\n'.join(numbered_lines),
            'lines': [line.strip() for line in function_lines if line.strip()],
            'start_line': start.line,
            'end_line': end.line
        }
    
    def detect_memory_vulnerabilities(self, file_path: str) -> List[Dict[str, Any]]:
        """Detect memory vulnerabilities using pattern matching"""
        vulnerabilities = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
            
            for vuln_type, patterns in MEMORY_VULN_PATTERNS.items():
                for pattern in patterns:
                    for line_num, line in enumerate(lines, 1):
                        matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in matches:
                            vuln = {
                                'type': vuln_type,
                                'location': f"{file_path}:{line_num}",
                                'line': line.strip(),
                                'description': self._get_vuln_description(vuln_type),
                                'severity': self._get_vuln_severity(vuln_type),
                                'mitigation': self._get_vuln_mitigation(vuln_type),
                                'confidence': self._calculate_confidence(pattern, line, vuln_type)
                            }
                            vulnerabilities.append(vuln)
            
            return vulnerabilities
            
        except Exception as e:
            return []
    
    def _get_vuln_description(self, vuln_type: str) -> str:
        descriptions = {
            'buffer_overflow': 'Buffer overflow vulnerability - writing beyond allocated memory boundaries',
            'format_string': 'Format string vulnerability - user input used as format string',
            'use_after_free': 'Use-after-free vulnerability - accessing freed memory',
            'double_free': 'Double-free vulnerability - freeing memory twice',
            'null_pointer_dereference': 'Null pointer dereference - accessing null pointer',
            'integer_overflow': 'Integer overflow in memory allocation'
        }
        return descriptions.get(vuln_type, 'Memory corruption vulnerability')
    
    def _get_vuln_severity(self, vuln_type: str) -> str:
        severity_map = {
            'buffer_overflow': 'critical',
            'format_string': 'high',
            'use_after_free': 'critical',
            'double_free': 'high',
            'null_pointer_dereference': 'medium',
            'integer_overflow': 'high'
        }
        return severity_map.get(vuln_type, 'medium')
    
    def _get_vuln_mitigation(self, vuln_type: str) -> str:
        mitigation_map = {
            'buffer_overflow': 'Use safe string functions (strncpy, strncat), enable stack protection',
            'format_string': 'Use format strings with proper format specifiers',
            'use_after_free': 'Set pointers to NULL after free, use smart pointers',
            'double_free': 'Set pointers to NULL after free, use memory debugging tools',
            'null_pointer_dereference': 'Check return values before dereferencing',
            'integer_overflow': 'Validate input sizes, use safe allocation functions'
        }
        return mitigation_map.get(vuln_type, 'Follow secure coding practices')
    
    def _calculate_confidence(self, pattern: str, line: str, vuln_type: str) -> float:
        base_confidence = 0.7
        
        # Increase confidence for user input related code
        if any(keyword in line.lower() for keyword in ['user', 'input', 'argv', 'stdin']):
            base_confidence += 0.2
        
        # Decrease confidence for comments
        if line.strip().startswith('//') or line.strip().startswith('/*'):
            base_confidence -= 0.4
        
        # Increase confidence for specific dangerous patterns
        if vuln_type in ['buffer_overflow', 'format_string']:
            base_confidence += 0.1
        
        return min(max(base_confidence, 0.1), 1.0)
    
    def create_memory_gdb_script(self, binary_path: str, function_name: str, test_input: str) -> str:
        """Create GDB script focused on memory corruption detection"""
        script = f"""
        set verbose off
        file {binary_path}
        
        # Set up memory corruption detection
        set environment MALLOC_CHECK_=2
        set environment MALLOC_PERTURB_=165
        
        # Break at function entry
        break {function_name}
        run {test_input}
        
        # Memory layout analysis
        printf "\\n=== MEMORY LAYOUT ANALYSIS ===\\n"
        printf "Stack pointer: "
        print/x $sp
        printf "Base pointer: "
        print/x $bp
        printf "Return address: "
        x/gx $bp+8
        
        # Stack frame inspection
        printf "\\n=== STACK FRAME ===\\n"
        x/32gx $sp-64
        
        # Check for stack canaries
        printf "\\n=== STACK CANARY CHECK ===\\n"
        info symbol __stack_chk_fail
        
        # Continue execution and watch for crashes
        continue
        
        # If we reach here, check final memory state
        printf "\\n=== POST-EXECUTION MEMORY ===\\n"
        printf "Final stack pointer: "
        print/x $sp
        printf "Final base pointer: "
        print/x $bp
        
        # Check heap state if applicable
        printf "\\n=== HEAP STATE ===\\n"
        info heap
        
        quit
        """
        
        fd, path = tempfile.mkstemp(suffix='.gdb')
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        return path
    
    def analyze_memory_corruption(self, binary_path: str, function_name: str, test_inputs: List[str]) -> str:
        """Analyze memory corruption using GDB with various inputs"""
        results = []
        
        for i, test_input in enumerate(test_inputs):
            try:
                script_path = self.create_memory_gdb_script(binary_path, function_name, test_input)
                
                cmd = ['gdb', '-batch', '-x', script_path]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                os.unlink(script_path)  # Clean up
                
                # Analyze output for signs of corruption
                output = result.stdout + result.stderr
                corruption_indicators = [
                    'segmentation fault', 'sigsegv', 'sigbus', 'sigabrt',
                    'stack smashing detected', 'heap corruption', 'double free',
                    'use after free', 'buffer overflow'
                ]
                
                found_issues = []
                for indicator in corruption_indicators:
                    if indicator in output.lower():
                        found_issues.append(indicator)
                
                if found_issues:
                    results.append(f"Test {i+1} (input: '{test_input}'): CORRUPTION DETECTED - {', '.join(found_issues)}")
                    results.append(f"GDB Output:\n{output[:500]}...")
                else:
                    results.append(f"Test {i+1} (input: '{test_input}'): No corruption detected")
                    
            except subprocess.TimeoutExpired:
                results.append(f"Test {i+1} (input: '{test_input}'): TIMEOUT - possible infinite loop or hang")
            except Exception as e:
                results.append(f"Test {i+1} (input: '{test_input}'): ERROR - {str(e)}")
        
        return '\n'.join(results)
    
    def analyze_dangerous_patterns(self, source_code: str) -> List[str]:
        """Analyze source code for dangerous memory patterns"""
        dangerous_patterns = []
        lines = source_code.split('\n')
        
        # Dangerous function patterns
        dangerous_funcs = {
            'strcpy': 'Unsafe string copy - use strncpy or strlcpy',
            'strcat': 'Unsafe string concatenation - use strncat or strlcat',
            'sprintf': 'Unsafe string formatting - use snprintf',
            'vsprintf': 'Unsafe string formatting - use vsnprintf',
            'gets': 'Extremely unsafe input function - use fgets',
            'scanf': 'Unsafe input parsing - validate input length',
            'alloca': 'Stack allocation can cause overflow - use malloc',
        }
        
        # Buffer patterns
        buffer_patterns = {
            'char.*\\[.*\\]': 'Fixed-size buffer - ensure bounds checking',
            'malloc.*without.*free': 'Potential memory leak',
            'free.*without.*null': 'Potential double-free vulnerability'
        }
        
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            
            # Check for dangerous functions
            for func, warning in dangerous_funcs.items():
                if func in line_lower and '(' in line_lower:
                    dangerous_patterns.append(f"Line {i}: {warning} - {line.strip()}")
            
            # Check for potential integer overflows
            if any(op in line_lower for op in ['*', '+', '-']) and any(type_kw in line_lower for type_kw in ['int', 'size_t', 'unsigned']):
                if 'malloc' in line_lower or 'calloc' in line_lower:
                    dangerous_patterns.append(f"Line {i}: Potential integer overflow in allocation - {line.strip()}")
        
        return dangerous_patterns

# Initialize analyzer
analyzer = MemoryAnalyzer()

model_settings = ModelSettings(temperature=0.01, max_tokens=16384)
memory_agent = Agent(
    'openai:gpt-4o-mini',
    result_type=str,
    model_settings=model_settings,
    system_prompt="""
    You are a specialized Memory Corruption vulnerability detection agent using Baby Naptime methodology.
    Your expertise covers all aspects of memory safety vulnerabilities with advanced debugging capabilities:
    
    1. **Buffer Overflow Vulnerabilities**:
       - Stack-based buffer overflows with GDB stack analysis
       - Heap-based buffer overflows with heap state inspection
       - Integer overflow leading to buffer overflow
       - Off-by-one errors with precise memory boundary testing
       - Format string vulnerabilities with memory layout analysis
    
    2. **Memory Management Issues**:
       - Use-after-free vulnerabilities with heap tracking
       - Double-free vulnerabilities with allocation monitoring
       - Memory leaks and resource exhaustion
       - Uninitialized memory usage detection
       - Null pointer dereferences with crash analysis
    
    3. **Baby Naptime Memory Analysis**:
       - GDB-based dynamic memory inspection
       - Stack frame and register analysis during execution
       - Memory corruption detection with MALLOC_CHECK_
       - Stack canary and protection bypass analysis
       - Real-time memory state monitoring
       - libclang-based source code function extraction
    
    **Analysis Strategy:**
    - Extract function bodies using libclang for precise analysis
    - Use GDB with memory corruption detection environment variables
    - Test with various input sizes and patterns to trigger corruption
    - Monitor stack, heap, and register states during execution
    - Identify vulnerable function calls and memory operations
    - Analyze memory layout and exploitation potential
    
    **Memory Safety Tests:**
    - Buffer boundary testing with incremental input sizes
    - Integer overflow detection in allocation calculations
    - Heap manipulation analysis with allocation tracking
    - Stack frame analysis with canary detection
    - Memory allocation/deallocation pattern monitoring
    
    **Baby Naptime Focus:**
    - Dynamic memory corruption detection with GDB scripts
    - Stack and heap state inspection at runtime
    - Crash analysis and segmentation fault investigation
    - Memory protection bypass technique identification
    - Real-time vulnerability confirmation through debugging
    
    If memory corruption vulnerabilities are found, provide:
    - Specific vulnerability type and location in source
    - Memory layout analysis showing corruption
    - GDB debugging output with crash details
    - Exploitation methodology and proof-of-concept
    - Potential impact (code execution, privilege escalation)
    - Remediation recommendations (safe functions, bounds checking)
    
    If no memory corruption vulnerabilities are found, respond with "No memory corruption vulnerabilities detected."
    """,
    retries=2,
)

@memory_agent.tool
async def analyze_function_memory_safety(file_path: str, function_name: str) -> str:
    """
    Analyze specific function for memory safety vulnerabilities using libclang.
    
    Args:
        file_path: Path to the source code file
        function_name: Specific function to analyze
    """
    await send_log_message(f"Memory Agent: Analyzing function {function_name} in {file_path}")
    
    try:
        # Extract function body using libclang
        function_info = analyzer.get_function_body(file_path, function_name)
        
        # Analyze for dangerous patterns
        dangerous_patterns = analyzer.analyze_dangerous_patterns(function_info['source'])
        
        result = f"Function Analysis for {function_name}:\n"
        result += f"Location: {function_info['filename']}:{function_info.get('start_line', 'unknown')}\n"
        result += f"Function type: {function_info['type']}\n\n"
        
        if dangerous_patterns:
            result += "POTENTIAL MEMORY SAFETY ISSUES FOUND:\n"
            for pattern in dangerous_patterns:
                result += f"⚠️  {pattern}\n"
        else:
            result += "No obvious memory safety issues detected in static analysis.\n"
        
        result += f"\nFunction Source:\n{function_info['source']}"
        
        return result
        
    except Exception as e:
        return f"Function memory analysis failed: {str(e)}"

@memory_agent.tool
async def test_memory_corruption_dynamic(binary_path: str, function_name: str, test_inputs: list) -> str:
    """
    Test for memory corruption using dynamic analysis with GDB.
    
    Args:
        binary_path: Path to the binary to test
        function_name: Function to test
        test_inputs: List of test inputs to try
    """
    await send_log_message(f"Memory Agent: Dynamic testing {function_name} in {binary_path}")
    
    try:
        if not test_inputs:
            # Generate default test inputs for buffer overflow testing
            test_inputs = [
                "A" * 10,    # Small input
                "A" * 100,   # Medium input
                "A" * 1000,  # Large input
                "A" * 10000, # Very large input
                "\x00" * 100,  # Null bytes
                "\xff" * 100,  # High bytes
                "%s%s%s%s",    # Format string
                "../../../etc/passwd",  # Path traversal
            ]
        
        result = analyzer.analyze_memory_corruption(binary_path, function_name, test_inputs)
        return f"Dynamic Memory Corruption Testing Results:\n{result}"
        
    except Exception as e:
        return f"Dynamic memory corruption testing failed: {str(e)}"

@memory_agent.tool
async def analyze_buffer_overflow_potential(file_path: str, buffer_size: int = None) -> str:
    """
    Analyze source code for buffer overflow potential.
    
    Args:
        file_path: Path to source file
        buffer_size: Expected buffer size to analyze against
    """
    await send_log_message(f"Memory Agent: Analyzing buffer overflow potential in {file_path}")
    
    try:
        with open(file_path, 'r') as f:
            source_code = f.read()
        
        # Analyze for buffer overflow patterns
        dangerous_patterns = analyzer.analyze_dangerous_patterns(source_code)
        
        # Look for buffer declarations
        buffer_declarations = []
        lines = source_code.split('\n')
        for i, line in enumerate(lines, 1):
            if 'char' in line and '[' in line and ']' in line:
                buffer_declarations.append(f"Line {i}: {line.strip()}")
        
        result = "Buffer Overflow Analysis:\n\n"
        
        if buffer_declarations:
            result += "BUFFER DECLARATIONS FOUND:\n"
            for decl in buffer_declarations:
                result += f"📋 {decl}\n"
            result += "\n"
        
        if dangerous_patterns:
            result += "DANGEROUS PATTERNS DETECTED:\n"
            for pattern in dangerous_patterns:
                result += f"⚠️  {pattern}\n"
        else:
            result += "No obvious buffer overflow patterns detected.\n"
        
        return result
        
    except Exception as e:
        return f"Buffer overflow analysis failed: {str(e)}"

@memory_agent.tool
async def check_heap_corruption_patterns(file_path: str) -> str:
    """
    Check for heap corruption vulnerability patterns.
    
    Args:
        file_path: Path to source file to analyze
    """
    await send_log_message(f"Memory Agent: Checking heap corruption patterns in {file_path}")
    
    try:
        with open(file_path, 'r') as f:
            source_code = f.read()
        
        heap_issues = []
        lines = source_code.split('\n')
        
        malloc_lines = []
        free_lines = []
        
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            
            # Track malloc/free patterns
            if 'malloc(' in line_lower or 'calloc(' in line_lower or 'realloc(' in line_lower:
                malloc_lines.append((i, line.strip()))
            
            if 'free(' in line_lower:
                free_lines.append((i, line.strip()))
            
            # Check for dangerous heap patterns
            if 'free(' in line_lower and 'free(' in line_lower[line_lower.find('free(')+5:]:
                heap_issues.append(f"Line {i}: Potential double-free - {line.strip()}")
            
            if 'malloc(' in line_lower and 'free(' not in source_code.lower():
                heap_issues.append(f"Line {i}: Potential memory leak - malloc without corresponding free")
        
        result = "Heap Corruption Analysis:\n\n"
        
        if malloc_lines:
            result += f"MEMORY ALLOCATIONS ({len(malloc_lines)} found):\n"
            for line_num, line in malloc_lines[:5]:  # Show first 5
                result += f"📦 Line {line_num}: {line}\n"
            result += "\n"
        
        if free_lines:
            result += f"MEMORY DEALLOCATIONS ({len(free_lines)} found):\n"
            for line_num, line in free_lines[:5]:  # Show first 5
                result += f"🗑️  Line {line_num}: {line}\n"
            result += "\n"
        
        if heap_issues:
            result += "HEAP CORRUPTION RISKS:\n"
            for issue in heap_issues:
                result += f"⚠️  {issue}\n"
        else:
            result += "No obvious heap corruption patterns detected.\n"
        
        # Check allocation/deallocation balance
        if len(malloc_lines) != len(free_lines):
            result += f"\n⚠️  ALLOCATION IMBALANCE: {len(malloc_lines)} allocations vs {len(free_lines)} deallocations\n"
        
        return result
        
    except Exception as e:
        return f"Heap corruption analysis failed: {str(e)}"

@memory_agent.tool
async def analyze_integer_overflow_potential(file_path: str) -> str:
    """
    Analyze for integer overflow vulnerabilities that could lead to memory corruption.
    
    Args:
        file_path: Path to source file
    """
    await send_log_message(f"Memory Agent: Analyzing integer overflow potential in {file_path}")
    
    try:
        with open(file_path, 'r') as f:
            source_code = f.read()
        
        overflow_risks = []
        lines = source_code.split('\n')
        
        for i, line in enumerate(lines, 1):
            line_lower = line.lower().strip()
            
            # Check for arithmetic in allocation contexts
            if ('malloc(' in line_lower or 'calloc(' in line_lower) and ('*' in line or '+' in line):
                overflow_risks.append(f"Line {i}: Potential integer overflow in allocation - {line.strip()}")
            
            # Check for size calculations
            if 'size' in line_lower and ('*' in line or '+' in line) and any(t in line_lower for t in ['int', 'unsigned', 'size_t']):
                overflow_risks.append(f"Line {i}: Potential size calculation overflow - {line.strip()}")
            
            # Check for array indexing with arithmetic
            if '[' in line and ']' in line and ('+' in line or '*' in line):
                overflow_risks.append(f"Line {i}: Potential array index overflow - {line.strip()}")
        
        result = "Integer Overflow Analysis:\n\n"
        
        if overflow_risks:
            result += "INTEGER OVERFLOW RISKS DETECTED:\n"
            for risk in overflow_risks:
                result += f"⚠️  {risk}\n"
        else:
            result += "No obvious integer overflow risks detected.\n"
        
        return result
        
    except Exception as e:
        return f"Integer overflow analysis failed: {str(e)}"