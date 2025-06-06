import asyncio
import subprocess
import os
import tempfile
from typing import Dict, Any, List, Optional
from pydantic_ai import Agent
from pydantic_ai.settings import ModelSettings
from pydantic import BaseModel
from dotenv import load_dotenv

from utils.logging import send_log_message

load_dotenv()

class BinaryAnalysisResult(BaseModel):
    """Result of binary analysis from Baby Naptime"""
    file_path: str
    binary_path: Optional[str] = None
    analysis_type: str
    findings: List[Dict[str, Any]]
    risk_level: str
    recommendations: List[str]
    compilation_flags: Optional[str] = None

class BinaryAnalyzer:
    """Binary analysis functionality from Baby Naptime"""
    
    def __init__(self):
        """Initialize binary analyzer with GDB check"""
        try:
            subprocess.run(['gdb', '--version'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            raise RuntimeError("GDB not found - required for binary analysis")
    
    def is_binary_by_extension(self, file_path: str) -> bool:
        """Check if file is binary based on extension"""
        TEXT_EXTENSIONS = {'.c', '.cpp', '.py', '.java', '.txt', '.h'}
        return os.path.splitext(file_path)[1].lower() not in TEXT_EXTENSIONS
    
    def build_binary(self, source_file: str) -> str:
        """Compile source code into binary with security mitigations disabled"""
        try:
            directory = os.path.dirname(source_file)
            base = os.path.splitext(os.path.basename(source_file))[0]
            
            output = os.path.join(directory, base) if directory else base
                
            # Compile with disabled protections for vulnerability analysis
            cmd = f"g++ -std=c++17 -g {source_file} -o {output} -fno-stack-protector -z execstack -no-pie -w"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.returncode != 0:
                raise Exception(f"Compilation failed: {result.stderr}")
                
            return output
        except Exception as e:
            raise Exception(f"Error compiling binary: {e}")
    
    def create_gdb_script(self, file: str, line: int, exprs: str) -> str:
        """Create GDB script for CTF-focused binary analysis"""
        expressions = [e.strip() for e in exprs.split(',')]
        
        if self.is_binary_by_extension(file):
            break_cmd = f"break *{line}"
        else:
            break_cmd = f"break {line}"

        script = f"""
        set verbose off
        file {file}
        {break_cmd}
        run
        
        # Function layout
        printf "\\n=== FUNCTION LAYOUT ===\\n"
        x/20i $pc-8
        
        # Stack & heap info
        printf "\\n=== MEMORY LAYOUT ===\\n"
        printf "\\nStack pointer: "
        print/x $sp
        printf "Base pointer: "
        print/x $bp
        
        # Register state
        printf "\\n=== REGISTERS ===\\n"
        info registers
        
        printf "\\n=== TARGET VARIABLES ===\\n"
        """

        # Add analysis for each requested variable/expression
        for expr in expressions:
            script += f"""
        printf "\\n{expr}:\\n"
        printf "  Address: "
        print/x &{expr}
        printf "  Value: "
        print {expr}
        printf "  Raw bytes: "
        x/32xb {expr}
        printf "  As string: "
        x/s {expr}
        """

        script += """
        # Check for common CTF gadgets
        printf "\\n=== USEFUL GADGETS ===\\n"
        find $pc,+1000,"/bin/sh"
        find $pc,+1000,"flag"
        find $pc,+1000,"system"
        
        # Look for writable sections
        printf "\\n=== WRITABLE SECTIONS ===\\n"
        maintenance info sections WRITABLE
        
        quit
        """
        
        fd, path = tempfile.mkstemp(suffix='.gdb')
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        return path
    
    def debug_binary(self, filename: str, line_number: int, exprs: str, input_vars: Optional[Dict] = None) -> str:
        """Debug binary using GDB with CTF focus"""
        try:
            script_path = self.create_gdb_script(filename, line_number, exprs)
            
            cmd = ['gdb', '-batch', '-x', script_path]
            if input_vars:
                # Handle input variables if provided
                input_str = '\n'.join(str(v) for v in input_vars.values())
                result = subprocess.run(cmd, input=input_str, text=True, capture_output=True)
            else:
                result = subprocess.run(cmd, capture_output=True, text=True)
            
            os.unlink(script_path)  # Clean up script file
            
            return f"GDB Analysis Output:\n{result.stdout}\n{result.stderr}"
            
        except Exception as e:
            return f"Debug error: {str(e)}"

# Initialize analyzer
analyzer = BinaryAnalyzer()

model_settings = ModelSettings(temperature=0.01, max_tokens=16384)
binary_agent = Agent(
    'openai:gpt-4o-mini',
    result_type=str,
    model_settings=model_settings,
    system_prompt="""
    You are a specialized Binary Analysis vulnerability detection agent using Baby Naptime methodology.
    Your expertise covers comprehensive analysis of compiled binaries and executables with CTF-focused techniques:
    
    1. **Binary Security Features**:
       - ASLR (Address Space Layout Randomization)
       - DEP/NX (Data Execution Prevention)
       - Stack canaries/cookies
       - RELRO (Relocation Read-Only)
       - PIE (Position Independent Executable)
       - Fortify Source protections
    
    2. **Baby Naptime Analysis Capabilities**:
       - GDB-based dynamic analysis with memory inspection
       - Compilation with disabled protections for testing
       - CTF-focused gadget discovery (/bin/sh, system calls)
       - Register and stack state analysis
       - Variable and expression evaluation at runtime
    
    3. **Vulnerability Discovery**:
       - Static analysis of disassembled code
       - Dynamic analysis with GDB debugging
       - Symbol table analysis
       - Library dependency vulnerabilities
       - Memory corruption detection
    
    **Analysis Strategy:**
    - Compile source with disabled protections (-fno-stack-protector -z execstack -no-pie)
    - Use GDB for runtime analysis and memory inspection
    - Check for security mitigation presence
    - Identify potentially vulnerable code patterns
    - Analyze function calls and data flow
    - Look for CTF-style exploitation opportunities
    
    **Binary Analysis Tests:**
    - Security feature detection (ASLR, DEP, canaries)
    - Dangerous function usage identification
    - Buffer overflow potential assessment
    - Format string vulnerability detection
    - Integer overflow possibility analysis
    - ROP/JOP gadget discovery
    
    **Baby Naptime Focus:**
    - Runtime debugging with GDB scripts
    - Memory layout analysis (stack, heap, registers)
    - Variable inspection and manipulation
    - CTF gadget hunting (/bin/sh, system, flag strings)
    - Writable section identification
    - Dynamic vulnerability confirmation
    
    If binary vulnerabilities are found, provide:
    - Specific vulnerability type and location
    - Missing security mitigations
    - GDB analysis results with memory state
    - Exploitation methodology and proof-of-concept
    - Potential impact (code execution, privilege escalation)
    - Remediation recommendations (compiler flags, secure coding)
    
    If no binary vulnerabilities are found, respond with "No binary vulnerabilities detected."
    """,
    retries=2,
)

@binary_agent.tool
async def analyze_binary_security(binary_path: str) -> str:
    """
    Analyze binary security features and mitigations using Baby Naptime techniques.
    
    Args:
        binary_path: Path to the binary file to analyze
    """
    await send_log_message(f"Binary Agent: Analyzing security features for {binary_path}")
    
    try:
        if not analyzer.is_binary_by_extension(binary_path):
            # If it's source code, compile it first
            compiled_binary = analyzer.build_binary(binary_path)
            analysis_result = f"Compiled {binary_path} to {compiled_binary} with disabled protections\n"
            target_binary = compiled_binary
        else:
            target_binary = binary_path
            analysis_result = f"Analyzing existing binary: {target_binary}\n"
        
        # Check if file exists and is executable
        if os.path.exists(target_binary):
            file_info = subprocess.run(['file', target_binary], capture_output=True, text=True)
            analysis_result += f"File type: {file_info.stdout}\n"
            
            # Check security mitigations using checksec if available
            checksec = subprocess.run(['checksec', '--file', target_binary], capture_output=True, text=True)
            if checksec.returncode == 0:
                analysis_result += f"Security mitigations: {checksec.stdout}\n"
            else:
                # Fallback to readelf
                readelf_result = subprocess.run(['readelf', '-l', target_binary], capture_output=True, text=True)
                if readelf_result.returncode == 0:
                    analysis_result += f"ELF headers: {readelf_result.stdout[:500]}...\n"
        
        return analysis_result
        
    except Exception as e:
        return f"Binary analysis failed: {str(e)}"

@binary_agent.tool
async def debug_at_location(file_path: str, line_number: int, expressions: str, input_vars: dict = None) -> str:
    """
    Debug binary at specific location using GDB with Baby Naptime methodology.
    
    Args:
        file_path: Path to the binary or source file
        line_number: Line number or address to break at
        expressions: Comma-separated list of variables/expressions to analyze
        input_vars: Optional dictionary of input variables for the program
    """
    await send_log_message(f"Binary Agent: Debugging {file_path} at line {line_number}")
    
    try:
        # Ensure we have a binary to debug
        if not analyzer.is_binary_by_extension(file_path):
            binary_path = analyzer.build_binary(file_path)
        else:
            binary_path = file_path
            
        result = analyzer.debug_binary(binary_path, line_number, expressions, input_vars)
        return result
        
    except Exception as e:
        return f"Debug analysis failed: {str(e)}"

@binary_agent.tool
async def find_gadgets_and_strings(binary_path: str) -> str:
    """
    Find ROP/JOP gadgets and useful strings in the binary using objdump and strings.
    
    Args:
        binary_path: Path to the binary file to analyze
    """
    await send_log_message(f"Binary Agent: Finding gadgets and strings in {binary_path}")
    
    try:
        results = []
        
        # Use objdump to disassemble and look for useful gadgets
        objdump_result = subprocess.run(['objdump', '-d', binary_path], capture_output=True, text=True)
        
        if objdump_result.returncode == 0:
            disasm = objdump_result.stdout
            gadgets = []
            
            # Look for common ROP gadgets
            common_gadgets = ['ret', 'pop.*ret', 'call.*', 'jmp.*', 'syscall', 'int.*0x80']
            
            lines = disasm.split('\n')
            for i, line in enumerate(lines):
                for gadget_pattern in common_gadgets:
                    if gadget_pattern in line.lower():
                        gadgets.append(f"Potential gadget at line {i}: {line.strip()}")
                        break
            
            if gadgets:
                results.append(f"Found {len(gadgets)} potential ROP/JOP gadgets:\n" + '\n'.join(gadgets[:10]))
        
        # Use strings to find useful strings
        strings_result = subprocess.run(['strings', binary_path], capture_output=True, text=True)
        if strings_result.returncode == 0:
            useful_strings = []
            interesting = ['/bin/sh', 'system', 'flag', 'password', 'admin', 'root']
            
            for line in strings_result.stdout.split('\n'):
                for pattern in interesting:
                    if pattern in line.lower():
                        useful_strings.append(line.strip())
            
            if useful_strings:
                results.append(f"Interesting strings found:\n" + '\n'.join(useful_strings[:10]))
        
        return '\n\n'.join(results) if results else "No obvious gadgets or interesting strings found"
        
    except Exception as e:
        return f"Gadget and string analysis failed: {str(e)}"

@binary_agent.tool
async def check_dangerous_functions(binary_path: str) -> str:
    """
    Check for usage of dangerous/unsafe functions in the binary.
    
    Args:
        binary_path: Path to the binary file to analyze
    """
    await send_log_message(f"Binary Agent: Checking for dangerous functions in {binary_path}")
    
    try:
        # Use objdump to check for dangerous function calls
        result = subprocess.run(['objdump', '-T', binary_path], capture_output=True, text=True)
        
        if result.returncode != 0:
            # Try nm if objdump fails
            result = subprocess.run(['nm', '-D', binary_path], capture_output=True, text=True)
        
        if result.returncode == 0:
            dangerous_funcs = [
                'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
                'strncpy', 'strncat', 'snprintf', 'vsnprintf', 'system',
                'exec', 'popen', 'malloc', 'free', 'realloc'
            ]
            
            found_dangerous = []
            output = result.stdout.lower()
            
            for func in dangerous_funcs:
                if func in output:
                    found_dangerous.append(func)
            
            if found_dangerous:
                return f"Dangerous functions found: {', '.join(found_dangerous)}"
            else:
                return "No obviously dangerous functions detected in symbol table"
        
        return "Could not analyze function symbols"
        
    except Exception as e:
        return f"Dangerous function analysis failed: {str(e)}"

@binary_agent.tool
async def compile_with_protections(source_file: str, lang: str = 'cpp') -> str:
    """
    Compile source with various protection levels for testing.
    
    Args:
        source_file: Path to source file
        lang: Language ('c' or 'cpp')
    """
    await send_log_message(f"Binary Agent: Compiling {source_file} with different protection levels")
    
    try:
        base_name = os.path.splitext(source_file)[0]
        compiler = 'g++' if lang == 'cpp' else 'gcc'
        
        # Compile with different protection levels
        configs = {
            'no_protections': f'{compiler} -std=c++17 -g {source_file} -o {base_name}_no_prot -fno-stack-protector -z execstack -no-pie -w',
            'basic_protections': f'{compiler} -std=c++17 -g {source_file} -o {base_name}_basic -fstack-protector',
            'full_protections': f'{compiler} -std=c++17 -g {source_file} -o {base_name}_full -fstack-protector-strong -pie -Wl,-z,relro,-z,now'
        }
        
        results = []
        for config_name, cmd in configs.items():
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode == 0:
                results.append(f"✓ {config_name}: {base_name}_{config_name.split('_')[0]}")
            else:
                results.append(f"✗ {config_name}: {result.stderr}")
        
        return "Compilation results:\n" + '\n'.join(results)
        
    except Exception as e:
        return f"Compilation failed: {str(e)}"