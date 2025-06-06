"""
Binary Analysis Tools

Integrated battle-tested binary analysis tools from Baby Naptime framework.
Provides comprehensive binary vulnerability analysis capabilities.

Based on the proven Baby Naptime implementation for binary security testing.
"""

import subprocess
import os
import tempfile
import json
import re
from typing import Dict, Any, List, Optional
from datetime import datetime

class BinaryAnalyzer:
    """Binary analysis tools from Baby Naptime framework"""
    
    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.gdb_available = self._check_gdb()
        self.radare2_available = self._check_radare2()
    
    def _check_gdb(self) -> bool:
        """Check if GDB is available"""
        try:
            subprocess.run(['gdb', '--version'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def _check_radare2(self) -> bool:
        """Check if Radare2 is available"""
        try:
            subprocess.run(['r2', '-v'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False
    
    def analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """Comprehensive binary analysis"""
        if not os.path.exists(binary_path):
            return {"error": f"Binary not found: {binary_path}"}
        
        results = {
            "binary_path": binary_path,
            "timestamp": datetime.now().isoformat(),
            "basic_info": self._get_basic_info(binary_path),
            "security_features": self._check_security_features(binary_path),
            "vulnerabilities": []
        }
        
        # Static analysis
        static_vulns = self._static_analysis(binary_path)
        results["vulnerabilities"].extend(static_vulns)
        
        # Dynamic analysis if GDB is available
        if self.gdb_available:
            dynamic_vulns = self._dynamic_analysis(binary_path)
            results["vulnerabilities"].extend(dynamic_vulns)
        
        # Radare2 analysis if available
        if self.radare2_available:
            r2_analysis = self._radare2_analysis(binary_path)
            results["radare2_analysis"] = r2_analysis
        
        return results
    
    def _get_basic_info(self, binary_path: str) -> Dict[str, Any]:
        """Get basic binary information"""
        try:
            # Use file command
            file_result = subprocess.run(['file', binary_path], capture_output=True, text=True)
            file_info = file_result.stdout.strip()
            
            # Use readelf for ELF binaries
            readelf_result = subprocess.run(['readelf', '-h', binary_path], capture_output=True, text=True)
            
            info = {
                "file_type": file_info,
                "size": os.path.getsize(binary_path),
                "permissions": oct(os.stat(binary_path).st_mode)[-3:]
            }
            
            if readelf_result.returncode == 0:
                # Parse ELF header info
                elf_info = self._parse_elf_header(readelf_result.stdout)
                info.update(elf_info)
            
            return info
        except Exception as e:
            return {"error": str(e)}
    
    def _parse_elf_header(self, readelf_output: str) -> Dict[str, Any]:
        """Parse ELF header information"""
        info = {}
        
        # Extract architecture
        arch_match = re.search(r'Machine:\s+(.+)', readelf_output)
        if arch_match:
            info["architecture"] = arch_match.group(1).strip()
        
        # Extract entry point
        entry_match = re.search(r'Entry point address:\s+(0x[0-9a-fA-F]+)', readelf_output)
        if entry_match:
            info["entry_point"] = entry_match.group(1)
        
        return info
    
    def _check_security_features(self, binary_path: str) -> Dict[str, Any]:
        """Check binary security features"""
        features = {
            "nx_bit": False,
            "stack_canary": False,
            "pie": False,
            "relro": False,
            "fortify": False
        }
        
        try:
            # Check with checksec if available
            checksec_result = subprocess.run(['checksec', '--file', binary_path], 
                                           capture_output=True, text=True)
            
            if checksec_result.returncode == 0:
                output = checksec_result.stdout.lower()
                features["nx_bit"] = "nx enabled" in output
                features["stack_canary"] = "canary found" in output
                features["pie"] = "pie enabled" in output
                features["relro"] = "full relro" in output or "partial relro" in output
                features["fortify"] = "fortify enabled" in output
            else:
                # Manual checks using readelf
                features.update(self._manual_security_check(binary_path))
        
        except FileNotFoundError:
            # checksec not available, use manual checks
            features.update(self._manual_security_check(binary_path))
        
        return features
    
    def _manual_security_check(self, binary_path: str) -> Dict[str, Any]:
        """Manual security feature detection"""
        features = {}
        
        try:
            # Check for stack canary
            strings_result = subprocess.run(['strings', binary_path], capture_output=True, text=True)
            if strings_result.returncode == 0:
                strings_output = strings_result.stdout
                features["stack_canary"] = "__stack_chk_fail" in strings_output
                features["fortify"] = any(func in strings_output for func in 
                                        ["__sprintf_chk", "__strcpy_chk", "__memcpy_chk"])
            
            # Check for PIE
            readelf_result = subprocess.run(['readelf', '-h', binary_path], capture_output=True, text=True)
            if readelf_result.returncode == 0:
                features["pie"] = "DYN (Shared object file)" in readelf_result.stdout
            
            # Check for NX bit
            readelf_stack = subprocess.run(['readelf', '-l', binary_path], capture_output=True, text=True)
            if readelf_stack.returncode == 0:
                features["nx_bit"] = "GNU_STACK" in readelf_stack.stdout and "RWE" not in readelf_stack.stdout
        
        except Exception:
            pass
        
        return features
    
    def _static_analysis(self, binary_path: str) -> List[Dict[str, Any]]:
        """Static vulnerability analysis"""
        vulnerabilities = []
        
        try:
            # Check for dangerous functions
            strings_result = subprocess.run(['strings', binary_path], capture_output=True, text=True)
            if strings_result.returncode == 0:
                dangerous_functions = [
                    "strcpy", "strcat", "sprintf", "gets", "scanf",
                    "system", "exec", "popen", "malloc", "free"
                ]
                
                found_functions = []
                for func in dangerous_functions:
                    if func in strings_result.stdout:
                        found_functions.append(func)
                
                if found_functions:
                    vulnerabilities.append({
                        "type": "Dangerous Functions",
                        "severity": "medium",
                        "description": f"Binary contains potentially dangerous functions: {', '.join(found_functions)}",
                        "functions": found_functions,
                        "recommendation": "Review usage of these functions for potential buffer overflows or injection vulnerabilities"
                    })
            
            # Check for hardcoded credentials/secrets
            secrets = self._find_secrets(strings_result.stdout if strings_result.returncode == 0 else "")
            if secrets:
                vulnerabilities.append({
                    "type": "Hardcoded Secrets",
                    "severity": "high",
                    "description": "Binary contains potential hardcoded secrets",
                    "secrets": secrets,
                    "recommendation": "Remove hardcoded credentials and use secure configuration management"
                })
        
        except Exception as e:
            vulnerabilities.append({
                "type": "Static Analysis Error",
                "severity": "info",
                "description": f"Error during static analysis: {str(e)}"
            })
        
        return vulnerabilities
    
    def _find_secrets(self, strings_output: str) -> List[str]:
        """Find potential secrets in strings"""
        secret_patterns = [
            r'password\s*=\s*["\']([^"\']+)["\']',
            r'api[_-]?key\s*=\s*["\']([^"\']+)["\']',
            r'secret\s*=\s*["\']([^"\']+)["\']',
            r'token\s*=\s*["\']([^"\']+)["\']',
            r'["\'][A-Za-z0-9+/]{20,}={0,2}["\']',  # Base64-like strings
            r'["\'][0-9a-fA-F]{32,}["\']'  # Hex strings
        ]
        
        secrets = []
        for pattern in secret_patterns:
            matches = re.findall(pattern, strings_output, re.IGNORECASE)
            secrets.extend(matches)
        
        return secrets[:10]  # Limit to first 10 findings
    
    def _dynamic_analysis(self, binary_path: str) -> List[Dict[str, Any]]:
        """Dynamic analysis using GDB"""
        vulnerabilities = []
        
        try:
            # Create GDB script for basic dynamic analysis
            gdb_script = f"""
set confirm off
file {binary_path}
set environment ASAN_OPTIONS=detect_stack_use_after_return=1
set environment MSAN_OPTIONS=print_stats=1
run
bt
info registers
quit
"""
            
            script_path = os.path.join(self.temp_dir, "analysis.gdb")
            with open(script_path, 'w') as f:
                f.write(gdb_script)
            
            # Run GDB analysis
            gdb_result = subprocess.run(['gdb', '-batch', '-x', script_path], 
                                      capture_output=True, text=True, timeout=30)
            
            if gdb_result.returncode != 0:
                # Check for crash indicators
                if "SIGSEGV" in gdb_result.stderr or "SIGABRT" in gdb_result.stderr:
                    vulnerabilities.append({
                        "type": "Crash Detected",
                        "severity": "high",
                        "description": "Binary crashed during execution",
                        "details": gdb_result.stderr,
                        "recommendation": "Investigate crash for potential memory corruption vulnerabilities"
                    })
                
                # Check for stack smashing
                if "stack smashing detected" in gdb_result.stderr:
                    vulnerabilities.append({
                        "type": "Stack Smashing",
                        "severity": "critical",
                        "description": "Stack buffer overflow detected",
                        "details": gdb_result.stderr,
                        "recommendation": "Fix buffer overflow vulnerability immediately"
                    })
        
        except subprocess.TimeoutExpired:
            vulnerabilities.append({
                "type": "Execution Timeout",
                "severity": "medium",
                "description": "Binary execution timed out",
                "recommendation": "Check for infinite loops or hanging operations"
            })
        except Exception as e:
            vulnerabilities.append({
                "type": "Dynamic Analysis Error",
                "severity": "info",
                "description": f"Error during dynamic analysis: {str(e)}"
            })
        
        return vulnerabilities
    
    def _radare2_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Analysis using Radare2"""
        try:
            # Basic Radare2 analysis
            r2_commands = [
                "aaa",  # Analyze all
                "afl",  # List functions
                "iz",   # List strings
                "ii",   # List imports
            ]
            
            results = {}
            
            for cmd in r2_commands:
                r2_result = subprocess.run(['r2', '-q', '-c', cmd, binary_path], 
                                         capture_output=True, text=True)
                if r2_result.returncode == 0:
                    results[cmd] = r2_result.stdout
            
            return results
        
        except Exception as e:
            return {"error": str(e)}
    
    def analyze_memory_corruption(self, binary_path: str, input_data: str = None) -> Dict[str, Any]:
        """Analyze for memory corruption vulnerabilities"""
        if not self.gdb_available:
            return {"error": "GDB not available for memory corruption analysis"}
        
        try:
            # Create input file if provided
            input_file = None
            if input_data:
                input_file = os.path.join(self.temp_dir, "input.txt")
                with open(input_file, 'w') as f:
                    f.write(input_data)
            
            # GDB script for memory corruption detection
            gdb_script = f"""
set confirm off
file {binary_path}
set environment MALLOC_CHECK_=2
set environment MALLOC_PERTURB_=165
"""
            
            if input_file:
                gdb_script += f"run < {input_file}\n"
            else:
                gdb_script += "run\n"
            
            gdb_script += """
bt
info registers
x/20i $pc
quit
"""
            
            script_path = os.path.join(self.temp_dir, "memory_analysis.gdb")
            with open(script_path, 'w') as f:
                f.write(gdb_script)
            
            # Run analysis
            result = subprocess.run(['gdb', '-batch', '-x', script_path], 
                                  capture_output=True, text=True, timeout=60)
            
            analysis = {
                "binary_path": binary_path,
                "input_provided": input_data is not None,
                "crashed": result.returncode != 0,
                "output": result.stdout,
                "errors": result.stderr,
                "vulnerabilities": []
            }
            
            # Analyze output for vulnerabilities
            if "SIGSEGV" in result.stderr:
                analysis["vulnerabilities"].append({
                    "type": "Segmentation Fault",
                    "severity": "high",
                    "description": "Memory access violation detected"
                })
            
            if "double free" in result.stderr:
                analysis["vulnerabilities"].append({
                    "type": "Double Free",
                    "severity": "critical",
                    "description": "Double free vulnerability detected"
                })
            
            if "heap buffer overflow" in result.stderr:
                analysis["vulnerabilities"].append({
                    "type": "Heap Buffer Overflow",
                    "severity": "critical",
                    "description": "Heap buffer overflow detected"
                })
            
            return analysis
        
        except Exception as e:
            return {"error": str(e)}
    
    def generate_exploit_template(self, vulnerability_type: str, binary_path: str) -> Dict[str, Any]:
        """Generate exploit template based on vulnerability type"""
        templates = {
            "buffer_overflow": """
#!/usr/bin/env python3
import struct

# Buffer overflow exploit template
# Target: {binary_path}

def exploit():
    # Calculate buffer size and offset
    buffer_size = 100  # Adjust based on analysis
    offset = 76        # Adjust based on crash analysis
    
    # Payload construction
    payload = b"A" * offset
    payload += struct.pack("<Q", 0x41414141)  # Return address (adjust for target)
    payload += b"C" * (buffer_size - len(payload))
    
    return payload

if __name__ == "__main__":
    exploit_payload = exploit()
    print(f"Exploit payload length: {{len(exploit_payload)}}")
    print(f"Payload: {{exploit_payload}}")
""",
            "format_string": """
#!/usr/bin/env python3

# Format string exploit template
# Target: {binary_path}

def exploit():
    # Format string payload
    # %x to leak stack values
    # %n to write to memory
    
    payload = b"%08x." * 10  # Leak 10 stack values
    payload += b"%n"         # Write to memory
    
    return payload

if __name__ == "__main__":
    exploit_payload = exploit()
    print(f"Format string payload: {{exploit_payload}}")
""",
            "use_after_free": """
#!/usr/bin/env python3

# Use-after-free exploit template
# Target: {binary_path}

def exploit():
    # UAF exploitation typically requires:
    # 1. Trigger free() on object
    # 2. Reallocate memory with controlled data
    # 3. Use freed object to gain control
    
    payload = b"Controlled data for reallocation"
    
    return payload

if __name__ == "__main__":
    exploit_payload = exploit()
    print(f"UAF payload: {{exploit_payload}}")
"""
        }
        
        template = templates.get(vulnerability_type, "# No template available for this vulnerability type")
        
        return {
            "vulnerability_type": vulnerability_type,
            "binary_path": binary_path,
            "template": template.format(binary_path=binary_path),
            "timestamp": datetime.now().isoformat()
        }

# Utility functions for compatibility with existing agents
def analyze_binary_file(binary_path: str) -> Dict[str, Any]:
    """Analyze binary file for vulnerabilities"""
    analyzer = BinaryAnalyzer()
    return analyzer.analyze_binary(binary_path)

def check_memory_corruption(binary_path: str, input_data: str = None) -> Dict[str, Any]:
    """Check for memory corruption vulnerabilities"""
    analyzer = BinaryAnalyzer()
    return analyzer.analyze_memory_corruption(binary_path, input_data)

def create_exploit_template(vulnerability_type: str, binary_path: str) -> Dict[str, Any]:
    """Create exploit template"""
    analyzer = BinaryAnalyzer()
    return analyzer.generate_exploit_template(vulnerability_type, binary_path)