from typing import List, Dict, Any, Set, Optional
from dataclasses import dataclass
from enum import Enum
import clang.cindex
from pathlib import Path
import re
import os
import json
import ast
import sys

# Adiciona o diretório do ambiente virtual ao PYTHONPATH
venv_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "venv", "lib", "python3.11", "site-packages")
sys.path.insert(0, venv_path)

import pyjsparser

# Define memory-related functions to check
MEMORY_FUNCTIONS = [
    'malloc', 'calloc', 'realloc', 'free',
    'strcpy', 'strcat', 'strncpy', 'strncat',
    'memcpy', 'memmove', 'memset',
    'new', 'delete', 'new[]', 'delete[]'
]

# Configure libclang before any other imports or usage
libclang_path = '/opt/homebrew/Cellar/llvm/20.1.3/lib/libclang.dylib'

if not os.path.exists(libclang_path):
    raise Exception(f"libclang library not found at {libclang_path}. Please ensure LLVM is installed correctly.")
    
if not os.access(libclang_path, os.R_OK):
    raise Exception(f"libclang library at {libclang_path} is not readable. Please check file permissions.")

# Set the library file before any clang usage
clang.cindex.Config.set_library_file(libclang_path)
os.environ['LIBCLANG_PATH'] = libclang_path

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

@dataclass
class VulnerabilityLocation:
    file: str
    line: int
    column: int
    snippet: str

@dataclass
class Vulnerability:
    type: str
    severity: Severity
    description: str
    location: VulnerabilityLocation
    cwe_id: str
    remediation: str
    score: int
    confidence: float  # New field for confidence level

class VulnerabilityAnalyzer:
    def __init__(self):
        try:
            # Create clang index
            print("Initializing clang...")
            print(f"libclang path: {libclang_path}")
            print(f"libclang exists: {os.path.exists(libclang_path)}")
            print(f"libclang readable: {os.access(libclang_path, os.R_OK)}")
            
            self.index = clang.cindex.Index.create()
            if not self.index:
                raise Exception("Failed to create clang index")
            print("Clang index created successfully")
                
        except Exception as e:
            print(f"Failed to initialize libclang: {str(e)}")
            raise
        
        # Get absolute path for learned patterns file
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        data_dir = os.path.join(base_dir, "data")
        
        # Create data directory if it doesn't exist
        if not os.path.exists(data_dir):
            os.makedirs(data_dir)
            print(f"Created data directory: {data_dir}")
        
        self.learned_patterns_file = os.path.join(data_dir, "learned_patterns.json")
        print(f"Using learned patterns file: {self.learned_patterns_file}")
        
        # Load learned patterns from file if exists
        self.learned_patterns = self._load_learned_patterns()
        
        # Initialize pattern weights
        self.pattern_weights = {
            'buffer_overflow': 1.0,
            'command_injection': 1.0,
            'use_after_free': 1.0,
            'format_string': 1.0,
            'sql_injection': 1.0,
            'xss': 1.0,
            'path_traversal': 1.0,
            'deserialization': 1.0,
            'insecure_crypto': 1.0,
            'insecure_random': 1.0
        }
        
        # Initialize false positive patterns
        self.false_positive_patterns = {
            'buffer_overflow': [],
            'command_injection': [],
            'use_after_free': [],
            'format_string': [],
            'sql_injection': [],
            'xss': [],
            'path_traversal': [],
            'deserialization': [],
            'insecure_crypto': [],
            'insecure_random': []
        }
        
        # Enhanced safe function patterns with more context
        self.safe_patterns = {
            'strncpy': [
                r'strncpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*sizeof\s*\(\s*\w+\s*\)\s*\)',
                r'strncpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*;.*if\s*\(\s*strlen\s*\(\s*\w+\s*\)\s*<\s*\w+\s*\)',
                r'strncpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*;.*assert\s*\(\s*strlen\s*\(\s*\w+\s*\)\s*<\s*\w+\s*\)'
            ],
            'snprintf': [
                r'snprintf\s*\(\s*\w+\s*,\s*sizeof\s*\(\s*\w+\s*\)\s*,\s*.*\)',
                r'snprintf\s*\(\s*\w+\s*,\s*\w+\s*,\s*.*\)\s*;.*if\s*\(\s*\w+\s*<\s*\w+\s*\)',
                r'snprintf\s*\(\s*\w+\s*,\s*\w+\s*,\s*.*\)\s*;.*assert\s*\(\s*\w+\s*<\s*\w+\s*\)'
            ],
            'strncat': [
                r'strncat\s*\(\s*\w+\s*,\s*\w+\s*,\s*sizeof\s*\(\s*\w+\s*\)\s*-\s*strlen\s*\(\s*\w+\s*\)\s*\)',
                r'strncat\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+\s*\)\s*;.*if\s*\(\s*strlen\s*\(\s*\w+\s*\)\s*\+\s*strlen\s*\(\s*\w+\s*\)\s*<\s*\w+\s*\)'
            ],
            'system': [
                r'system\s*\(\s*".*"\s*\)\s*;.*if\s*\(\s*\w+\s*==\s*0\s*\)',
                r'system\s*\(\s*".*"\s*\)\s*;.*assert\s*\(\s*\w+\s*==\s*0\s*\)',
                r'system\s*\(\s*".*"\s*\)\s*;.*validate\s*\(\s*\w+\s*\)'
            ],
            'popen': [
                r'popen\s*\(\s*".*"\s*,\s*"r"\s*\)\s*;.*if\s*\(\s*\w+\s*\)',
                r'popen\s*\(\s*".*"\s*,\s*"r"\s*\)\s*;.*assert\s*\(\s*\w+\s*\)'
            ],
            'exec': [
                r'exec\w*\s*\(\s*".*"\s*\)\s*;.*if\s*\(\s*\w+\s*\)',
                r'exec\w*\s*\(\s*".*"\s*\)\s*;.*assert\s*\(\s*\w+\s*\)'
            ],
            'eval': [
                r'eval\s*\(\s*".*"\s*\)\s*;.*if\s*\(\s*\w+\s*\)',
                r'eval\s*\(\s*".*"\s*\)\s*;.*assert\s*\(\s*\w+\s*\)'
            ],
            'pickle': [
                r'pickle\.loads\s*\(\s*\w+\s*\)\s*;.*if\s*\(\s*\w+\s*\)',
                r'pickle\.loads\s*\(\s*\w+\s*\)\s*;.*assert\s*\(\s*\w+\s*\)'
            ],
            'random': [
                r'random\.\w+\s*\(\s*\)\s*;.*if\s*\(\s*\w+\s*\)',
                r'random\.\w+\s*\(\s*\)\s*;.*assert\s*\(\s*\w+\s*\)'
            ]
        }
        
        # Common vulnerability patterns with improved detection
        self.patterns = {
            'buffer_overflow': {
                'functions': ['strcpy', 'strcat', 'gets', 'sprintf', 'memcpy', 'memmove'],
                'severity': Severity.CRITICAL,
                'cwe': 'CWE-119',
                'description': 'Potential buffer overflow vulnerability detected',
                'remediation': 'Use bounds-checking functions like strncpy, strncat, or snprintf',
                'score': 1000,
                'context_checks': {
                    'size_check': r'sizeof|strlen',
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'safe_function': r'strncpy|strncat|snprintf'
                }
            },
            'command_injection': {
                'functions': ['system', 'popen', 'exec', 'execv', 'execve', 'execvp', 'execvpe', 'spawn', 'spawnv', 'spawnve', 'spawnvp', 'spawnvpe'],
                'severity': Severity.CRITICAL,
                'cwe': 'CWE-78',
                'description': 'Potential command injection vulnerability detected',
                'remediation': 'Use input validation and sanitization before executing commands',
                'score': 1000,
                'context_checks': {
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'sanitization': r'sanitize|escape|clean',
                    'safe_function': r'popen|execve'
                }
            },
            'sql_injection': {
                'functions': ['execute', 'query', 'exec', 'prepare', 'executemany'],
                'severity': Severity.CRITICAL,
                'cwe': 'CWE-89',
                'description': 'Potential SQL injection vulnerability detected',
                'remediation': 'Use parameterized queries or prepared statements',
                'score': 1000,
                'context_checks': {
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'sanitization': r'sanitize|escape|clean',
                    'safe_function': r'prepare|bind_param|execute'
                }
            },
            'xss': {
                'functions': ['innerHTML', 'outerHTML', 'write', 'writeln', 'document.write', 'document.writeln', 'eval', 'setTimeout', 'setInterval'],
                'severity': Severity.HIGH,
                'cwe': 'CWE-79',
                'description': 'Potential Cross-Site Scripting (XSS) vulnerability detected',
                'remediation': 'Use proper output encoding and input validation',
                'score': 900,
                'context_checks': {
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'sanitization': r'sanitize|escape|clean',
                    'safe_function': r'encodeURI|encodeURIComponent|escape'
                }
            },
            'path_traversal': {
                'functions': ['open', 'fopen', 'readfile', 'file_get_contents', 'include', 'require', 'read', 'write'],
                'severity': Severity.HIGH,
                'cwe': 'CWE-22',
                'description': 'Potential path traversal vulnerability detected',
                'remediation': 'Validate and sanitize file paths before access',
                'score': 900,
                'context_checks': {
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'sanitization': r'sanitize|escape|clean',
                    'safe_function': r'basename|realpath|canonicalize'
                }
            },
            'deserialization': {
                'functions': ['unpickle', 'pickle.loads', 'json_decode', 'unserialize', 'YAML.load', 'YAML.parse'],
                'severity': Severity.HIGH,
                'cwe': 'CWE-502',
                'description': 'Potential insecure deserialization vulnerability detected',
                'remediation': 'Use safe deserialization methods and validate input',
                'score': 900,
                'context_checks': {
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'sanitization': r'sanitize|escape|clean',
                    'safe_function': r'json_decode|json_parse'
                }
            },
            'insecure_crypto': {
                'functions': ['md5', 'sha1', 'DES', 'RC4', 'MD5', 'SHA1', 'crypto.createCipher', 'crypto.createDecipher'],
                'severity': Severity.HIGH,
                'cwe': 'CWE-327',
                'description': 'Potential use of insecure cryptographic algorithm detected',
                'remediation': 'Use modern cryptographic algorithms like AES, SHA-256, or SHA-3',
                'score': 800,
                'context_checks': {
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'sanitization': r'sanitize|escape|clean',
                    'safe_function': r'AES|SHA256|SHA3'
                }
            },
            'insecure_random': {
                'functions': ['rand', 'random', 'Math.random', 'random.random'],
                'severity': Severity.MEDIUM,
                'cwe': 'CWE-338',
                'description': 'Potential use of insecure random number generator detected',
                'remediation': 'Use cryptographically secure random number generators',
                'score': 700,
                'context_checks': {
                    'input_validation': r'if\s*\(.*\)|assert|validate',
                    'sanitization': r'sanitize|escape|clean',
                    'safe_function': r'secrets|random.SystemRandom|crypto.randomBytes'
                }
            }
        }

    def _load_learned_patterns(self):
        """Load learned patterns from file."""
        try:
            if os.path.exists(self.learned_patterns_file):
                with open(self.learned_patterns_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading learned patterns: {str(e)}")
        return {}

    def _save_learned_patterns(self):
        """Save learned patterns to file."""
        try:
            with open(self.learned_patterns_file, 'w') as f:
                json.dump(self.learned_patterns, f)
        except Exception as e:
            print(f"Error saving learned patterns: {str(e)}")

    def _update_learned_patterns(self, vuln_type: str, snippet: str, is_false_positive: bool):
        """Update learned patterns based on user feedback."""
        if vuln_type not in self.learned_patterns:
            self.learned_patterns[vuln_type] = {
                'true_positives': [],
                'false_positives': []
            }
        
        if is_false_positive:
            self.learned_patterns[vuln_type]['false_positives'].append(snippet)
            # Update pattern weights
            self.pattern_weights[vuln_type] *= 0.9  # Reduce weight for this type
        else:
            self.learned_patterns[vuln_type]['true_positives'].append(snippet)
            # Update pattern weights
            self.pattern_weights[vuln_type] *= 1.1  # Increase weight for this type
        
        # Save updated patterns
        self._save_learned_patterns()

    def _check_learned_patterns(self, vuln_type: str, snippet: str) -> float:
        """Check if the code snippet matches learned patterns."""
        if vuln_type not in self.learned_patterns:
            return 1.0  # No learned patterns, use default confidence
        
        # Check against false positive patterns
        for pattern in self.learned_patterns[vuln_type]['false_positives']:
            if re.search(re.escape(pattern), snippet, re.DOTALL):
                return 0.0  # Matches a known false positive pattern
        
        # Check against true positive patterns
        for pattern in self.learned_patterns[vuln_type]['true_positives']:
            if re.search(re.escape(pattern), snippet, re.DOTALL):
                return 1.5  # Matches a known true positive pattern
        
        return 1.0  # No matches found

    def _get_code_snippet(self, file_path: str, line: int, context: int = 5) -> str:
        """Get the code snippet around the vulnerability with more context."""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                start = max(0, line - context - 1)
                end = min(len(lines), line + context)
                return ''.join(lines[start:end])
        except Exception:
            return ""

    def _check_safe_usage(self, file_path: str, line: int, func_name: str) -> bool:
        """Check if the function is used safely with enhanced pattern matching."""
        snippet = self._get_code_snippet(file_path, line, context=10)  # Increased context
        
        # Check for safe patterns specific to the function
        if func_name in self.safe_patterns:
            for pattern in self.safe_patterns[func_name]:
                if re.search(pattern, snippet, re.DOTALL):
                    return True
        
        # Check for common safe usage patterns
        safe_patterns = [
            r'if\s*\(\s*\w+\s*\)',  # Null check
            r'assert\s*\(\s*\w+\s*\)',  # Assertion
            r'validate\s*\(\s*\w+\s*\)',  # Validation
            r'check\s*\(\s*\w+\s*\)',  # Check
            r'verify\s*\(\s*\w+\s*\)',  # Verification
            r'try\s*{|catch\s*\(',  # Exception handling
            r'if\s*\(\s*errno\s*\)',  # Error checking
            r'if\s*\(\s*!\w+\s*\)',  # Negative check
            r'sizeof\s*\(\s*\w+\s*\)',  # Size check
            r'strlen\s*\(\s*\w+\s*\)',  # Length check
            r'memset\s*\(\s*\w+\s*,\s*0\s*,\s*sizeof',  # Safe initialization
            r'calloc\s*\(\s*\d+\s*,\s*sizeof',  # Safe allocation
            r'snprintf\s*\(\s*\w+\s*,\s*sizeof\s*\(\s*\w+\s*\)',  # Safe string formatting
            r'strncpy\s*\(\s*\w+\s*,\s*\w+\s*,\s*sizeof\s*\(\s*\w+\s*\)',  # Safe string copy
            r'strncat\s*\(\s*\w+\s*,\s*\w+\s*,\s*sizeof\s*\(\s*\w+\s*\)'  # Safe string concatenation
        ]
        
        for pattern in safe_patterns:
            if re.search(pattern, snippet, re.DOTALL):
                return True
        
        return False

    def _check_context(self, file_path: str, line: int, vuln_type: str) -> float:
        """Check the context around the vulnerability with improved confidence calculation."""
        snippet = self._get_code_snippet(file_path, line, context=10)  # Increased context
        pattern = self.patterns[vuln_type]
        confidence = 1.0
        
        if 'context_checks' in pattern:
            for check, regex in pattern['context_checks'].items():
                if re.search(regex, snippet, re.DOTALL):
                    if check == 'safe_function':
                        confidence *= 0.2  # Strong reduction if safe function is used
                    else:
                        confidence *= 0.5  # Moderate reduction for other safety checks
        
        return confidence

    def _calculate_vulnerability_score(self, vuln_type: str, file_path: str, line: int, node) -> float:
        """Calculate a sophisticated vulnerability score based on multiple factors."""
        base_score = self.patterns[vuln_type]['score']
        confidence = self._check_context(file_path, line, vuln_type)
        
        # Get more context for analysis
        snippet = self._get_code_snippet(file_path, line, context=20)
        
        # Initialize score factors
        score_factors = {
            'context_confidence': confidence,
            'input_validation': 1.0,
            'error_handling': 1.0,
            'safe_usage': 1.0,
            'complexity': 1.0,
            'learned_patterns': self._check_learned_patterns(vuln_type, snippet)
        }
        
        # Check for input validation - less aggressive reduction
        if re.search(r'if\s*\(.*\)|assert|validate|check|verify', snippet, re.DOTALL):
            score_factors['input_validation'] *= 0.7  # Reduced from 0.5
        
        # Check for error handling - less aggressive reduction
        if re.search(r'try\s*{|catch\s*\(|if\s*\(\s*errno\s*\)|if\s*\(\s*!\w+\s*\)', snippet, re.DOTALL):
            score_factors['error_handling'] *= 0.7  # Reduced from 0.5
        
        # Check for safe function usage - less aggressive reduction
        if 'functions' in self.patterns[vuln_type]:
            for safe_func in self.patterns[vuln_type]['context_checks'].get('safe_function', '').split('|'):
                if re.search(fr'{safe_func}\s*\(', snippet, re.DOTALL):
                    score_factors['safe_usage'] *= 0.5  # Reduced from 0.3
        
        # Check code complexity - increased impact
        if re.search(r'for\s*\(|while\s*\(|switch\s*\(|goto\s*\w+', snippet, re.DOTALL):
            score_factors['complexity'] *= 1.5  # Increased from 1.2
        
        # Calculate final score
        final_score = base_score * confidence * self.pattern_weights[vuln_type]
        for factor in score_factors.values():
            final_score *= factor
        
        # Apply minimum threshold - reduced from 300
        if final_score < 200:  # Below this threshold, consider it a false positive
            return 0.0
            
        return final_score

    def _check_memory_issues(self, node: clang.cindex.Cursor, file_path: str) -> Optional[Vulnerability]:
        """Check for memory-related vulnerabilities."""
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            function_name = node.displayname
            
            # Get the code context
            code_snippet = self._get_code_snippet(file_path, node.location.line, context=10)
            
            # Memory allocation checks
            if function_name in ['malloc', 'calloc', 'realloc']:
                # Get the variable name that receives the allocation
                var_name = None
                parent = node.semantic_parent
                if parent and parent.kind == clang.cindex.CursorKind.VAR_DECL:
                    var_name = parent.spelling
                
                if var_name:
                    # Check if the variable is freed anywhere in the function
                    if not re.search(rf'free\s*\(\s*{var_name}\s*\)', code_snippet):
                        # Check if the variable is returned or passed to another function
                        if not re.search(rf'return\s+{var_name}|{var_name}\s*[,)]', code_snippet):
                            return Vulnerability(
                                type="Memory Leak",
                                severity=Severity.HIGH,
                                description=f"Potential memory leak: {var_name} allocated with {function_name} but never freed",
                                location=VulnerabilityLocation(
                                    file=file_path,
                                    line=node.location.line,
                                    column=node.location.column,
                                    snippet=code_snippet
                                ),
                                cwe_id="CWE-401",
                                remediation="Always free allocated memory when it is no longer needed",
                                score=900,
                                confidence=0.9
                            )
            
            # Use after free checks
            elif function_name == 'free':
                # Look for variable usage after free
                var_name = None
                for arg in node.get_arguments():
                    var_name = arg.spelling
                    break
                
                if var_name:
                    # Check for use after free pattern
                    if re.search(rf'free\s*\(\s*{var_name}\s*\)\s*;.*{var_name}\s*[=\[]', code_snippet):
                        return Vulnerability(
                            type="Use After Free",
                            severity=Severity.CRITICAL,
                            description=f"Potential use after free vulnerability: {var_name} is used after being freed",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=node.location.line,
                                column=node.location.column,
                                snippet=code_snippet
                            ),
                            cwe_id="CWE-416",
                            remediation="Set pointers to NULL after freeing and check for NULL before use",
                            score=1000,
                            confidence=0.95
                        )
            
            # Buffer overflow checks
            elif function_name in ['strcpy', 'strcat', 'sprintf']:
                # Check for missing bounds checking
                if not re.search(r'sizeof\s*\(|strlen\s*\(|strncpy|strncat|snprintf', code_snippet):
                    # Check if the destination is a fixed-size buffer
                    for arg in node.get_arguments():
                        if arg.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                            var_name = arg.spelling
                            # Look for array declaration
                            if re.search(rf'{var_name}\s*\[\s*\d+\s*\]', code_snippet):
                                return Vulnerability(
                                    type="Buffer Overflow",
                                    severity=Severity.CRITICAL,
                                    description=f"Potential buffer overflow: {function_name} without size validation on fixed-size buffer",
                                    location=VulnerabilityLocation(
                                        file=file_path,
                                        line=node.location.line,
                                        column=node.location.column,
                                        snippet=code_snippet
                                    ),
                                    cwe_id="CWE-120",
                                    remediation="Use bounds-checking functions (strncpy, strncat, snprintf)",
                                    score=1000,
                                    confidence=0.95
                                )
        
        return None

    def _check_buffer_overflow(self, node: clang.cindex.Cursor, file_path: str) -> Optional[Vulnerability]:
        """Check for buffer overflow vulnerabilities."""
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            function_name = node.displayname
            
            # Get the code context
            code_snippet = self._get_code_snippet(file_path, node.location.line, context=10)
            
            # Check for unsafe string/memory functions
            if function_name in ['strcpy', 'strcat', 'gets', 'sprintf', 'vsprintf', 'scanf', 'fscanf', 'sscanf', 'memcpy', 'memmove']:
                # Look for size validation patterns
                has_size_check = False
                has_safe_alternative = False
                
                # Check for size validation patterns
                size_check_patterns = [
                    r'if\s*\([^)]*\b(strlen|sizeof)\b',
                    r'assert\s*\([^)]*\b(strlen|sizeof)\b',
                    r'\bstrncpy\b|\bstrncat\b|\bsnprintf\b|\bvsnprintf\b',
                    r'memcpy\s*\([^,]+,\s*[^,]+,\s*sizeof\s*\(',
                    r'if\s*\([^)]*\bdst\s*\+\s*len\s*<\s*dst_size\b',
                    r'if\s*\([^)]*\bsize\s*<\s*\d+\b',
                    r'if\s*\([^)]*\blen\s*<\s*\d+\b'
                ]
                
                for pattern in size_check_patterns:
                    if re.search(pattern, code_snippet):
                        has_size_check = True
                        break
                
                # Check for safe alternatives
                safe_alternatives = {
                    'strcpy': 'strncpy',
                    'strcat': 'strncat',
                    'sprintf': 'snprintf',
                    'vsprintf': 'vsnprintf',
                    'gets': 'fgets',
                    'scanf': 'sscanf'
                }
                
                if function_name in safe_alternatives:
                    if re.search(rf'\b{safe_alternatives[function_name]}\b', code_snippet):
                        has_safe_alternative = True
                
                if not (has_size_check or has_safe_alternative):
                    # Check if the destination is a fixed-size buffer
                    for arg in node.get_arguments():
                        if arg.kind == clang.cindex.CursorKind.DECL_REF_EXPR:
                            var_name = arg.spelling
                            # Look for array declaration
                            if re.search(rf'{var_name}\s*\[\s*\d+\s*\]', code_snippet):
                                return Vulnerability(
                                    type="Buffer Overflow",
                                    severity=Severity.CRITICAL,
                                    description=f"Potential buffer overflow vulnerability in {function_name} call on fixed-size buffer",
                                    location=VulnerabilityLocation(
                                        file=file_path,
                                        line=node.location.line,
                                        column=node.location.column,
                                        snippet=code_snippet
                                    ),
                                    cwe_id="CWE-120",
                                    remediation=f"Use {safe_alternatives.get(function_name, 'bounds-checking functions')} with proper size validation",
                                    score=1000,
                                    confidence=0.95
                                )
        
        return None

    def _check_command_injection(self, node: clang.cindex.Cursor, file_path: str) -> Optional[Vulnerability]:
        """Check for command injection vulnerabilities."""
        if node.kind == clang.cindex.CursorKind.CALL_EXPR:
            function_name = node.displayname
            
            # Get the code context
            code_snippet = self._get_code_snippet(file_path, node.location.line, context=10)
            
            # Check for dangerous command execution functions
            if function_name in ['system', 'popen', 'exec', 'execv', 'execve', 'execvp', 'execvpe']:
                # Look for string concatenation or variable usage in command
                has_variable = False
                has_validation = False
                
                # Check arguments for potential injection points
                for arg in node.get_arguments():
                    arg_str = str(arg.type)
                    if 'char' in arg_str and '*' in arg_str:
                        has_variable = True
                        break
                
                # Check for input validation patterns
                validation_patterns = [
                    r'if\s*\([^)]*\b(strlen|strcmp|strncmp|validate|check|sanitize)\b',
                    r'assert\s*\([^)]*\b(strlen|strcmp|strncmp|validate|check|sanitize)\b',
                    r'\b(validate|sanitize|escape|clean)_input\b',
                    r'\b(input_validation|command_validation)\b',
                    r'if\s*\([^)]*\b(contains|matches|startsWith|endsWith)\b',
                    r'if\s*\([^)]*\b(whitelist|blacklist|allowed|forbidden)\b',
                    r'if\s*\([^)]*\b(regex|pattern)\b'
                ]
                
                for pattern in validation_patterns:
                    if re.search(pattern, code_snippet):
                        has_validation = True
                        break
                
                if has_variable and not has_validation:
                    # Check if the command is constructed with user input
                    if re.search(r'strcat|strcpy|sprintf|snprintf', code_snippet):
                        return Vulnerability(
                            type="Command Injection",
                            severity=Severity.CRITICAL,
                            description=f"Potential command injection vulnerability in {function_name} call with user input",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=node.location.line,
                                column=node.location.column,
                                snippet=code_snippet
                            ),
                            cwe_id="CWE-78",
                            remediation="Validate and sanitize all user input before using in system commands",
                            score=1000,
                            confidence=0.95
                        )
        
        return None

    def visit_node(self, node, parent=None):
        """
        Recursively visit nodes in the AST to detect vulnerabilities.
        """
        try:
            if node is None:
                return

            # Get the node location
            location = node.location
            if location and location.file:
                file_path = location.file.name
                line_number = location.line
                column = location.column
                
                # Get code snippet for context
                code_snippet = self._get_code_snippet(file_path, line_number, context=10)
                
                # Check for function calls
                if node.kind == clang.cindex.CursorKind.CALL_EXPR:
                    # Get the actual function name from the referenced declaration
                    func_decl = node.referenced
                    if func_decl:
                        func_name = func_decl.spelling
                    else:
                        func_name = node.spelling
                        
                    print(f"Analyzing function call: {func_name} at line {line_number}")
                    
                    # Buffer Overflow checks
                    if any(unsafe_func in func_name for unsafe_func in ['strcpy', 'strcat', 'gets', 'sprintf']):
                        self.vulnerabilities.append(
                            Vulnerability(
                                type="Buffer Overflow",
                                severity=Severity.CRITICAL,
                                description=f"Potential buffer overflow in {func_name} call",
                                location=VulnerabilityLocation(
                                    file=file_path,
                                    line=line_number,
                                    column=column,
                                    snippet=code_snippet
                                ),
                                cwe_id="CWE-120",
                                remediation=f"Use bounds-checking functions like strncpy, strncat, or snprintf",
                                score=1000,
                                confidence=0.95
                            )
                        )
                    
                    # Command Injection checks
                    elif any(unsafe_func in func_name for unsafe_func in ['system', 'popen', 'exec']):
                        self.vulnerabilities.append(
                            Vulnerability(
                                type="Command Injection",
                                severity=Severity.CRITICAL,
                                description=f"Potential command injection in {func_name} call",
                                location=VulnerabilityLocation(
                                    file=file_path,
                                    line=line_number,
                                    column=column,
                                    snippet=code_snippet
                                ),
                                cwe_id="CWE-78",
                                remediation="Use input validation and sanitization before executing commands",
                                score=1000,
                                confidence=0.95
                            )
                        )
                    
                    # Format String checks
                    elif any(unsafe_func in func_name for unsafe_func in ['printf', 'fprintf', 'sprintf']):
                        args = list(node.get_arguments())
                        if len(args) > 0:
                            self.vulnerabilities.append(
                                Vulnerability(
                                    type="Format String",
                                    severity=Severity.HIGH,
                                    description=f"Potential format string vulnerability in {func_name} call",
                                    location=VulnerabilityLocation(
                                        file=file_path,
                                        line=line_number,
                                        column=column,
                                        snippet=code_snippet
                                    ),
                                    cwe_id="CWE-134",
                                    remediation="Use proper format string validation",
                                    score=900,
                                    confidence=0.9
                                )
                            )
                    
                    # Memory Management checks
                    elif 'malloc' in func_name:
                        self.vulnerabilities.append(
                            Vulnerability(
                                type="Memory Leak",
                                severity=Severity.HIGH,
                                description="Potential memory leak detected",
                                location=VulnerabilityLocation(
                                    file=file_path,
                                    line=line_number,
                                    column=column,
                                    snippet=code_snippet
                                ),
                                cwe_id="CWE-401",
                                remediation="Ensure allocated memory is properly freed",
                                score=900,
                                confidence=0.9
                            )
                        )
                    
                    # SQL Injection checks
                    elif 'query' in code_snippet.lower() and 'select' in code_snippet.lower():
                        self.vulnerabilities.append(
                            Vulnerability(
                                type="SQL Injection",
                                severity=Severity.CRITICAL,
                                description="Potential SQL injection vulnerability detected",
                                location=VulnerabilityLocation(
                                    file=file_path,
                                    line=line_number,
                                    column=column,
                                    snippet=code_snippet
                                ),
                                cwe_id="CWE-89",
                                remediation="Use parameterized queries or prepared statements",
                                score=1000,
                                confidence=0.95
                            )
                        )
                
                # Check for string literals that might contain secrets
                elif node.kind == clang.cindex.CursorKind.STRING_LITERAL:
                    literal = node.spelling
                    secret_patterns = [
                        r'password\s*=\s*["\'].*["\']',
                        r'secret\s*=\s*["\'].*["\']',
                        r'key\s*=\s*["\'].*["\']',
                        r'token\s*=\s*["\'].*["\']',
                        r'credential\s*=\s*["\'].*["\']',
                        r'AKIA[0-9A-Z]{16}',
                        r'eyJhbGciOiJ[^\s]{20,}'
                    ]
                    
                    for pattern in secret_patterns:
                        if re.search(pattern, literal, re.IGNORECASE) and not re.search(r'test|example|dummy', literal, re.IGNORECASE):
                            self.vulnerabilities.append(
                                Vulnerability(
                                    type="Hardcoded Secret",
                                    severity=Severity.HIGH,
                                    description="Potential hardcoded secret detected",
                                    location=VulnerabilityLocation(
                                        file=file_path,
                                        line=line_number,
                                        column=column,
                                        snippet=code_snippet
                                    ),
                                    cwe_id="CWE-798",
                                    remediation="Store sensitive data in environment variables or secure configuration",
                                    score=900,
                                    confidence=0.9
                                )
                            )
                            break
            
            # Recursively visit children
            for child in node.get_children():
                self.visit_node(child, node)
                
        except Exception as e:
            print(f"Error in visit_node: {str(e)}")
            # Continue processing other nodes even if one fails
            pass

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Analyze a single file for vulnerabilities with improved detection."""
        self.vulnerabilities = []
        
        try:
            print(f"Analyzing file: {file_path}")
            
            # Read the file content
            with open(file_path, 'r') as f:
                content = f.read()
                lines = content.split('\n')
            
            # Direct pattern matching for various vulnerabilities
            for i, line in enumerate(lines, 1):
                # Buffer Overflow checks
                if any(func in line for func in ['strcpy', 'strcat', 'gets', 'sprintf']):
                    self.vulnerabilities.append(
                        Vulnerability(
                            type="Buffer Overflow",
                            severity=Severity.CRITICAL,
                            description="Potential buffer overflow vulnerability detected",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=i,
                                column=1,
                                snippet=self._get_code_snippet(file_path, i)
                            ),
                            cwe_id="CWE-120",
                            remediation="Use bounds-checking functions like strncpy, strncat, or snprintf",
                            score=1000,
                            confidence=0.95
                        )
                    )
                
                # Command Injection checks
                if any(func in line for func in ['system', 'popen', 'exec']):
                    self.vulnerabilities.append(
                        Vulnerability(
                            type="Command Injection",
                            severity=Severity.CRITICAL,
                            description="Potential command injection vulnerability detected",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=i,
                                column=1,
                                snippet=self._get_code_snippet(file_path, i)
                            ),
                            cwe_id="CWE-78",
                            remediation="Use input validation and sanitization before executing commands",
                            score=1000,
                            confidence=0.95
                        )
                    )
                
                # Format String checks
                if 'printf' in line and '%' in line and not line.strip().startswith('//'):
                    self.vulnerabilities.append(
                        Vulnerability(
                            type="Format String",
                            severity=Severity.HIGH,
                            description="Potential format string vulnerability detected",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=i,
                                column=1,
                                snippet=self._get_code_snippet(file_path, i)
                            ),
                            cwe_id="CWE-134",
                            remediation="Use proper format string validation",
                            score=900,
                            confidence=0.9
                        )
                    )
                
                # Memory Management checks
                if 'malloc' in line and not 'free' in '\n'.join(lines[i:i+10]):
                    self.vulnerabilities.append(
                        Vulnerability(
                            type="Memory Leak",
                            severity=Severity.HIGH,
                            description="Potential memory leak detected",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=i,
                                column=1,
                                snippet=self._get_code_snippet(file_path, i)
                            ),
                            cwe_id="CWE-401",
                            remediation="Ensure allocated memory is properly freed",
                            score=900,
                            confidence=0.9
                        )
                    )
                
                # SQL Injection checks
                if ('SELECT' in line.upper() or 'INSERT' in line.upper() or 'UPDATE' in line.upper()) and '%s' in line:
                    self.vulnerabilities.append(
                        Vulnerability(
                            type="SQL Injection",
                            severity=Severity.CRITICAL,
                            description="Potential SQL injection vulnerability detected",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=i,
                                column=1,
                                snippet=self._get_code_snippet(file_path, i)
                            ),
                            cwe_id="CWE-89",
                            remediation="Use parameterized queries or prepared statements",
                            score=1000,
                            confidence=0.95
                        )
                    )
                
                # Path Traversal checks
                if ('fopen' in line or 'open' in line) and '%s' in line:
                    self.vulnerabilities.append(
                        Vulnerability(
                            type="Path Traversal",
                            severity=Severity.HIGH,
                            description="Potential path traversal vulnerability detected",
                            location=VulnerabilityLocation(
                                file=file_path,
                                line=i,
                                column=1,
                                snippet=self._get_code_snippet(file_path, i)
                            ),
                            cwe_id="CWE-22",
                            remediation="Validate and sanitize file paths before access",
                            score=900,
                            confidence=0.9
                        )
                    )
                
                # Hardcoded Secrets checks
                secret_patterns = [
                    r'password\s*=\s*["\'].*["\']',
                    r'secret\s*=\s*["\'].*["\']',
                    r'key\s*=\s*["\'].*["\']',
                    r'token\s*=\s*["\'].*["\']',
                    r'credential\s*=\s*["\'].*["\']',
                    r'AKIA[0-9A-Z]{16}',
                    r'eyJhbGciOiJ[^\s]{20,}'
                ]
                
                for pattern in secret_patterns:
                    if re.search(pattern, line, re.IGNORECASE) and not re.search(r'test|example|dummy', line, re.IGNORECASE):
                        self.vulnerabilities.append(
                            Vulnerability(
                                type="Hardcoded Secret",
                                severity=Severity.HIGH,
                                description="Potential hardcoded secret detected",
                                location=VulnerabilityLocation(
                                    file=file_path,
                                    line=i,
                                    column=1,
                                    snippet=self._get_code_snippet(file_path, i)
                                ),
                                cwe_id="CWE-798",
                                remediation="Store sensitive data in environment variables or secure configuration",
                                score=900,
                                confidence=0.9
                            )
                        )
                        break
            
            print(f"Found {len(self.vulnerabilities)} vulnerabilities")
            return self.vulnerabilities
            
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
            return []

    def _analyze_python_file(self, file_path: str) -> List[Vulnerability]:
        """Analyze a Python file for vulnerabilities."""
        vulnerabilities: List[Vulnerability] = []
        
        try:
            with open(file_path, 'r') as f:
                source = f.read()
            
            # Parse Python AST
            tree = ast.parse(source)
            
            # Analyze imports for unsafe modules
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for name in node.names:
                        if name.name in ['pickle', 'marshal', 'yaml']:
                            location = VulnerabilityLocation(
                                file=str(file_path),
                                line=node.lineno,
                                column=node.col_offset,
                                snippet=self._get_code_snippet(str(file_path), node.lineno)
                            )
                            vulnerability = Vulnerability(
                                type='Insecure Deserialization',
                                severity=Severity.HIGH,
                                description='Potential insecure deserialization vulnerability detected',
                                location=location,
                                cwe_id='CWE-502',
                                remediation='Use safe deserialization methods and validate input',
                                score=900,
                                confidence=0.9
                            )
                            vulnerabilities.append(vulnerability)
                
                # Check for eval and exec
                elif isinstance(node, (ast.Call, ast.Expr)):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                        if node.func.id in ['eval', 'exec']:
                            location = VulnerabilityLocation(
                                file=str(file_path),
                                line=node.lineno,
                                column=node.col_offset,
                                snippet=self._get_code_snippet(str(file_path), node.lineno)
                            )
                            vulnerability = Vulnerability(
                                type='Code Injection',
                                severity=Severity.CRITICAL,
                                description='Potential code injection vulnerability detected',
                                location=location,
                                cwe_id='CWE-94',
                                remediation='Avoid using eval and exec with untrusted input',
                                score=1000,
                                confidence=1.0
                            )
                            vulnerabilities.append(vulnerability)
                
                # Check for SQL injection
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['execute', 'executemany', 'query']:
                        # Check if the query is constructed with string concatenation
                        for arg in node.args:
                            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                                location = VulnerabilityLocation(
                                    file=str(file_path),
                                    line=node.lineno,
                                    column=node.col_offset,
                                    snippet=self._get_code_snippet(str(file_path), node.lineno)
                                )
                                vulnerability = Vulnerability(
                                    type='SQL Injection',
                                    severity=Severity.CRITICAL,
                                    description='Potential SQL injection vulnerability detected',
                                    location=location,
                                    cwe_id='CWE-89',
                                    remediation='Use parameterized queries or prepared statements',
                                    score=1000,
                                    confidence=0.9
                                )
                                vulnerabilities.append(vulnerability)
                
                # Check for command injection
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['system', 'popen', 'call', 'run']:
                        # Check if the command is constructed with string concatenation
                        for arg in node.args:
                            if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                                location = VulnerabilityLocation(
                                    file=str(file_path),
                                    line=node.lineno,
                                    column=node.col_offset,
                                    snippet=self._get_code_snippet(str(file_path), node.lineno)
                                )
                                vulnerability = Vulnerability(
                                    type='Command Injection',
                                    severity=Severity.CRITICAL,
                                    description='Potential command injection vulnerability detected',
                                    location=location,
                                    cwe_id='CWE-78',
                                    remediation='Use subprocess with shell=False and proper input validation',
                                    score=1000,
                                    confidence=0.9
                                )
                                vulnerabilities.append(vulnerability)
                
                # Check for XSS in web frameworks
                elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                    if node.func.attr in ['render_template', 'render', 'render_string']:
                        # Check if user input is directly passed to template
                        for arg in node.args:
                            if isinstance(arg, ast.Dict):
                                for key in arg.keys:
                                    if isinstance(key, ast.Str) and key.s in ['content', 'html', 'body']:
                                        location = VulnerabilityLocation(
                                            file=str(file_path),
                                            line=node.lineno,
                                            column=node.col_offset,
                                            snippet=self._get_code_snippet(str(file_path), node.lineno)
                                        )
                                        vulnerability = Vulnerability(
                                            type='Cross-Site Scripting',
                                            severity=Severity.HIGH,
                                            description='Potential XSS vulnerability detected',
                                            location=location,
                                            cwe_id='CWE-79',
                                            remediation='Use proper output encoding and input validation',
                                            score=900,
                                            confidence=0.8
                                        )
                                        vulnerabilities.append(vulnerability)
                
                # Check for hardcoded secrets
                elif isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if target.id.lower() in ['password', 'secret', 'key', 'token', 'credential']:
                                if isinstance(node.value, ast.Str):
                                    # Check if it's a test or example value
                                    if not re.search(r'test|example|demo|sample|placeholder', node.value.s, re.I):
                                        location = VulnerabilityLocation(
                                            file=str(file_path),
                                            line=node.lineno,
                                            column=node.col_offset,
                                            snippet=self._get_code_snippet(str(file_path), node.lineno)
                                        )
                                        vulnerability = Vulnerability(
                                            type='Hardcoded Secret',
                                            severity=Severity.HIGH,
                                            description='Potential hardcoded secret or credential detected',
                                            location=location,
                                            cwe_id='CWE-798',
                                            remediation='Store sensitive data in secure configuration files or environment variables',
                                            score=900,
                                            confidence=0.8
                                        )
                                        vulnerabilities.append(vulnerability)
        
        except Exception as e:
            print(f"Error analyzing Python file {file_path}: {str(e)}")
        
        return vulnerabilities

    def _analyze_javascript_file(self, file_path: str) -> List[Vulnerability]:
        """Analyze a JavaScript/TypeScript file for vulnerabilities."""
        vulnerabilities: List[Vulnerability] = []
        
        try:
            with open(file_path, 'r') as f:
                source = f.read()
            
            # Parse JavaScript AST
            tree = pyjsparser.parse(source)
            
            # Analyze for XSS vulnerabilities
            def visit_node(node):
                if node['type'] == 'CallExpression':
                    if node['callee']['type'] == 'MemberExpression':
                        if node['callee']['property']['name'] in ['innerHTML', 'outerHTML', 'write', 'writeln']:
                            location = VulnerabilityLocation(
                                file=str(file_path),
                                line=node['loc']['start']['line'],
                                column=node['loc']['start']['column'],
                                snippet=self._get_code_snippet(str(file_path), node['loc']['start']['line'])
                            )
                            vulnerability = Vulnerability(
                                type='xss',
                                severity=Severity.HIGH,
                                description='Potential Cross-Site Scripting (XSS) vulnerability detected',
                                location=location,
                                cwe_id='CWE-79',
                                remediation='Use proper output encoding and input validation',
                                score=900,
                                confidence=0.9
                            )
                            vulnerabilities.append(vulnerability)
                    
                    elif node['callee']['type'] == 'Identifier':
                        if node['callee']['name'] in ['eval', 'setTimeout', 'setInterval']:
                            location = VulnerabilityLocation(
                                file=str(file_path),
                                line=node['loc']['start']['line'],
                                column=node['loc']['start']['column'],
                                snippet=self._get_code_snippet(str(file_path), node['loc']['start']['line'])
                            )
                            vulnerability = Vulnerability(
                                type='command_injection',
                                severity=Severity.CRITICAL,
                                description='Potential code injection vulnerability detected',
                                location=location,
                                cwe_id='CWE-94',
                                remediation='Avoid using eval with untrusted input',
                                score=1000,
                                confidence=1.0
                            )
                            vulnerabilities.append(vulnerability)
                
                # Recursively visit children
                for key, value in node.items():
                    if isinstance(value, dict):
                        visit_node(value)
                    elif isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict):
                                visit_node(item)
            
            visit_node(tree)
        
        except Exception as e:
            print(f"Error analyzing JavaScript file {file_path}: {str(e)}")
        
        return vulnerabilities

    def analyze_directory(self, directory: str, file_patterns: List[str] = [
        "*.c", "*.cpp", "*.h", "*.hpp",  # C/C++
        "*.py", "*.pyw",  # Python
        "*.js", "*.jsx", "*.ts", "*.tsx",  # JavaScript/TypeScript
        "*.java", "*.kt",  # Java/Kotlin
        "*.php",  # PHP
        "*.rb",  # Ruby
        "*.go",  # Go
        "*.rs",  # Rust
        "*.swift",  # Swift
        "*.cs",  # C#
    ]) -> List[Vulnerability]:
        """Analyze all matching files in a directory recursively."""
        vulnerabilities: List[Vulnerability] = []
        directory_path = Path(directory)
        
        for pattern in file_patterns:
            for file_path in directory_path.rglob(pattern):
                vulnerabilities.extend(self.analyze_file(str(file_path)))
        
        return vulnerabilities

    def mark_as_false_positive(self, vuln_type: str, file_path: str, line: int):
        """Mark a vulnerability as a false positive and update learned patterns."""
        snippet = self._get_code_snippet(file_path, line, context=20)
        self._update_learned_patterns(vuln_type, snippet, True)

    def mark_as_true_positive(self, vuln_type: str, file_path: str, line: int):
        """Mark a vulnerability as a true positive and update learned patterns."""
        snippet = self._get_code_snippet(file_path, line, context=20)
        self._update_learned_patterns(vuln_type, snippet, False) 