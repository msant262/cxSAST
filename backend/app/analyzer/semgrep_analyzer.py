import subprocess
import json
import os
from typing import List, Dict, Any
from dataclasses import dataclass
from enum import Enum
import tempfile
import shutil

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
    confidence: float

class SemgrepAnalyzer:
    def __init__(self):
        self.semgrep_path = shutil.which('semgrep')
        if not self.semgrep_path:
            raise Exception("Semgrep not found. Please install it using 'pip install semgrep'")
        
        # Create temporary directory for rules
        self.temp_dir = tempfile.mkdtemp()
        self.rules_dir = os.path.join(self.temp_dir, 'rules')
        os.makedirs(self.rules_dir, exist_ok=True)
        
        # Download default rules
        self._download_default_rules()

    def _download_default_rules(self):
        """Download default Semgrep rules from the official repository"""
        try:
            subprocess.run([
                'semgrep',
                '--config', 'p/r2c-security-audit',
                '--config', 'p/owasp-top-ten',
                '--config', 'p/cwe-top-25',
                '--config', 'p/security',
                '--config', 'p/cpp',
                '--config', 'p/c',
                '--dry-run'
            ], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error downloading default rules: {e}")
            raise

    def _run_semgrep(self, target_path: str, rules: List[str] = None) -> Dict[str, Any]:
        """Run Semgrep scan on the target path"""
        cmd = [
            self.semgrep_path,
            '--json',
            '--config', 'p/r2c-security-audit',
            '--config', 'p/owasp-top-ten',
            '--config', 'p/cwe-top-25',
            '--config', 'p/security',
            '--config', 'p/cpp',
            '--config', 'p/c',
            target_path
        ]

        if rules:
            for rule in rules:
                cmd.extend(['--config', rule])

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return json.loads(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"Error running Semgrep: {e}")
            print(f"Semgrep output: {e.output}")
            raise

    def _convert_severity(self, semgrep_severity: str) -> Severity:
        """Convert Semgrep severity to our Severity enum"""
        severity_map = {
            'ERROR': Severity.CRITICAL,
            'WARNING': Severity.HIGH,
            'INFO': Severity.MEDIUM
        }
        return severity_map.get(semgrep_severity, Severity.LOW)

    def _get_code_snippet(self, file_path: str, line: int, context: int = 5) -> str:
        """Get the code snippet around the vulnerability"""
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
                start = max(0, line - context - 1)
                end = min(len(lines), line + context)
                return ''.join(lines[start:end])
        except Exception:
            return ""

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Analyze a single file for vulnerabilities using Semgrep"""
        vulnerabilities = []
        
        try:
            results = self._run_semgrep(file_path)
            
            for result in results.get('results', []):
                # Extract vulnerability information
                vuln_type = result.get('check_id', 'Unknown')
                severity = self._convert_severity(result.get('extra', {}).get('severity', 'INFO'))
                description = result.get('extra', {}).get('message', 'No description available')
                cwe_id = result.get('extra', {}).get('metadata', {}).get('cwe', 'Unknown')
                remediation = result.get('extra', {}).get('fix', 'No remediation available')
                
                # Create location object
                location = VulnerabilityLocation(
                    file=result.get('path', ''),
                    line=result.get('start', {}).get('line', 0),
                    column=result.get('start', {}).get('col', 0),
                    snippet=self._get_code_snippet(
                        result.get('path', ''),
                        result.get('start', {}).get('line', 0)
                    )
                )
                
                # Calculate score based on severity
                score_map = {
                    Severity.CRITICAL: 1000,
                    Severity.HIGH: 900,
                    Severity.MEDIUM: 700,
                    Severity.LOW: 500
                }
                score = score_map.get(severity, 500)
                
                # Create vulnerability object
                vulnerability = Vulnerability(
                    type=vuln_type,
                    severity=severity,
                    description=description,
                    location=location,
                    cwe_id=cwe_id,
                    remediation=remediation,
                    score=score,
                    confidence=0.9  # Semgrep has high confidence in its findings
                )
                
                vulnerabilities.append(vulnerability)
        
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
        
        return vulnerabilities

    def analyze_directory(self, directory_path: str, file_patterns: List[str] = None) -> List[Vulnerability]:
        """Analyze all files in a directory using Semgrep"""
        vulnerabilities = []
        
        try:
            results = self._run_semgrep(directory_path)
            
            for result in results.get('results', []):
                # Skip files that don't match the patterns
                if file_patterns and not any(result.get('path', '').endswith(pattern) for pattern in file_patterns):
                    continue
                
                # Extract vulnerability information
                vuln_type = result.get('check_id', 'Unknown')
                severity = self._convert_severity(result.get('extra', {}).get('severity', 'INFO'))
                description = result.get('extra', {}).get('message', 'No description available')
                cwe_id = result.get('extra', {}).get('metadata', {}).get('cwe', 'Unknown')
                remediation = result.get('extra', {}).get('fix', 'No remediation available')
                
                # Create location object
                location = VulnerabilityLocation(
                    file=result.get('path', ''),
                    line=result.get('start', {}).get('line', 0),
                    column=result.get('start', {}).get('col', 0),
                    snippet=self._get_code_snippet(
                        result.get('path', ''),
                        result.get('start', {}).get('line', 0)
                    )
                )
                
                # Calculate score based on severity
                score_map = {
                    Severity.CRITICAL: 1000,
                    Severity.HIGH: 900,
                    Severity.MEDIUM: 700,
                    Severity.LOW: 500
                }
                score = score_map.get(severity, 500)
                
                # Create vulnerability object
                vulnerability = Vulnerability(
                    type=vuln_type,
                    severity=severity,
                    description=description,
                    location=location,
                    cwe_id=cwe_id,
                    remediation=remediation,
                    score=score,
                    confidence=0.9  # Semgrep has high confidence in its findings
                )
                
                vulnerabilities.append(vulnerability)
        
        except Exception as e:
            print(f"Error analyzing directory {directory_path}: {str(e)}")
        
        return vulnerabilities

    def __del__(self):
        """Clean up temporary files"""
        try:
            shutil.rmtree(self.temp_dir)
        except Exception:
            pass 