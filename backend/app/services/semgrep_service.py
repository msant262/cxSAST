import subprocess
import json
import os
from typing import List, Dict
from pathlib import Path
from ..config import SEMGREP_CONFIG

class SemgrepService:
    def __init__(self):
        self.config = SEMGREP_CONFIG

    def analyze_file(self, file_path: str) -> List[Dict]:
        """Analisa um arquivo usando Semgrep"""
        try:
            result = subprocess.run(
                ["semgrep", "--json", file_path],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return self._parse_results(result.stdout)
            return []
        except Exception as e:
            print(f"Error analyzing file {file_path}: {str(e)}")
            return []

    def analyze_directory(self, directory: str) -> List[Dict]:
        """Analisa um diretório completo usando Semgrep"""
        try:
            result = subprocess.run(
                ["semgrep", "--json", directory],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                return self._parse_results(result.stdout)
            return []
        except Exception as e:
            print(f"Error analyzing directory {directory}: {str(e)}")
            return []

    def _parse_results(self, semgrep_output: str) -> List[Dict]:
        """Converte a saída do Semgrep para o formato interno"""
        try:
            results = json.loads(semgrep_output)
            vulnerabilities = []
            
            for result in results.get("results", []):
                vulnerability = {
                    "rule_id": result.get("check_id"),
                    "severity": result.get("extra", {}).get("severity", "INFO"),
                    "message": result.get("extra", {}).get("message", ""),
                    "line_number": result.get("start", {}).get("line", 0),
                    "metadata": {
                        "path": result.get("path"),
                        "start": result.get("start"),
                        "end": result.get("end"),
                        "extra": result.get("extra", {})
                    }
                }
                vulnerabilities.append(vulnerability)
            
            return vulnerabilities
        except Exception as e:
            print(f"Error parsing Semgrep results: {str(e)}")
            return [] 