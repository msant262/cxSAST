from backend.analyzer.core import VulnerabilityAnalyzer

def main():
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python run_analyzer.py <file_to_analyze>")
        sys.exit(1)
    
    file_to_analyze = sys.argv[1]
    print(f"Analyzing file: {file_to_analyze}")
    
    analyzer = VulnerabilityAnalyzer()
    vulnerabilities = analyzer.analyze_file(file_to_analyze)
    
    print("\nAnalysis Results:")
    print("=================")
    
    if not vulnerabilities:
        print("No vulnerabilities found.")
    else:
        for i, vuln in enumerate(vulnerabilities, 1):
            print(f"\nVulnerability #{i}:")
            print(f"Type: {vuln.type}")
            print(f"Severity: {vuln.severity}")
            print(f"Description: {vuln.description}")
            print(f"Location: {vuln.location.file}:{vuln.location.line}")
            print(f"Code snippet:\n{vuln.location.snippet}")
            print(f"CWE: {vuln.cwe_id}")
            print(f"Remediation: {vuln.remediation}")
            print(f"Score: {vuln.score}")
            print(f"Confidence: {vuln.confidence}")

if __name__ == "__main__":
    main() 