from analyzer.core import VulnerabilityAnalyzer
import os

def main():
    analyzer = VulnerabilityAnalyzer()
    test_file = os.path.join(os.path.dirname(__file__), "test_files", "vulnerable.cpp")
    
    print(f"Analyzing file: {test_file}")
    vulnerabilities = analyzer.analyze_file(test_file)
    
    print("\nFound vulnerabilities:")
    for vuln in vulnerabilities:
        print(f"\nType: {vuln.rule}")
        print(f"Severity: {vuln.severity}")
        print(f"Line: {vuln.line}")
        print(f"Message: {vuln.message}")
        print(f"Source code: {vuln.source_code}")

if __name__ == "__main__":
    main() 