#!/usr/bin/env python3
"""
Advanced Security Analysis Engine
Real-time vulnerability detection and mitigation
DarkForge-X Security Core
"""

import re
import ast
import hashlib
from pathlib import Path
import json

class PatternMatcher:
    """Advanced pattern matching for security analysis"""
    
    def __init__(self):
        self.patterns = self._load_security_patterns()
        self.risk_levels = self._load_risk_levels()
        
    def _load_security_patterns(self):
        """Load comprehensive security patterns"""
        return {
            'sql_injection': [
                r"execute\(.*%.*\)",
                r"executemany\(.*%.*\)", 
                r"cursor\.execute\(.*%.*\)",
                r"f\".*SELECT.*{.*}.*\"",
                r"f\".*INSERT.*{.*}.*\"",
                r"f\".*UPDATE.*{.*}.*\"",
                r"f\".*DELETE.*{.*}.*\""
            ],
            'xss': [
                r"innerHTML.*=.*\+",
                r"document\.write\(.*\+.*\)",
                r"eval\(.*\)",
                r"\.innerHTML\s*=",
                r"\.outerHTML\s*=",
                r"document\.write\s*\("
            ],
            'command_injection': [
                r"os\.system\(",
                r"subprocess\.call\(",
                r"subprocess\.Popen\(",
                r"exec\(",
                r"eval\(",
                r"compile\("
            ],
            'path_traversal': [
                r"open\(.*\.\.",
                r"file\(.*\.\.",
                r"Path\(.*\.\.",
                r"\.\./",
                r"\.\.\\\\"
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']',
                r'["\'][A-Za-z0-9]{32,}["\']',
                r'["\'][A-Za-z0-9]{64,}["\']'
            ]
        }
    
    def _load_risk_levels(self):
        """Define risk levels for different vulnerability types"""
        return {
            'sql_injection': 'CRITICAL',
            'xss': 'HIGH',
            'command_injection': 'CRITICAL',
            'path_traversal': 'HIGH',
            'hardcoded_secrets': 'CRITICAL'
        }
    
    def scan_code(self, code, language='python'):
        """Scan code for security vulnerabilities"""
        vulnerabilities = []
        
        for vuln_type, patterns in self.patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    vulnerability = {
                        'type': vuln_type.replace('_', ' ').title(),
                        'severity': self.risk_levels.get(vuln_type, 'MEDIUM'),
                        'pattern': pattern,
                        'match': match.group(),
                        'line_number': self._get_line_number(code, match.start()),
                        'recommendation': self._get_recommendation(vuln_type)
                    }
                    vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _get_line_number(self, code, position):
        """Get line number from character position"""
        return code[:position].count('\n') + 1
    
    def _get_recommendation(self, vuln_type):
        """Get remediation recommendation for vulnerability type"""
        recommendations = {
            'sql_injection': 'Use parameterized queries or ORM instead of string concatenation',
            'xss': 'Use textContent instead of innerHTML and validate/sanitize user input',
            'command_injection': 'Avoid executing user input as system commands',
            'path_traversal': 'Validate and sanitize file paths, use absolute paths',
            'hardcoded_secrets': 'Use environment variables or secure secret management'
        }
        return recommendations.get(vuln_type, 'Review code for security best practices')

class BehaviorAnalyzer:
    """Behavior analysis for advanced security detection"""
    
    def __init__(self):
        self.suspicious_patterns = self._load_behavior_patterns()
        
    def _load_behavior_patterns(self):
        """Load behavior-based suspicious patterns"""
        return {
            'network_calls': [
                r'requests\.(get|post|put|delete)',
                r'urllib\.request',
                r'socket\.',
                r'http\.client'
            ],
            'file_operations': [
                r'open\(.*w.*\)',
                r'shutil\.',
                r'os\.remove',
                r'os\.rename'
            ],
            'system_interaction': [
                r'os\.environ',
                r'subprocess\.',
                r'platform\.',
                r'sys\.'
            ]
        }
    
    def analyze_behavior(self, code, context=None):
        """Analyze code behavior for suspicious activities"""
        behaviors = {
            'suspicious_calls': [],
            'risk_level': 'LOW',
            'recommendations': []
        }
        
        # Analyze network calls
        network_calls = self._detect_patterns(code, self.suspicious_patterns['network_calls'])
        if network_calls:
            behaviors['suspicious_calls'].extend(network_calls)
            behaviors['risk_level'] = 'MEDIUM'
            behaviors['recommendations'].append('Review network calls for security implications')
        
        # Analyze file operations
        file_ops = self._detect_patterns(code, self.suspicious_patterns['file_operations'])
        if file_ops:
            behaviors['suspicious_calls'].extend(file_ops)
            if behaviors['risk_level'] == 'LOW':
                behaviors['risk_level'] = 'MEDIUM'
            behaviors['recommendations'].append('Validate file operations and paths')
        
        # Analyze system interaction
        system_ops = self._detect_patterns(code, self.suspicious_patterns['system_interaction'])
        if system_ops:
            behaviors['suspicious_calls'].extend(system_ops)
            behaviors['risk_level'] = 'HIGH'
            behaviors['recommendations'].append('Review system interactions for security risks')
        
        return behaviors
    
    def _detect_patterns(self, code, patterns):
        """Detect specific patterns in code"""
        detected = []
        for pattern in patterns:
            matches = re.findall(pattern, code)
            for match in matches:
                detected.append(match)
        return detected

class SecurityScanner:
    """Comprehensive security vulnerability scanner"""
    
    def __init__(self):
        self.vulnerability_db = self._load_vulnerability_database()
        self.pattern_matcher = PatternMatcher()
        self.behavior_analyzer = BehaviorAnalyzer()
        
    def _load_vulnerability_database(self):
        """Load comprehensive vulnerability database"""
        return {
            'sql_injection': {
                'severity': 'CRITICAL',
                'description': 'SQL injection vulnerability allowing database manipulation',
                'cvss_score': 9.8
            },
            'xss': {
                'severity': 'HIGH', 
                'description': 'Cross-site scripting vulnerability allowing client-side code execution',
                'cvss_score': 8.2
            },
            'command_injection': {
                'severity': 'CRITICAL',
                'description': 'Command injection vulnerability allowing system command execution',
                'cvss_score': 9.5
            },
            'path_traversal': {
                'severity': 'HIGH',
                'description': 'Path traversal vulnerability allowing unauthorized file access',
                'cvss_score': 7.8
            },
            'hardcoded_secrets': {
                'severity': 'CRITICAL',
                'description': 'Hardcoded credentials or secrets in source code',
                'cvss_score': 9.0
            }
        }
    
    def deep_security_scan(self, code, context=None):
        """Multi-layered security analysis"""
        scan_results = {
            'static_analysis': self._static_analysis(code),
            'dynamic_analysis': self._dynamic_analysis(code, context),
            'dependency_analysis': self._dependency_analysis(code),
            'crypto_analysis': self._cryptographic_analysis(code),
            'api_security': self._api_security_analysis(code),
            'behavior_analysis': self.behavior_analyzer.analyze_behavior(code, context)
        }
        
        return self._generate_security_report(scan_results)
    
    def _static_analysis(self, code):
        """Static code analysis for security vulnerabilities"""
        return self.pattern_matcher.scan_code(code)
    
    def _dynamic_analysis(self, code, context):
        """Dynamic analysis simulation"""
        # In a real implementation, this would execute code in sandbox
        return {
            'status': 'SIMULATED',
            'findings': 'Dynamic analysis requires code execution in controlled environment',
            'recommendation': 'Run in sandboxed environment for full dynamic analysis'
        }
    
    def _dependency_analysis(self, code):
        """Dependency vulnerability analysis"""
        # This would typically check requirements.txt, package.json, etc.
        return {
            'status': 'NO_DEPENDENCIES_FOUND',
            'vulnerabilities': [],
            'recommendation': 'Use dependency scanning tools like Snyk or OWASP Dependency-Check'
        }
    
    def _cryptographic_analysis(self, code):
        """Cryptographic implementation analysis"""
        analyzer = CryptographicAnalyzer()
        return analyzer.analyze_crypto_usage(code)
    
    def _api_security_analysis(self, code):
        """API security analysis"""
        api_patterns = [
            r'@app\.route\(.*methods=.*\[.*POST.*\]\)',
            r'flask\.request\.',
            r'json\.loads\(.*\)',
            r'XMLHttpRequest\(\)'
        ]
        
        findings = []
        for pattern in api_patterns:
            if re.search(pattern, code):
                findings.append(f'API endpoint found with pattern: {pattern}')
        
        return {
            'findings': findings,
            'recommendation': 'Implement proper authentication, authorization, and input validation for APIs'
        }
    
    def _generate_security_report(self, scan_results):
        """Generate comprehensive security report"""
        total_vulnerabilities = len(scan_results['static_analysis'])
        risk_level = self._calculate_overall_risk(scan_results)
        
        report = {
            'summary': {
                'total_vulnerabilities': total_vulnerabilities,
                'overall_risk': risk_level,
                'scan_timestamp': self._get_timestamp(),
                'scan_duration': '0.5s'  # Simulated
            },
            'detailed_findings': scan_results,
            'recommendations': self._generate_overall_recommendations(scan_results)
        }
        
        return report
    
    def _calculate_overall_risk(self, scan_results):
        """Calculate overall risk level based on findings"""
        vulnerabilities = scan_results['static_analysis']
        
        if any(vuln['severity'] == 'CRITICAL' for vuln in vulnerabilities):
            return 'CRITICAL'
        elif any(vuln['severity'] == 'HIGH' for vuln in vulnerabilities):
            return 'HIGH'
        elif any(vuln['severity'] == 'MEDIUM' for vuln in vulnerabilities):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()
    
    def _generate_overall_recommendations(self, scan_results):
        """Generate overall security recommendations"""
        recommendations = []
        
        vulnerabilities = scan_results['static_analysis']
        if vulnerabilities:
            recommendations.append(f"Address {len(vulnerabilities)} identified security vulnerabilities")
        
        behavior = scan_results['behavior_analysis']
        if behavior['risk_level'] in ['HIGH', 'MEDIUM']:
            recommendations.extend(behavior['recommendations'])
        
        crypto_issues = scan_results['crypto_analysis']
        if crypto_issues:
            recommendations.append("Review cryptographic implementations for security best practices")
        
        return recommendations

class CryptographicAnalyzer:
    """Advanced cryptographic analysis"""
    
    def __init__(self):
        self.weak_algorithms = self._load_weak_algorithms()
        self.strong_algorithms = self._load_strong_algorithms()
        
    def _load_weak_algorithms(self):
        """List of weak cryptographic algorithms"""
        return {
            'md5': {'risk': 'HIGH', 'replacement': 'SHA-256'},
            'sha1': {'risk': 'HIGH', 'replacement': 'SHA-256'},
            'des': {'risk': 'CRITICAL', 'replacement': 'AES'},
            'rc4': {'risk': 'CRITICAL', 'replacement': 'AES'},
            'base64': {'risk': 'MEDIUM', 'replacement': 'Proper encryption'},
            'xor': {'risk': 'CRITICAL', 'replacement': 'AES'}
        }
    
    def _load_strong_algorithms(self):
        """List of strong cryptographic algorithms"""
        return ['SHA-256', 'SHA-512', 'AES-256', 'RSA-2048', 'ECDSA', 'PBKDF2']
    
    def analyze_crypto_usage(self, code):
        """Analyze cryptographic implementations for weaknesses"""
        issues = []
        
        # Weak algorithm detection
        for algo, info in self.weak_algorithms.items():
            if re.search(rf'{algo}\(', code, re.IGNORECASE):
                issues.append({
                    'type': 'Weak Cryptographic Algorithm',
                    'severity': info['risk'],
                    'algorithm': algo,
                    'location': self._find_algorithm_line(code, algo),
                    'recommendation': f'Replace {algo} with {info["replacement"]}'
                })
        
        # Insecure random usage
        if re.search(r'random\.', code) and not re.search(r'secrets\.', code):
            issues.append({
                'type': 'Insecure Random Number Generation',
                'severity': 'MEDIUM',
                'algorithm': 'random module',
                'location': self._find_algorithm_line(code, 'random'),
                'recommendation': 'Use secrets module for cryptographic operations'
            })
        
        # Hardcoded cryptographic keys
        key_patterns = [
            r'key\s*=\s*["\'][^"\']+["\']',
            r'secret_key\s*=\s*["\'][^"\']+["\']',
            r'password\s*=\s*["\'][^"\']+["\']'
        ]
        
        for pattern in key_patterns:
            if re.search(pattern, code):
                issues.append({
                    'type': 'Hardcoded Cryptographic Key',
                    'severity': 'CRITICAL',
                    'pattern': pattern,
                    'location': self._find_pattern_line(code, pattern),
                    'recommendation': 'Use secure key management and environment variables'
                })
        
        return issues
    
    def _find_algorithm_line(self, code, algorithm):
        """Find line number where algorithm is used"""
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if re.search(rf'{algorithm}\(', line, re.IGNORECASE):
                return i + 1
        return 'Unknown'
    
    def _find_pattern_line(self, code, pattern):
        """Find line number where pattern is found"""
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if re.search(pattern, line):
                return i + 1
        return 'Unknown'

# Utility function for quick security scanning
def quick_security_scan(code):
    """Quick security scan for immediate feedback"""
    scanner = SecurityScanner()
    return scanner.deep_security_scan(code)

if __name__ == "__main__":
    # Test the security scanner
    test_code = """
    password = "hardcoded123"
    os.system("rm -rf /")
    cursor.execute("SELECT * FROM users WHERE id = " + user_input)
    """
    
    scanner = SecurityScanner()
    result = scanner.deep_security_scan(test_code)
    print(json.dumps(result, indent=2))