#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Analyzer - OWASP Top 10 & CWE Vulnerabilities
Detects common security vulnerabilities and coding flaws
"""

import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.auditor_engine import Finding, Severity, Category


class SecurityAnalyzer:
    """
    Advanced security vulnerability analyzer
    Covers OWASP Top 10, CWE, and Windows-specific security issues
    """
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.file_cache = {}
        
    def _initialize_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize security vulnerability patterns"""
        return {
            # SQL Injection (OWASP A03:2021, CWE-89)
            'sql_injection': [
                {
                    'pattern': r'(?:Execute|ExecuteReader|ExecuteScalar|ExecuteNonQuery)\s*\(\s*["\'].*?\+.*?["\']',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'SQL Injection via string concatenation',
                    'recommendation': 'Use parameterized queries (SqlParameter) instead of string concatenation'
                },
                {
                    'pattern': r'SELECT\s+.*?\s+FROM\s+.*?\s+WHERE\s+.*?\+',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'Potential SQL Injection in query construction',
                    'recommendation': 'Use ORM (Entity Framework) or parameterized queries'
                },
                {
                    'pattern': r'String\.Format\(["\']SELECT|INSERT|UPDATE|DELETE.*?{0}',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-89',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'SQL query built with String.Format - potential injection',
                    'recommendation': 'Use parameterized queries with SqlCommand.Parameters'
                },
            ],
            
            # Command Injection (CWE-78)
            'command_injection': [
                {
                    'pattern': r'Process\.Start\s*\(\s*(?:["\']|@["\'])(?:cmd|powershell|bash).*?\+',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-78',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'Command Injection via Process.Start with concatenation',
                    'recommendation': 'Validate and sanitize all inputs, use ProcessStartInfo with Arguments'
                },
                {
                    'pattern': r'System\.Diagnostics\.Process\.Start\([^)]*\$\{.*?\}',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-78',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'Command execution with variable interpolation',
                    'recommendation': 'Use whitelist validation and escape special characters'
                },
                {
                    'pattern': r'exec\(|eval\(|system\(|shell_exec\(',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-78',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'Dangerous function allowing arbitrary code execution',
                    'recommendation': 'Avoid dynamic code execution, use safer alternatives'
                },
            ],
            
            # Path Traversal (CWE-22)
            'path_traversal': [
                {
                    'pattern': r'File\.(?:Open|ReadAllText|WriteAllText|Delete|Move|Copy)\s*\([^)]*\+',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'description': 'Path Traversal - file operations with user input',
                    'recommendation': 'Validate paths, use Path.GetFullPath() and check against allowed directory'
                },
                {
                    'pattern': r'\.\.[\\/]',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-22',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'description': 'Directory traversal sequence detected',
                    'recommendation': 'Sanitize file paths and reject ".." sequences'
                },
            ],
            
            # XSS (CWE-79)
            'xss': [
                {
                    'pattern': r'(?:Response\.Write|<%=|@Html\.Raw)\s*\([^)]*Request\[',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-79',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'Cross-Site Scripting (XSS) - unencoded user input in output',
                    'recommendation': 'Use @Html.Encode() or Html.DisplayFor() to encode output'
                },
                {
                    'pattern': r'innerHTML\s*=\s*.*?(?:Request|document\.location|location\.search)',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-79',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'DOM-based XSS vulnerability',
                    'recommendation': 'Use textContent instead of innerHTML, or sanitize input'
                },
            ],
            
            # Weak Cryptography (CWE-327)
            'weak_crypto': [
                {
                    'pattern': r'(?:MD5|SHA1)(?:CryptoServiceProvider|\.Create)',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-327',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'description': 'Weak cryptographic algorithm (MD5/SHA1)',
                    'recommendation': 'Use SHA256, SHA384, or SHA512 for hashing'
                },
                {
                    'pattern': r'DESCryptoServiceProvider|TripleDES',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-327',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'description': 'Weak encryption algorithm (DES/3DES)',
                    'recommendation': 'Use AES-256 with proper key management'
                },
                {
                    'pattern': r'new\s+RNGCryptoServiceProvider\(\).*?GetBytes\((?:[1-4]|new byte\[[1-4]\])',
                    'severity': Severity.MEDIUM,
                    'cwe': 'CWE-330',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'description': 'Insufficient randomness - too few random bytes',
                    'recommendation': 'Use at least 16 bytes (128 bits) for cryptographic randomness'
                },
            ],
            
            # Hardcoded Credentials (CWE-798)
            'hardcoded_secrets': [
                {
                    'pattern': r'(?:password|pwd|pass|secret|token|api[_-]?key)\s*=\s*["\'][^"\']{8,}["\']',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-798',
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'description': 'Hardcoded credentials in source code',
                    'recommendation': 'Use Azure Key Vault, environment variables, or secure configuration'
                },
                {
                    'pattern': r'connectionString\s*=\s*["\'].*?(?:password|pwd)=(?![\*\{])[^;"\'\s]{3,}',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-798',
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'description': 'Database password in connection string',
                    'recommendation': 'Use Windows Authentication or Azure Managed Identity'
                },
                {
                    'pattern': r'(?:private|secret|api)[_-]?key\s*[:=]\s*["\'][A-Za-z0-9+/]{20,}["\']',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-798',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'description': 'API key or secret key hardcoded',
                    'recommendation': 'Move secrets to secure configuration management'
                },
            ],
            
            # Insecure Deserialization (CWE-502)
            'deserialization': [
                {
                    'pattern': r'BinaryFormatter\.Deserialize|JavaScriptSerializer\.Deserialize',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-502',
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'description': 'Insecure deserialization - can lead to RCE',
                    'recommendation': 'Use JSON.NET with TypeNameHandling.None or DataContractSerializer'
                },
                {
                    'pattern': r'XmlSerializer\.Deserialize|SoapFormatter',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-502',
                    'owasp': 'A08:2021 - Software and Data Integrity Failures',
                    'description': 'Potentially unsafe deserialization',
                    'recommendation': 'Validate input and use safe serializers'
                },
            ],
            
            # Logging Sensitive Data (CWE-532)
            'sensitive_logging': [
                {
                    'pattern': r'(?:Log|logger|Console\.WriteLine).*?(?:password|credential|token|ssn|credit[_-]?card)',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-532',
                    'owasp': 'A09:2021 - Security Logging and Monitoring Failures',
                    'description': 'Logging sensitive information',
                    'recommendation': 'Remove sensitive data from logs or mask/redact it'
                },
            ],
            
            # Insufficient Authentication (CWE-306)
            'auth_issues': [
                {
                    'pattern': r'\[AllowAnonymous\](?:(?!Authorize).{0,200}public)',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-306',
                    'owasp': 'A07:2021 - Identification and Authentication Failures',
                    'description': 'Endpoint allows anonymous access without authorization',
                    'recommendation': 'Review if AllowAnonymous is necessary, add [Authorize] attribute'
                },
                {
                    'pattern': r'ValidateAntiForgeryToken.*?=\s*false',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-352',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'description': 'CSRF protection disabled',
                    'recommendation': 'Enable ValidateAntiForgeryToken for state-changing operations'
                },
            ],
            
            # Windows-Specific Security Issues
            'windows_security': [
                {
                    'pattern': r'Registry\.(?:SetValue|DeleteValue).*?HKEY_LOCAL_MACHINE',
                    'severity': Severity.MEDIUM,
                    'cwe': 'CWE-250',
                    'owasp': 'A04:2021 - Insecure Design',
                    'description': 'Registry modification requiring elevated privileges',
                    'recommendation': 'Verify least privilege principle and user permissions'
                },
                {
                    'pattern': r'new\s+DirectoryEntry\s*\(\s*["\']LDAP://[^)]+\)',
                    'severity': Severity.MEDIUM,
                    'cwe': 'CWE-90',
                    'owasp': 'A03:2021 - Injection',
                    'description': 'LDAP injection risk in Active Directory queries',
                    'recommendation': 'Sanitize user input before LDAP queries'
                },
                {
                    'pattern': r'impersonation.*?=.*?true|WindowsIdentity\.Impersonate',
                    'severity': Severity.MEDIUM,
                    'cwe': 'CWE-250',
                    'owasp': 'A04:2021 - Insecure Design',
                    'description': 'Windows identity impersonation detected',
                    'recommendation': 'Ensure proper security context and audit logging'
                },
            ],
            
            # Insecure Network Communication
            'network_security': [
                {
                    'pattern': r'ServicePointManager\.ServerCertificateValidationCallback\s*=.*?true',
                    'severity': Severity.CRITICAL,
                    'cwe': 'CWE-295',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'description': 'SSL/TLS certificate validation disabled',
                    'recommendation': 'Never disable certificate validation in production'
                },
                {
                    'pattern': r'SecurityProtocolType\.(?:Ssl3|Tls(?:11)?)\b',
                    'severity': Severity.HIGH,
                    'cwe': 'CWE-327',
                    'owasp': 'A02:2021 - Cryptographic Failures',
                    'description': 'Outdated TLS/SSL protocol version',
                    'recommendation': 'Use TLS 1.2 or TLS 1.3 minimum'
                },
            ],
        }
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze a file for security vulnerabilities"""
        findings = []
        
        # Skip non-code files
        code_extensions = {'.cs', '.cpp', '.c', '.h', '.py', '.js', '.ts', 
                          '.java', '.php', '.rb', '.go', '.rs', '.vb', 
                          '.config', '.xml', '.aspx', '.cshtml'}
        
        if file_path.suffix.lower() not in code_extensions:
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return findings
        
        # Run all pattern checks
        for vuln_type, patterns in self.patterns.items():
            for pattern_def in patterns:
                pattern = pattern_def['pattern']
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    # Find line number
                    line_num = content[:match.start()].count('\n') + 1
                    
                    # Extract code snippet
                    snippet_start = max(0, line_num - 2)
                    snippet_end = min(len(lines), line_num + 2)
                    snippet = '\n'.join(lines[snippet_start:snippet_end])
                    
                    # Create finding
                    finding_id = hashlib.md5(
                        f"{file_path}{line_num}{vuln_type}".encode()
                    ).hexdigest()[:12]
                    
                    finding = Finding(
                        id=f"SEC-{finding_id}",
                        title=f"{vuln_type.replace('_', ' ').title()} Vulnerability",
                        severity=pattern_def['severity'],
                        category=Category.SECURITY,
                        description=pattern_def['description'],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=snippet,
                        cwe_id=pattern_def['cwe'],
                        owasp_category=pattern_def['owasp'],
                        impact=self._get_impact(pattern_def['severity']),
                        recommendation=pattern_def['recommendation'],
                        references=[
                            f"https://cwe.mitre.org/data/definitions/{pattern_def['cwe'].split('-')[1]}.html",
                            "https://owasp.org/Top10/"
                        ],
                        confidence=0.85
                    )
                    
                    findings.append(finding)
        
        return findings
    
    def _get_impact(self, severity: Severity) -> str:
        """Get impact description based on severity"""
        impacts = {
            Severity.CRITICAL: "Exploitation could lead to complete system compromise, data breach, or remote code execution",
            Severity.HIGH: "Significant security risk that could lead to unauthorized access or data exposure",
            Severity.MEDIUM: "Moderate security risk that should be addressed to prevent potential vulnerabilities",
            Severity.LOW: "Minor security concern that represents a best practice violation",
            Severity.INFO: "Informational finding for awareness"
        }
        return impacts.get(severity, "Security risk identified")


if __name__ == "__main__":
    # Test
    analyzer = SecurityAnalyzer()
    print("✅ Security Analyzer initialized")
    print(f"📋 Loaded {sum(len(p) for p in analyzer.patterns.values())} security patterns")
