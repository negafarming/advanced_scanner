#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Configuration and System Analyzer
Analyzes Windows configurations, dependencies, and system settings
"""

import re
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Any
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.auditor_engine import Finding, Severity, Category


class ConfigAnalyzer:
    """Analyzes configuration files and system settings"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.dependencies = {}
        
    def _initialize_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize configuration check patterns"""
        return {
            # .NET Configuration Issues
            'dotnet_config': [
                {
                    'pattern': r'<authentication\s+mode\s*=\s*["\']None["\']',
                    'severity': Severity.CRITICAL,
                    'description': 'Authentication disabled in ASP.NET',
                    'recommendation': 'Enable Windows, Forms, or Federation authentication'
                },
                {
                    'pattern': r'<httpCookies\s+(?!.*?requireSSL\s*=\s*["\']true["\'])',
                    'severity': Severity.HIGH,
                    'description': 'Cookies not restricted to SSL/TLS',
                    'recommendation': 'Set requireSSL="true" and httpOnlyCookies="true"'
                },
                {
                    'pattern': r'<sessionState\s+(?!.*?cookieless\s*=\s*["\']UseCookies["\'])',
                    'severity': Severity.MEDIUM,
                    'description': 'Session state not properly secured',
                    'recommendation': 'Use cookieless="UseCookies" and enable SSL'
                },
                {
                    'pattern': r'<trace\s+enabled\s*=\s*["\']true["\']',
                    'severity': Severity.HIGH,
                    'description': 'ASP.NET tracing enabled (information disclosure)',
                    'recommendation': 'Disable tracing in production'
                },
                {
                    'pattern': r'<compilation\s+debug\s*=\s*["\']true["\']',
                    'severity': Severity.MEDIUM,
                    'description': 'Debug compilation enabled',
                    'recommendation': 'Set debug="false" for production'
                },
                {
                    'pattern': r'<httpRuntime\s+(?!.*?enableVersionHeader\s*=\s*["\']false["\'])',
                    'severity': Severity.LOW,
                    'description': 'Version header disclosure enabled',
                    'recommendation': 'Set enableVersionHeader="false"'
                },
            ],
            
            # Database Connection Strings
            'connection_strings': [
                {
                    'pattern': r'(?:User\s+ID|uid)\s*=\s*sa\b',
                    'severity': Severity.CRITICAL,
                    'description': 'Using SQL Server "sa" account',
                    'recommendation': 'Use least privilege accounts, never use "sa" account'
                },
                {
                    'pattern': r'Integrated\s+Security\s*=\s*false',
                    'severity': Severity.MEDIUM,
                    'description': 'Windows Integrated Security not used',
                    'recommendation': 'Use Integrated Security or Azure Managed Identity'
                },
                {
                    'pattern': r'Encrypt\s*=\s*(?:false|no)',
                    'severity': Severity.HIGH,
                    'description': 'Database connection encryption disabled',
                    'recommendation': 'Enable encryption with Encrypt=true'
                },
                {
                    'pattern': r'TrustServerCertificate\s*=\s*true',
                    'severity': Severity.MEDIUM,
                    'description': 'Server certificate validation disabled',
                    'recommendation': 'Set TrustServerCertificate=false and use valid certificates'
                },
            ],
            
            # Package/Dependency Issues
            'dependencies': [
                {
                    'pattern': r'<PackageReference.*?Version\s*=\s*["\'][\d]+\.[\d]+\.[\*x]',
                    'severity': Severity.MEDIUM,
                    'description': 'Wildcard version in package reference',
                    'recommendation': 'Pin to specific stable versions for reproducible builds'
                },
                {
                    'pattern': r'<PackageReference.*?PrivateAssets\s*=\s*["\']None["\']',
                    'severity': Severity.LOW,
                    'description': 'Package assets not properly scoped',
                    'recommendation': 'Use appropriate PrivateAssets settings'
                },
            ],
            
            # Docker/Container Configuration
            'docker_config': [
                {
                    'pattern': r'FROM\s+.*?:latest',
                    'severity': Severity.MEDIUM,
                    'description': 'Using "latest" tag in Docker base image',
                    'recommendation': 'Pin to specific version tags for reproducibility'
                },
                {
                    'pattern': r'USER\s+root',
                    'severity': Severity.HIGH,
                    'description': 'Container running as root user',
                    'recommendation': 'Create and use non-root user for container execution'
                },
                {
                    'pattern': r'ADD\s+http',
                    'severity': Severity.MEDIUM,
                    'description': 'Using ADD with URL (security risk)',
                    'recommendation': 'Use curl/wget with explicit verification or COPY'
                },
            ],
            
            # PowerShell Security
            'powershell_security': [
                {
                    'pattern': r'-ExecutionPolicy\s+Bypass',
                    'severity': Severity.HIGH,
                    'description': 'PowerShell execution policy bypass',
                    'recommendation': 'Sign scripts and use appropriate execution policy'
                },
                {
                    'pattern': r'Invoke-Expression\s*\$',
                    'severity': Severity.CRITICAL,
                    'description': 'Dangerous use of Invoke-Expression with variables',
                    'recommendation': 'Avoid Invoke-Expression, use safer alternatives'
                },
                {
                    'pattern': r'System\.Net\.WebClient.*?DownloadString',
                    'severity': Severity.HIGH,
                    'description': 'Downloading and potentially executing remote code',
                    'recommendation': 'Validate sources, use HTTPS, verify content'
                },
            ],
            
            # IIS Configuration
            'iis_config': [
                {
                    'pattern': r'<directoryBrowse\s+enabled\s*=\s*["\']true["\']',
                    'severity': Severity.HIGH,
                    'description': 'Directory browsing enabled',
                    'recommendation': 'Disable directory browsing in production'
                },
                {
                    'pattern': r'<httpErrors\s+errorMode\s*=\s*["\']Detailed["\']',
                    'severity': Severity.HIGH,
                    'description': 'Detailed error messages enabled',
                    'recommendation': 'Use "DetailedLocalOnly" or "Custom" error mode'
                },
            ],
            
            # JSON Configuration
            'json_config': [
                {
                    'pattern': r'"Logging":\s*\{[^}]*"LogLevel":\s*\{[^}]*"Default":\s*"Debug"',
                    'severity': Severity.LOW,
                    'description': 'Debug logging level in configuration',
                    'recommendation': 'Use Information or Warning level in production'
                },
                {
                    'pattern': r'"AllowedHosts":\s*"\*"',
                    'severity': Severity.MEDIUM,
                    'description': 'All hosts allowed (potential host header injection)',
                    'recommendation': 'Specify explicit allowed hosts'
                },
            ],
        }
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze configuration file"""
        findings = []
        
        config_extensions = {'.config', '.xml', '.json', '.ps1', '.bat', 
                            '.cmd', '.yml', '.yaml', 'Dockerfile'}
        config_names = {'web.config', 'app.config', 'appsettings.json', 
                       'packages.config', 'docker-compose.yml'}
        
        if (file_path.suffix.lower() not in config_extensions and 
            file_path.name.lower() not in config_names):
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return findings
        
        # Check for sensitive data exposure
        findings.extend(self._check_sensitive_data(file_path, content, lines))
        
        # Run pattern checks
        for issue_type, patterns in self.patterns.items():
            for pattern_def in patterns:
                pattern = pattern_def['pattern']
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    snippet_start = max(0, line_num - 2)
                    snippet_end = min(len(lines), line_num + 2)
                    snippet = '\n'.join(lines[snippet_start:snippet_end])
                    
                    finding_id = hashlib.md5(
                        f"{file_path}{line_num}{issue_type}".encode()
                    ).hexdigest()[:12]
                    
                    finding = Finding(
                        id=f"CFG-{finding_id}",
                        title=f"Configuration Issue: {issue_type.replace('_', ' ').title()}",
                        severity=pattern_def['severity'],
                        category=Category.CONFIGURATION,
                        description=pattern_def['description'],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=snippet,
                        recommendation=pattern_def['recommendation'],
                        confidence=0.85
                    )
                    
                    findings.append(finding)
        
        # Analyze dependencies if it's a package file
        if file_path.name.lower() in ['packages.config', 'package.json', 
                                      'requirements.txt', 'cargo.toml']:
            findings.extend(self._analyze_dependencies(file_path, content))
        
        return findings
    
    def _check_sensitive_data(self, file_path: Path, content: str, 
                             lines: List[str]) -> List[Finding]:
        """Check for sensitive data in configuration files"""
        findings = []
        
        sensitive_patterns = [
            (r'(?:api[_-]?key|apikey|api-key)\s*[:=]\s*["\']?([A-Za-z0-9+/]{20,})["\']?', 
             'API Key'),
            (r'(?:secret[_-]?key|secretkey|secret-key)\s*[:=]\s*["\']?([A-Za-z0-9+/]{20,})["\']?',
             'Secret Key'),
            (r'(?:password|pwd|pass)\s*[:=]\s*["\']?([^"\'\s]{3,})["\']?',
             'Password'),
            (r'(?:private[_-]?key|privatekey)\s*[:=]',
             'Private Key'),
            (r'aws_access_key_id|aws_secret_access_key',
             'AWS Credentials'),
        ]
        
        for pattern, data_type in sensitive_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                
                finding_id = hashlib.md5(
                    f"{file_path}{line_num}{data_type}".encode()
                ).hexdigest()[:12]
                
                finding = Finding(
                    id=f"SENS-{finding_id}",
                    title=f"Sensitive Data Exposure: {data_type}",
                    severity=Severity.CRITICAL,
                    category=Category.SECURITY,
                    description=f"{data_type} found in configuration file",
                    file_path=str(file_path),
                    line_number=line_num,
                    code_snippet="[REDACTED FOR SECURITY]",
                    recommendation='Move sensitive data to secure storage (Azure Key Vault, environment variables, secrets manager)',
                    confidence=0.9
                )
                
                findings.append(finding)
        
        return findings
    
    def _analyze_dependencies(self, file_path: Path, content: str) -> List[Finding]:
        """Analyze package dependencies for known vulnerabilities"""
        findings = []
        
        # This is a simplified check - in production, integrate with vulnerability databases
        outdated_packages = {
            'Newtonsoft.Json': ('12.0.0', 'MEDIUM', 'Known security issues in older versions'),
            'System.Net.Http': ('4.3.0', 'HIGH', 'TLS/SSL vulnerabilities'),
            'Microsoft.AspNetCore.All': ('2.0.0', 'HIGH', 'End of support'),
        }
        
        for package, (max_version, severity, description) in outdated_packages.items():
            pattern = rf'{package}.*?Version\s*=\s*["\']([^"\']+)["\']'
            matches = re.finditer(pattern, content, re.IGNORECASE)
            
            for match in matches:
                version = match.group(1)
                if version < max_version:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    finding = Finding(
                        id=f"DEP-{hashlib.md5(f'{file_path}{package}'.encode()).hexdigest()[:12]}",
                        title=f"Outdated Dependency: {package}",
                        severity=Severity[severity],
                        category=Category.DEPENDENCIES,
                        description=f"Using outdated version {version} of {package}. {description}",
                        file_path=str(file_path),
                        line_number=line_num,
                        recommendation=f'Update to version {max_version} or later',
                        references=['https://nvd.nist.gov/', 'https://github.com/advisories'],
                        confidence=0.8
                    )
                    
                    findings.append(finding)
        
        return findings


if __name__ == "__main__":
    analyzer = ConfigAnalyzer()
    print("✅ Configuration Analyzer initialized")
    print(f"📋 Loaded {sum(len(p) for p in analyzer.patterns.values())} configuration patterns")
