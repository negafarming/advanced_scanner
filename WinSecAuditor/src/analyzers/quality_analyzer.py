#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Code Quality and Architecture Analyzer
Detects code smells, anti-patterns, and architectural issues
"""

import re
import hashlib
from pathlib import Path
from typing import List, Dict, Any
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.auditor_engine import Finding, Severity, Category


class CodeQualityAnalyzer:
    """Analyzes code quality, architecture, and best practices"""
    
    def __init__(self):
        self.patterns = self._initialize_patterns()
        self.metrics = {}
        
    def _initialize_patterns(self) -> Dict[str, List[Dict]]:
        """Initialize code quality patterns"""
        return {
            # Memory Management Issues
            'memory_issues': [
                {
                    'pattern': r'new\s+\w+\s*\[.*?\](?!.*?(?:delete|Dispose|using))',
                    'severity': Severity.HIGH,
                    'description': 'Potential memory leak - array allocation without deallocation',
                    'recommendation': 'Use RAII pattern (C++) or IDisposable pattern (C#), wrap in using statement'
                },
                {
                    'pattern': r'(?<!using\s*\()[A-Z]\w+\s+\w+\s*=\s*new\s+[A-Z]\w+.*?(?:Stream|Connection|SqlCommand|FileStream)',
                    'severity': Severity.HIGH,
                    'description': 'IDisposable object not wrapped in using statement',
                    'recommendation': 'Use using statement or try-finally with Dispose() call'
                },
                {
                    'pattern': r'GC\.Collect\(\)',
                    'severity': Severity.MEDIUM,
                    'description': 'Manual garbage collection invocation',
                    'recommendation': 'Avoid forcing GC, let .NET manage memory automatically'
                },
            ],
            
            # Exception Handling
            'exception_handling': [
                {
                    'pattern': r'catch\s*\(\s*Exception\s+\w+\s*\)\s*\{\s*\}',
                    'severity': Severity.HIGH,
                    'description': 'Empty catch block - swallowing exceptions',
                    'recommendation': 'Log exceptions, handle appropriately, or let them propagate'
                },
                {
                    'pattern': r'catch\s*\([^\)]*\)\s*\{[^}]*throw\s+new\s+Exception',
                    'severity': Severity.MEDIUM,
                    'description': 'Throwing new exception instead of rethrowing original',
                    'recommendation': 'Use "throw;" to preserve stack trace or wrap with "throw new Exception(msg, ex);"'
                },
                {
                    'pattern': r'try\s*\{[^}]*\}\s*catch\s*\(\s*\)\s*\{',
                    'severity': Severity.HIGH,
                    'description': 'Catching all exceptions without type specification',
                    'recommendation': 'Catch specific exception types and handle them appropriately'
                },
                {
                    'pattern': r'throw\s+ex\s*;',
                    'severity': Severity.MEDIUM,
                    'description': 'Rethrowing exception incorrectly (loses stack trace)',
                    'recommendation': 'Use "throw;" instead of "throw ex;"'
                },
            ],
            
            # Threading and Concurrency
            'threading_issues': [
                {
                    'pattern': r'Thread\.Sleep\s*\(\s*\d+\s*\)',
                    'severity': Severity.LOW,
                    'description': 'Thread.Sleep() used - potential for race conditions',
                    'recommendation': 'Use proper synchronization primitives (ManualResetEvent, SemaphoreSlim, Task.Delay)'
                },
                {
                    'pattern': r'(?<!private\s)(?<!static\s)(?:public|internal|protected)\s+(?!readonly)\w+\s+\w+\s*;',
                    'severity': Severity.MEDIUM,
                    'description': 'Public mutable field - thread safety concern',
                    'recommendation': 'Use properties with backing fields, consider thread-safe collections'
                },
                {
                    'pattern': r'lock\s*\(\s*this\s*\)',
                    'severity': Severity.HIGH,
                    'description': 'Locking on "this" - can cause deadlocks',
                    'recommendation': 'Lock on a private readonly object instead'
                },
                {
                    'pattern': r'lock\s*\(\s*typeof\s*\(',
                    'severity': Severity.HIGH,
                    'description': 'Locking on a Type object - dangerous practice',
                    'recommendation': 'Use a private static readonly object for locking'
                },
            ],
            
            # Code Complexity
            'complexity': [
                {
                    'pattern': r'(?:if|else if|while|for|foreach|case)(?:[^{]*(?:if|else if|while|for|foreach|case)){5,}',
                    'severity': Severity.MEDIUM,
                    'description': 'Deeply nested code structure (cyclomatic complexity)',
                    'recommendation': 'Refactor into smaller methods, use early returns, extract logic'
                },
                {
                    'pattern': r'(?:public|private|protected|internal)\s+\w+\s+\w+\s*\([^)]*\)[^{]*\{(?:[^}]|{[^}]*}){500,}\}',
                    'severity': Severity.MEDIUM,
                    'description': 'Very long method (> 500 characters)',
                    'recommendation': 'Break down into smaller, focused methods following SRP'
                },
            ],
            
            # SOLID Violations
            'solid_violations': [
                {
                    'pattern': r'class\s+\w+\s*:.*?(?:,.*?){4,}',
                    'severity': Severity.MEDIUM,
                    'description': 'Class implements too many interfaces (ISP violation)',
                    'recommendation': 'Split into smaller, focused interfaces (Interface Segregation Principle)'
                },
                {
                    'pattern': r'(?:public|internal)\s+class\s+\w+.*?\{(?:[^}]|{[^}]*}){2000,}\}',
                    'severity': Severity.HIGH,
                    'description': 'God class - too many responsibilities (SRP violation)',
                    'recommendation': 'Decompose into multiple classes with single responsibilities'
                },
            ],
            
            # Null Reference Issues
            'null_handling': [
                {
                    'pattern': r'(?<!if\s*\()[A-Za-z_]\w*\.\w+(?!\s*(?:!=|==)\s*null)',
                    'severity': Severity.LOW,
                    'description': 'Potential null reference without null check',
                    'recommendation': 'Use null-conditional operator (?.) or null-coalescing (??), enable nullable reference types'
                },
                {
                    'pattern': r'(?:==|!=)\s*null(?!\s*\?)',
                    'severity': Severity.LOW,
                    'description': 'Explicit null comparison',
                    'recommendation': 'Consider using "is null" or "is not null" pattern matching (C# 7+)'
                },
            ],
            
            # String Handling
            'string_issues': [
                {
                    'pattern': r'(?:\w+\s*\+\s*){3,}["\']',
                    'severity': Severity.MEDIUM,
                    'description': 'Multiple string concatenations in loop or expression',
                    'recommendation': 'Use StringBuilder for multiple concatenations'
                },
                {
                    'pattern': r'String\.Format\s*\(\s*["\'][^"\']*\{0\}[^"\']*\{1\}[^"\']*\{2\}',
                    'severity': Severity.LOW,
                    'description': 'String.Format with multiple parameters',
                    'recommendation': 'Consider using string interpolation ($"...{var}...") for readability'
                },
                {
                    'pattern': r'\.ToLower\(\)\s*==|==\s*\.ToLower\(\)',
                    'severity': Severity.LOW,
                    'description': 'Case-insensitive comparison using ToLower()',
                    'recommendation': 'Use StringComparison.OrdinalIgnoreCase for better performance'
                },
            ],
            
            # Resource Management
            'resource_management': [
                {
                    'pattern': r'(?:File|Stream)\.\w+\s*\([^)]*\)(?!.*?\.(?:Close|Dispose)\s*\(\))',
                    'severity': Severity.HIGH,
                    'description': 'File/Stream operation without explicit close or disposal',
                    'recommendation': 'Wrap in using statement to ensure proper disposal'
                },
                {
                    'pattern': r'new\s+(?:StreamReader|StreamWriter|FileStream)(?!.*?using)',
                    'severity': Severity.HIGH,
                    'description': 'Stream object created outside using statement',
                    'recommendation': 'Use using statement to ensure proper disposal'
                },
            ],
            
            # Performance Issues
            'performance': [
                {
                    'pattern': r'foreach\s*\([^)]*\)\s*\{[^}]*\.Add\s*\(',
                    'severity': Severity.LOW,
                    'description': 'Adding to collection inside foreach loop',
                    'recommendation': 'Pre-allocate collection size if known, or use LINQ Select()'
                },
                {
                    'pattern': r'\.ToList\(\)\.Count\(\)',
                    'severity': Severity.LOW,
                    'description': 'Calling ToList() before Count()',
                    'recommendation': 'Use Count() directly on IEnumerable, or Any() if checking > 0'
                },
                {
                    'pattern': r'\.Where\([^)]*\)\.FirstOrDefault\(\)',
                    'severity': Severity.LOW,
                    'description': 'Inefficient LINQ chain',
                    'recommendation': 'Use FirstOrDefault(predicate) instead of Where().FirstOrDefault()'
                },
            ],
            
            # Configuration Issues
            'configuration': [
                {
                    'pattern': r'ConfigurationManager\.AppSettings\[',
                    'severity': Severity.LOW,
                    'description': 'Using legacy ConfigurationManager.AppSettings',
                    'recommendation': 'Use IConfiguration with options pattern for better testability'
                },
                {
                    'pattern': r'<compilation\s+debug\s*=\s*["\']true["\']',
                    'severity': Severity.MEDIUM,
                    'description': 'Debug mode enabled in compilation configuration',
                    'recommendation': 'Set debug="false" for production deployments'
                },
                {
                    'pattern': r'<customErrors\s+mode\s*=\s*["\']Off["\']',
                    'severity': Severity.HIGH,
                    'description': 'Custom errors disabled - exposes stack traces',
                    'recommendation': 'Set customErrors mode to "RemoteOnly" or "On" in production'
                },
            ],
            
            # Windows-Specific Issues
            'windows_specific': [
                {
                    'pattern': r'System\.IO\.Path\.Combine\([^)]*["\'][/\\]',
                    'severity': Severity.LOW,
                    'description': 'Hard-coded path separator in Path.Combine',
                    'recommendation': 'Let Path.Combine handle separators automatically'
                },
                {
                    'pattern': r'["\'][A-Z]:[/\\]',
                    'severity': Severity.MEDIUM,
                    'description': 'Hard-coded absolute Windows path',
                    'recommendation': 'Use relative paths or configuration-based paths'
                },
                {
                    'pattern': r'Environment\.OSVersion\.Version\.Major\s*(?:==|>=|<=)',
                    'severity': Severity.LOW,
                    'description': 'Version checking using OSVersion (unreliable)',
                    'recommendation': 'Use RuntimeInformation.IsOSPlatform() or feature detection'
                },
            ],
            
            # Deprecated APIs
            'deprecated_apis': [
                {
                    'pattern': r'\.Substring\(0,\s*1\)',
                    'severity': Severity.LOW,
                    'description': 'Inefficient substring operation',
                    'recommendation': 'Use indexer [0] for single character access'
                },
                {
                    'pattern': r'BinaryFormatter',
                    'severity': Severity.HIGH,
                    'description': 'BinaryFormatter is deprecated and insecure',
                    'recommendation': 'Use JSON serialization or System.Text.Json'
                },
            ],
        }
    
    def analyze_file(self, file_path: Path) -> List[Finding]:
        """Analyze file for code quality issues"""
        findings = []
        
        code_extensions = {'.cs', '.cpp', '.c', '.h', '.py', '.js', 
                          '.java', '.config', '.xml', '.vb'}
        
        if file_path.suffix.lower() not in code_extensions:
            return findings
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception:
            return findings
        
        # Calculate basic metrics
        self._calculate_metrics(content, file_path)
        
        # Run pattern checks
        for issue_type, patterns in self.patterns.items():
            for pattern_def in patterns:
                pattern = pattern_def['pattern']
                matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE | re.DOTALL)
                
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    snippet_start = max(0, line_num - 2)
                    snippet_end = min(len(lines), line_num + 2)
                    snippet = '\n'.join(lines[snippet_start:snippet_end])
                    
                    finding_id = hashlib.md5(
                        f"{file_path}{line_num}{issue_type}".encode()
                    ).hexdigest()[:12]
                    
                    finding = Finding(
                        id=f"CQ-{finding_id}",
                        title=f"{issue_type.replace('_', ' ').title()} Issue",
                        severity=pattern_def['severity'],
                        category=Category.CODE_QUALITY,
                        description=pattern_def['description'],
                        file_path=str(file_path),
                        line_number=line_num,
                        code_snippet=snippet,
                        recommendation=pattern_def['recommendation'],
                        confidence=0.75
                    )
                    
                    findings.append(finding)
        
        return findings
    
    def _calculate_metrics(self, content: str, file_path: Path):
        """Calculate code metrics"""
        lines = content.split('\n')
        
        # Count lines of code (excluding empty and comments)
        loc = 0
        for line in lines:
            stripped = line.strip()
            if stripped and not stripped.startswith('//') and not stripped.startswith('#'):
                loc += 1
        
        # Count functions/methods
        methods = len(re.findall(r'(?:public|private|protected|internal)\s+\w+\s+\w+\s*\(', content))
        
        # Count classes
        classes = len(re.findall(r'(?:public|internal|private)\s+class\s+\w+', content))
        
        self.metrics[str(file_path)] = {
            'lines_of_code': loc,
            'total_lines': len(lines),
            'methods': methods,
            'classes': classes,
            'avg_method_length': loc / methods if methods > 0 else 0
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get collected metrics"""
        return self.metrics


if __name__ == "__main__":
    analyzer = CodeQualityAnalyzer()
    print("✅ Code Quality Analyzer initialized")
    print(f"📋 Loaded {sum(len(p) for p in analyzer.patterns.values())} quality patterns")
