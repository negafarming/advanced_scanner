#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Security Auditor - Core Engine
Advanced diagnostic and security analysis system for Windows environments
"""

import os
import sys
import json
import hashlib
import datetime
import threading
import queue
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    """Security and issue severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Category(Enum):
    """Vulnerability and issue categories"""
    SECURITY = "Security"
    PERFORMANCE = "Performance"
    ARCHITECTURE = "Architecture"
    CODE_QUALITY = "Code Quality"
    CONFIGURATION = "Configuration"
    COMPATIBILITY = "Compatibility"
    DEPENDENCIES = "Dependencies"
    BEST_PRACTICES = "Best Practices"


@dataclass
class Finding:
    """Represents a single audit finding"""
    id: str
    title: str
    severity: Severity
    category: Category
    description: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    impact: str = ""
    recommendation: str = ""
    references: List[str] = field(default_factory=list)
    confidence: float = 1.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary"""
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity.value,
            'category': self.category.value,
            'description': self.description,
            'file_path': self.file_path,
            'line_number': self.line_number,
            'code_snippet': self.code_snippet,
            'cwe_id': self.cwe_id,
            'owasp_category': self.owasp_category,
            'impact': self.impact,
            'recommendation': self.recommendation,
            'references': self.references,
            'confidence': self.confidence
        }


@dataclass
class AuditResult:
    """Complete audit results container"""
    project_name: str
    scan_date: datetime.datetime
    scan_duration: float
    findings: List[Finding] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    scanned_files: int = 0
    total_lines: int = 0
    technologies: List[str] = field(default_factory=list)
    
    def get_summary(self) -> Dict[str, int]:
        """Get findings summary by severity"""
        summary = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0
        }
        for finding in self.findings:
            summary[finding.severity.value] += 1
        return summary
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert audit result to dictionary"""
        return {
            'project_name': self.project_name,
            'scan_date': self.scan_date.isoformat(),
            'scan_duration': self.scan_duration,
            'findings': [f.to_dict() for f in self.findings],
            'statistics': self.statistics,
            'scanned_files': self.scanned_files,
            'total_lines': self.total_lines,
            'technologies': self.technologies,
            'summary': self.get_summary()
        }


class AuditorEngine:
    """Main auditing engine orchestrator"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.findings: List[Finding] = []
        self.analyzers: List[Any] = []
        self.progress_callback = None
        self.stop_flag = threading.Event()
        
    def _default_config(self) -> Dict[str, Any]:
        """Default configuration"""
        return {
            'max_file_size': 10 * 1024 * 1024,  # 10MB
            'excluded_dirs': ['.git', 'node_modules', 'bin', 'obj', '__pycache__', 
                             'venv', '.vs', 'packages', 'Debug', 'Release'],
            'excluded_extensions': ['.exe', '.dll', '.so', '.dylib', '.bin', 
                                   '.obj', '.o', '.pdb', '.suo', '.user'],
            'parallel_scans': 4,
            'timeout_per_file': 30,
            'enable_deep_scan': True,
            'min_confidence': 0.6
        }
    
    def register_analyzer(self, analyzer):
        """Register an analyzer module"""
        self.analyzers.append(analyzer)
    
    def set_progress_callback(self, callback):
        """Set progress reporting callback"""
        self.progress_callback = callback
    
    def _report_progress(self, message: str, percent: float = 0):
        """Report progress if callback is set"""
        if self.progress_callback:
            self.progress_callback(message, percent)
    
    def scan_directory(self, target_path: str) -> AuditResult:
        """
        Scan entire directory structure
        
        Args:
            target_path: Path to the directory to scan
            
        Returns:
            AuditResult object with all findings
        """
        start_time = datetime.datetime.now()
        target_path = Path(target_path).resolve()
        
        if not target_path.exists():
            raise FileNotFoundError(f"Target path does not exist: {target_path}")
        
        self._report_progress(f"🔍 Scanning directory: {target_path}", 0)
        
        # Collect all files to scan
        files_to_scan = self._collect_files(target_path)
        total_files = len(files_to_scan)
        
        self._report_progress(f"📁 Found {total_files} files to analyze", 5)
        
        # Initialize result
        result = AuditResult(
            project_name=target_path.name,
            scan_date=start_time,
            scan_duration=0,
            scanned_files=total_files
        )
        
        # Detect technologies
        result.technologies = self._detect_technologies(files_to_scan)
        self._report_progress(f"🔧 Detected technologies: {', '.join(result.technologies)}", 10)
        
        # Run all analyzers
        total_lines = 0
        for idx, file_path in enumerate(files_to_scan):
            if self.stop_flag.is_set():
                break
                
            progress = 10 + (idx / total_files) * 80
            self._report_progress(f"📄 Analyzing: {file_path.name}", progress)
            
            try:
                # Count lines
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    lines = len(f.readlines())
                    total_lines += lines
                
                # Run analyzers
                for analyzer in self.analyzers:
                    findings = analyzer.analyze_file(file_path)
                    self.findings.extend(findings)
                    
            except Exception as e:
                # Log error but continue
                self.findings.append(Finding(
                    id=f"ERR-{hashlib.md5(str(file_path).encode()).hexdigest()[:8]}",
                    title="File Analysis Error",
                    severity=Severity.LOW,
                    category=Category.CODE_QUALITY,
                    description=f"Error analyzing file: {str(e)}",
                    file_path=str(file_path),
                    recommendation="Review file manually for issues"
                ))
        
        result.total_lines = total_lines
        result.findings = self.findings
        
        # Generate statistics
        result.statistics = self._generate_statistics(result)
        
        # Calculate duration
        end_time = datetime.datetime.now()
        result.scan_duration = (end_time - start_time).total_seconds()
        
        self._report_progress("✅ Scan completed!", 100)
        
        return result
    
    def _collect_files(self, target_path: Path) -> List[Path]:
        """Collect all files to be scanned"""
        files = []
        excluded_dirs = set(self.config['excluded_dirs'])
        excluded_exts = set(self.config['excluded_extensions'])
        max_size = self.config['max_file_size']
        
        for item in target_path.rglob('*'):
            if self.stop_flag.is_set():
                break
                
            # Skip excluded directories
            if any(excluded in item.parts for excluded in excluded_dirs):
                continue
            
            # Skip if not a file
            if not item.is_file():
                continue
            
            # Skip excluded extensions
            if item.suffix.lower() in excluded_exts:
                continue
            
            # Skip oversized files
            try:
                if item.stat().st_size > max_size:
                    continue
            except:
                continue
            
            files.append(item)
        
        return files
    
    def _detect_technologies(self, files: List[Path]) -> List[str]:
        """Detect technologies used in the project"""
        technologies = set()
        
        tech_indicators = {
            '.cs': ['.NET/C#'],
            '.csproj': ['.NET'],
            '.sln': ['Visual Studio'],
            '.cpp': ['C++'],
            '.c': ['C'],
            '.h': ['C/C++'],
            '.py': ['Python'],
            '.js': ['JavaScript'],
            '.ts': ['TypeScript'],
            '.java': ['Java'],
            '.go': ['Go'],
            '.rs': ['Rust'],
            '.php': ['PHP'],
            '.rb': ['Ruby'],
            '.ps1': ['PowerShell'],
            '.bat': ['Batch'],
            '.cmd': ['Windows CMD'],
            '.vbs': ['VBScript'],
            '.xaml': ['WPF/XAML'],
            '.json': ['JSON Config'],
            '.xml': ['XML Config'],
            '.config': ['.NET Config'],
            'Dockerfile': ['Docker'],
            'docker-compose.yml': ['Docker Compose'],
            'package.json': ['Node.js/npm'],
            'requirements.txt': ['Python/pip'],
            'Cargo.toml': ['Rust/Cargo'],
            'pom.xml': ['Java/Maven'],
            'build.gradle': ['Java/Gradle'],
        }
        
        for file_path in files:
            for indicator, techs in tech_indicators.items():
                if indicator.startswith('.') and file_path.suffix == indicator:
                    technologies.update(techs)
                elif file_path.name == indicator:
                    technologies.update(techs)
        
        return sorted(list(technologies))
    
    def _generate_statistics(self, result: AuditResult) -> Dict[str, Any]:
        """Generate detailed statistics"""
        stats = {
            'total_findings': len(result.findings),
            'by_severity': result.get_summary(),
            'by_category': {},
            'files_with_issues': len(set(f.file_path for f in result.findings if f.file_path)),
            'avg_confidence': sum(f.confidence for f in result.findings) / len(result.findings) if result.findings else 0,
            'high_confidence_findings': len([f for f in result.findings if f.confidence >= 0.8]),
        }
        
        # Count by category
        for finding in result.findings:
            cat = finding.category.value
            stats['by_category'][cat] = stats['by_category'].get(cat, 0) + 1
        
        return stats
    
    def stop(self):
        """Stop the scanning process"""
        self.stop_flag.set()
    
    def clear_findings(self):
        """Clear all findings"""
        self.findings.clear()


if __name__ == "__main__":
    # Simple test
    engine = AuditorEngine()
    print("✅ Auditor Engine initialized successfully")
    print(f"📋 Configuration: {json.dumps(engine.config, indent=2)}")
