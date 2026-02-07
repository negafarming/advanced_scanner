#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Security Auditor - CLI Application
Command-line interface for security auditing
"""

import sys
import argparse
import json
from pathlib import Path
from datetime import datetime

# Add to path
sys.path.append(str(Path(__file__).parent))

from core.auditor_engine import AuditorEngine
from analyzers.security_analyzer import SecurityAnalyzer
from analyzers.quality_analyzer import CodeQualityAnalyzer
from analyzers.config_analyzer import ConfigAnalyzer
from reporters.report_generator import ReportGenerator


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def print_banner():
    """Print application banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        🛡️  WINDOWS SECURITY AUDITOR v1.0                        ║
║                                                                  ║
║        Advanced Security & Code Quality Analysis                ║
║        for Windows Projects                                     ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)


def progress_callback(message, percent):
    """Progress callback for scan updates"""
    bar_length = 50
    filled = int(bar_length * percent / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    
    print(f"\r{Colors.CYAN}[{bar}] {percent:.0f}% - {message}{Colors.END}", end='', flush=True)
    
    if percent >= 100:
        print()  # New line when complete


def run_scan(args):
    """Run security scan"""
    target_path = Path(args.target)
    
    if not target_path.exists():
        print(f"{Colors.RED}Error: Target path does not exist: {target_path}{Colors.END}")
        return 1
    
    print(f"{Colors.BOLD}Target:{Colors.END} {target_path}")
    print(f"{Colors.BOLD}Output:{Colors.END} {args.output}")
    print()
    
    # Initialize engine
    engine = AuditorEngine()
    engine.set_progress_callback(progress_callback)
    
    # Register analyzers
    if args.security or args.all:
        print(f"{Colors.GREEN}✓ Security Analyzer enabled{Colors.END}")
        engine.register_analyzer(SecurityAnalyzer())
    
    if args.quality or args.all:
        print(f"{Colors.GREEN}✓ Code Quality Analyzer enabled{Colors.END}")
        engine.register_analyzer(CodeQualityAnalyzer())
    
    if args.config or args.all:
        print(f"{Colors.GREEN}✓ Configuration Analyzer enabled{Colors.END}")
        engine.register_analyzer(ConfigAnalyzer())
    
    print()
    
    # Run scan
    print(f"{Colors.BOLD}Starting scan...{Colors.END}\n")
    
    try:
        result = engine.scan_directory(str(target_path))
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}✓ Scan completed successfully!{Colors.END}\n")
        
        # Print summary
        report_gen = ReportGenerator()
        summary = report_gen.generate_summary_text(result)
        print(summary)
        
        # Generate reports
        output_path = Path(args.output)
        output_path.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        print(f"\n{Colors.BOLD}Generating reports...{Colors.END}")
        
        # HTML Report
        if args.format in ['html', 'all']:
            html_path = output_path / f"security_report_{timestamp}.html"
            report_gen.generate_html_report(result, html_path)
            print(f"{Colors.GREEN}✓ HTML Report:{Colors.END} {html_path}")
        
        # JSON Report
        if args.format in ['json', 'all']:
            json_path = output_path / f"security_report_{timestamp}.json"
            report_gen.generate_json_report(result, json_path)
            print(f"{Colors.GREEN}✓ JSON Report:{Colors.END} {json_path}")
        
        # Print critical/high findings count
        summary_data = result.get_summary()
        critical_high = summary_data['CRITICAL'] + summary_data['HIGH']
        
        if critical_high > 0:
            print(f"\n{Colors.RED}{Colors.BOLD}⚠️  WARNING: {critical_high} CRITICAL/HIGH severity findings detected!{Colors.END}")
            if args.fail_on_high:
                return 1
        
        return 0
        
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}Scan interrupted by user{Colors.END}")
        return 130
    except Exception as e:
        print(f"\n{Colors.RED}{Colors.BOLD}Error during scan:{Colors.END} {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


def list_checks(args):
    """List all available security checks"""
    print(f"\n{Colors.BOLD}Available Security Checks:{Colors.END}\n")
    
    # Security Checks
    print(f"{Colors.CYAN}{Colors.BOLD}🔒 Security Analyzer:{Colors.END}")
    security_checks = [
        "SQL Injection (CWE-89, OWASP A03:2021)",
        "Command Injection (CWE-78)",
        "Path Traversal (CWE-22)",
        "Cross-Site Scripting - XSS (CWE-79)",
        "Weak Cryptography (CWE-327)",
        "Hardcoded Credentials (CWE-798)",
        "Insecure Deserialization (CWE-502)",
        "Sensitive Data Logging (CWE-532)",
        "Authentication Issues (CWE-306)",
        "Windows Security Issues",
        "Network Security (TLS/SSL)"
    ]
    for check in security_checks:
        print(f"  • {check}")
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}📊 Code Quality Analyzer:{Colors.END}")
    quality_checks = [
        "Memory Management Issues",
        "Exception Handling",
        "Threading & Concurrency",
        "Code Complexity",
        "SOLID Violations",
        "Null Reference Issues",
        "String Handling",
        "Resource Management",
        "Performance Issues",
        "Deprecated APIs"
    ]
    for check in quality_checks:
        print(f"  • {check}")
    
    print(f"\n{Colors.CYAN}{Colors.BOLD}⚙️ Configuration Analyzer:{Colors.END}")
    config_checks = [
        ".NET Configuration Issues",
        "Database Connection Strings",
        "Package/Dependency Issues",
        "Docker/Container Configuration",
        "PowerShell Security",
        "IIS Configuration",
        "Sensitive Data Exposure"
    ]
    for check in config_checks:
        print(f"  • {check}")
    
    print()


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description='Windows Security Auditor - Advanced Security Analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan with all analyzers
  %(prog)s scan /path/to/project --all
  
  # Scan with specific analyzers
  %(prog)s scan /path/to/project --security --quality
  
  # Generate HTML report only
  %(prog)s scan /path/to/project --all --format html
  
  # List available checks
  %(prog)s list-checks
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Run security scan')
    scan_parser.add_argument('target', help='Target directory to scan')
    scan_parser.add_argument('-o', '--output', default='./reports',
                           help='Output directory for reports (default: ./reports)')
    scan_parser.add_argument('--security', action='store_true',
                           help='Enable security analysis')
    scan_parser.add_argument('--quality', action='store_true',
                           help='Enable code quality analysis')
    scan_parser.add_argument('--config', action='store_true',
                           help='Enable configuration analysis')
    scan_parser.add_argument('--all', action='store_true',
                           help='Enable all analyzers (default)')
    scan_parser.add_argument('--format', choices=['html', 'json', 'all'],
                           default='all', help='Report format (default: all)')
    scan_parser.add_argument('--fail-on-high', action='store_true',
                           help='Exit with error code if high/critical findings detected')
    scan_parser.add_argument('-v', '--verbose', action='store_true',
                           help='Verbose output')
    
    # List checks command
    list_parser = subparsers.add_parser('list-checks', 
                                       help='List all available security checks')
    
    # Parse arguments
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # Execute command
    if args.command == 'scan':
        # Default to --all if no specific analyzer selected
        if not (args.security or args.quality or args.config):
            args.all = True
        
        exit_code = run_scan(args)
        sys.exit(exit_code)
        
    elif args.command == 'list-checks':
        list_checks(args)
        
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
