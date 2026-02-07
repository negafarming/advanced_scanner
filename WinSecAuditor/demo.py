#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Security Auditor - Demo Script
Demonstrates the capabilities of the security auditor
"""

import sys
from pathlib import Path

# Add to path
sys.path.append(str(Path(__file__).parent / 'src'))

from core.auditor_engine import AuditorEngine
from analyzers.security_analyzer import SecurityAnalyzer
from analyzers.quality_analyzer import CodeQualityAnalyzer
from analyzers.config_analyzer import ConfigAnalyzer
from reporters.report_generator import ReportGenerator


def print_banner():
    """Print demo banner"""
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║     🛡️  WINDOWS SECURITY AUDITOR - DEMONSTRATION                ║
║                                                                  ║
║     This demo scans the sample vulnerable code file             ║
║     to show you what the tool can detect                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


def progress_callback(message, percent):
    """Simple progress display"""
    bar_length = 40
    filled = int(bar_length * percent / 100)
    bar = '█' * filled + '░' * (bar_length - filled)
    print(f"\r[{bar}] {percent:3.0f}% - {message}", end='', flush=True)
    if percent >= 100:
        print()


def run_demo():
    """Run the demonstration"""
    print_banner()
    
    # Check if sample file exists
    sample_file = Path(__file__).parent / 'tests' / 'sample_vulnerable_code.cs'
    
    if not sample_file.exists():
        print("❌ Error: Sample file not found!")
        print(f"   Expected: {sample_file}")
        return 1
    
    print(f"📁 Scanning sample file: {sample_file.name}\n")
    
    # Initialize engine
    engine = AuditorEngine()
    engine.set_progress_callback(progress_callback)
    
    # Register all analyzers
    print("🔧 Initializing analyzers...")
    engine.register_analyzer(SecurityAnalyzer())
    engine.register_analyzer(CodeQualityAnalyzer())
    engine.register_analyzer(ConfigAnalyzer())
    print("✓ Analyzers ready\n")
    
    # Run scan
    print("🔍 Starting security scan...\n")
    
    try:
        result = engine.scan_directory(str(sample_file.parent))
        
        print("\n✅ Scan completed!\n")
        
        # Generate and display summary
        report_gen = ReportGenerator()
        summary = report_gen.generate_summary_text(result)
        print(summary)
        
        # Show some examples of findings
        print("\n" + "="*65)
        print("SAMPLE FINDINGS (First 5):")
        print("="*65 + "\n")
        
        for idx, finding in enumerate(result.findings[:5], 1):
            print(f"{idx}. [{finding.severity.value}] {finding.title}")
            print(f"   Category: {finding.category.value}")
            print(f"   Description: {finding.description}")
            print(f"   Recommendation: {finding.recommendation[:80]}...")
            print()
        
        # Generate reports
        output_dir = Path(__file__).parent / 'output'
        output_dir.mkdir(exist_ok=True)
        
        print("="*65)
        print("GENERATING REPORTS")
        print("="*65 + "\n")
        
        html_report = output_dir / 'demo_report.html'
        json_report = output_dir / 'demo_report.json'
        
        report_gen.generate_html_report(result, html_report)
        report_gen.generate_json_report(result, json_report)
        
        print(f"📄 HTML Report: {html_report}")
        print(f"📄 JSON Report: {json_report}")
        
        print("\n" + "="*65)
        print("DEMO COMPLETED SUCCESSFULLY!")
        print("="*65)
        print("\nNext steps:")
        print("  1. Open the HTML report in your browser")
        print("  2. Review the detected issues")
        print("  3. Try scanning your own projects!")
        print("\nUsage:")
        print("  GUI: python src/gui_app.py")
        print("  CLI: python src/cli_app.py scan <your-project-path>")
        print()
        
        return 0
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Demo interrupted by user")
        return 130
        
    except Exception as e:
        print(f"\n❌ Error during demo: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(run_demo())
