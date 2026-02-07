#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Report Generator
Generates comprehensive HTML and JSON reports from audit results
"""

import json
import datetime
from pathlib import Path
from typing import Dict, Any
import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.auditor_engine import AuditResult, Severity


class ReportGenerator:
    """Generates comprehensive audit reports"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent.parent.parent / 'templates'
        
    def generate_html_report(self, result: AuditResult, output_path: Path) -> str:
        """Generate HTML report"""
        
        html_template = self._get_html_template()
        
        # Prepare data
        summary = result.get_summary()
        severity_colors = {
            'CRITICAL': '#dc3545',
            'HIGH': '#fd7e14',
            'MEDIUM': '#ffc107',
            'LOW': '#17a2b8',
            'INFO': '#6c757d'
        }
        
        # Generate findings HTML
        findings_html = self._generate_findings_html(result, severity_colors)
        
        # Generate statistics HTML
        stats_html = self._generate_statistics_html(result, summary, severity_colors)
        
        # Generate charts data
        charts_data = self._generate_charts_data(result, summary)
        
        # Fill template
        html_content = html_template.format(
            project_name=result.project_name,
            scan_date=result.scan_date.strftime('%Y-%m-%d %H:%M:%S'),
            scan_duration=f"{result.scan_duration:.2f}",
            total_findings=len(result.findings),
            critical_count=summary['CRITICAL'],
            high_count=summary['HIGH'],
            medium_count=summary['MEDIUM'],
            low_count=summary['LOW'],
            info_count=summary['INFO'],
            scanned_files=result.scanned_files,
            total_lines=result.total_lines,
            technologies=', '.join(result.technologies) if result.technologies else 'N/A',
            statistics_html=stats_html,
            findings_html=findings_html,
            charts_data=json.dumps(charts_data)
        )
        
        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def generate_json_report(self, result: AuditResult, output_path: Path) -> str:
        """Generate JSON report"""
        
        json_data = result.to_dict()
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_data, f, indent=2, ensure_ascii=False)
        
        return str(output_path)
    
    def generate_summary_text(self, result: AuditResult) -> str:
        """Generate text summary"""
        
        summary = result.get_summary()
        
        text = f"""
╔═══════════════════════════════════════════════════════════════╗
║           WINDOWS SECURITY AUDITOR - SCAN SUMMARY            ║
╚═══════════════════════════════════════════════════════════════╝

📁 Project: {result.project_name}
📅 Scan Date: {result.scan_date.strftime('%Y-%m-%d %H:%M:%S')}
⏱️  Duration: {result.scan_duration:.2f} seconds
📄 Files Scanned: {result.scanned_files:,}
📝 Total Lines: {result.total_lines:,}
🔧 Technologies: {', '.join(result.technologies) if result.technologies else 'N/A'}

╔═══════════════════════════════════════════════════════════════╗
║                      FINDINGS SUMMARY                         ║
╚═══════════════════════════════════════════════════════════════╝

🔴 CRITICAL: {summary['CRITICAL']}
🟠 HIGH:     {summary['HIGH']}
🟡 MEDIUM:   {summary['MEDIUM']}
🔵 LOW:      {summary['LOW']}
⚪ INFO:     {summary['INFO']}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
   TOTAL:    {len(result.findings)}

╔═══════════════════════════════════════════════════════════════╗
║                    FINDINGS BY CATEGORY                       ║
╚═══════════════════════════════════════════════════════════════╝
"""
        
        # Category breakdown
        for category, count in sorted(result.statistics.get('by_category', {}).items(),
                                     key=lambda x: x[1], reverse=True):
            text += f"\n{category:.<50} {count:>5}"
        
        text += "\n\n"
        
        # Top critical/high findings
        critical_high = [f for f in result.findings 
                        if f.severity in [Severity.CRITICAL, Severity.HIGH]]
        
        if critical_high:
            text += """
╔═══════════════════════════════════════════════════════════════╗
║              TOP PRIORITY FINDINGS (CRITICAL/HIGH)            ║
╚═══════════════════════════════════════════════════════════════╝
"""
            for idx, finding in enumerate(critical_high[:10], 1):
                text += f"\n{idx}. [{finding.severity.value}] {finding.title}\n"
                text += f"   📁 {Path(finding.file_path).name if finding.file_path else 'N/A'}"
                if finding.line_number:
                    text += f" (Line {finding.line_number})"
                text += f"\n   💡 {finding.recommendation[:100]}...\n"
        
        text += "\n" + "="*65 + "\n"
        text += "📊 Full detailed report available in HTML format\n"
        text += "="*65 + "\n"
        
        return text
    
    def _generate_findings_html(self, result: AuditResult, 
                                severity_colors: Dict[str, str]) -> str:
        """Generate findings HTML section"""
        
        if not result.findings:
            return "<p class='text-muted'>No findings detected.</p>"
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4
        }
        sorted_findings = sorted(result.findings, 
                                key=lambda f: (severity_order[f.severity], f.title))
        
        html = ""
        for finding in sorted_findings:
            severity_color = severity_colors.get(finding.severity.value, '#6c757d')
            
            html += f"""
            <div class="finding-card border-start" style="border-left: 4px solid {severity_color} !important;">
                <div class="d-flex justify-content-between align-items-start mb-2">
                    <h6 class="mb-0">{finding.title}</h6>
                    <span class="badge" style="background-color: {severity_color};">
                        {finding.severity.value}
                    </span>
                </div>
                <p class="text-muted mb-2"><small>{finding.category.value} | ID: {finding.id}</small></p>
                <p class="mb-2">{finding.description}</p>
                
                {f'<p class="mb-2"><strong>📁 File:</strong> <code>{Path(finding.file_path).name}</code> (Line {finding.line_number})</p>' if finding.file_path else ''}
                
                {f'''<div class="code-snippet mb-2">
                    <strong>Code Snippet:</strong>
                    <pre><code>{finding.code_snippet}</code></pre>
                </div>''' if finding.code_snippet else ''}
                
                {f'<p class="mb-2"><strong>🎯 Impact:</strong> {finding.impact}</p>' if finding.impact else ''}
                
                <div class="recommendation mb-2">
                    <strong>💡 Recommendation:</strong>
                    <p class="mb-0">{finding.recommendation}</p>
                </div>
                
                {f'<p class="mb-0"><small><strong>CWE:</strong> {finding.cwe_id} | <strong>OWASP:</strong> {finding.owasp_category}</small></p>' if finding.cwe_id or finding.owasp_category else ''}
                
                {f'''<p class="mb-0 mt-2"><small><strong>References:</strong><br>
                    {'<br>'.join([f'<a href="{ref}" target="_blank">{ref}</a>' for ref in finding.references])}
                    </small></p>''' if finding.references else ''}
            </div>
            """
        
        return html
    
    def _generate_statistics_html(self, result: AuditResult, summary: Dict[str, int],
                                  severity_colors: Dict[str, str]) -> str:
        """Generate statistics HTML section"""
        
        html = f"""
        <div class="row mb-4">
            <div class="col-md-4">
                <div class="stat-card">
                    <h6>Files with Issues</h6>
                    <h3>{result.statistics.get('files_with_issues', 0)}</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <h6>Average Confidence</h6>
                    <h3>{result.statistics.get('avg_confidence', 0):.1%}</h3>
                </div>
            </div>
            <div class="col-md-4">
                <div class="stat-card">
                    <h6>High Confidence Findings</h6>
                    <h3>{result.statistics.get('high_confidence_findings', 0)}</h3>
                </div>
            </div>
        </div>
        
        <h5>Findings by Category</h5>
        <table class="table table-striped">
            <thead>
                <tr>
                    <th>Category</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
            </thead>
            <tbody>
        """
        
        total = len(result.findings)
        for category, count in sorted(result.statistics.get('by_category', {}).items(),
                                     key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            html += f"""
                <tr>
                    <td>{category}</td>
                    <td>{count}</td>
                    <td>
                        <div class="progress" style="height: 20px;">
                            <div class="progress-bar" role="progressbar" 
                                 style="width: {percentage}%;" 
                                 aria-valuenow="{percentage}" aria-valuemin="0" aria-valuemax="100">
                                {percentage:.1f}%
                            </div>
                        </div>
                    </td>
                </tr>
            """
        
        html += """
            </tbody>
        </table>
        """
        
        return html
    
    def _generate_charts_data(self, result: AuditResult, 
                             summary: Dict[str, int]) -> Dict[str, Any]:
        """Generate data for charts"""
        
        return {
            'severity': {
                'labels': list(summary.keys()),
                'data': list(summary.values()),
                'colors': ['#dc3545', '#fd7e14', '#ffc107', '#17a2b8', '#6c757d']
            },
            'category': {
                'labels': list(result.statistics.get('by_category', {}).keys()),
                'data': list(result.statistics.get('by_category', {}).values())
            }
        }
    
    def _get_html_template(self) -> str:
        """Get HTML template"""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows Security Auditor Report - {project_name}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8f9fa; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 0; margin-bottom: 30px; }}
        .stat-card {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .severity-badge {{ display: inline-block; padding: 8px 16px; border-radius: 20px; color: white; font-weight: bold; margin: 5px; }}
        .finding-card {{ background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }}
        .code-snippet {{ background: #f5f5f5; padding: 15px; border-radius: 5px; overflow-x: auto; }}
        .code-snippet code {{ font-family: 'Courier New', monospace; font-size: 13px; }}
        .recommendation {{ background: #e7f3ff; padding: 15px; border-left: 4px solid #0066cc; border-radius: 4px; }}
        .progress {{ height: 30px; font-size: 14px; font-weight: bold; }}
        .chart-container {{ background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
    </style>
</head>
<body>
    <div class="header">
        <div class="container">
            <h1><i class="fas fa-shield-alt"></i> Windows Security Auditor Report</h1>
            <p class="lead">Comprehensive Security and Code Quality Analysis</p>
        </div>
    </div>
    
    <div class="container">
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="stat-card">
                    <h3>📁 {project_name}</h3>
                    <p class="mb-2"><strong>Scan Date:</strong> {scan_date}</p>
                    <p class="mb-2"><strong>Duration:</strong> {scan_duration} seconds</p>
                    <p class="mb-2"><strong>Files Scanned:</strong> {scanned_files:,}</p>
                    <p class="mb-2"><strong>Total Lines:</strong> {total_lines:,}</p>
                    <p class="mb-0"><strong>Technologies:</strong> {technologies}</p>
                </div>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="stat-card text-center">
                    <h4>Findings Summary</h4>
                    <div class="mt-3">
                        <span class="severity-badge" style="background-color: #dc3545;">🔴 CRITICAL: {critical_count}</span>
                        <span class="severity-badge" style="background-color: #fd7e14;">🟠 HIGH: {high_count}</span>
                        <span class="severity-badge" style="background-color: #ffc107;">🟡 MEDIUM: {medium_count}</span>
                        <span class="severity-badge" style="background-color: #17a2b8;">🔵 LOW: {low_count}</span>
                        <span class="severity-badge" style="background-color: #6c757d;">⚪ INFO: {info_count}</span>
                    </div>
                    <h2 class="mt-3">Total: {total_findings}</h2>
                </div>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Findings by Severity</h5>
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="col-md-6">
                <div class="chart-container">
                    <h5>Findings by Category</h5>
                    <canvas id="categoryChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="stat-card">
                    <h4>📊 Statistics</h4>
                    {statistics_html}
                </div>
            </div>
        </div>
        
        <div class="row mb-4">
            <div class="col-md-12">
                <div class="stat-card">
                    <h4>🔍 Detailed Findings</h4>
                    <hr>
                    {findings_html}
                </div>
            </div>
        </div>
        
        <footer class="text-center text-muted pb-4">
            <p>Generated by Windows Security Auditor | © 2026</p>
        </footer>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script>
        const chartsData = {charts_data};
        
        // Severity Chart
        new Chart(document.getElementById('severityChart'), {{
            type: 'doughnut',
            data: {{
                labels: chartsData.severity.labels,
                datasets: [{{
                    data: chartsData.severity.data,
                    backgroundColor: chartsData.severity.colors
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ position: 'bottom' }}
                }}
            }}
        }});
        
        // Category Chart
        new Chart(document.getElementById('categoryChart'), {{
            type: 'bar',
            data: {{
                labels: chartsData.category.labels,
                datasets: [{{
                    label: 'Findings',
                    data: chartsData.category.data,
                    backgroundColor: '#667eea'
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{ display: false }}
                }},
                scales: {{
                    y: {{ beginAtZero: true }}
                }}
            }}
        }});
    </script>
</body>
</html>"""


if __name__ == "__main__":
    print("✅ Report Generator initialized")
