#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Security Auditor - GUI Application
Modern graphical interface for security auditing
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import sys
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.append(str(Path(__file__).parent))

from core.auditor_engine import AuditorEngine, AuditResult
from analyzers.security_analyzer import SecurityAnalyzer
from analyzers.quality_analyzer import CodeQualityAnalyzer
from analyzers.config_analyzer import ConfigAnalyzer
from reporters.report_generator import ReportGenerator


class AuditorGUI:
    """Main GUI Application for Windows Security Auditor"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Windows Security Auditor v1.0")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # Initialize components
        self.engine = None
        self.scan_thread = None
        self.current_result = None
        
        # Configure styles
        self._configure_styles()
        
        # Build UI
        self._build_ui()
        
    def _configure_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Segoe UI', 18, 'bold'), 
                       background='#667eea', foreground='white', padding=10)
        style.configure('Subtitle.TLabel', font=('Segoe UI', 10), 
                       background='#667eea', foreground='white')
        style.configure('Section.TLabel', font=('Segoe UI', 12, 'bold'))
        style.configure('Info.TLabel', font=('Segoe UI', 9))
        
        style.configure('Primary.TButton', font=('Segoe UI', 10, 'bold'),
                       padding=10)
        style.configure('Success.TButton', font=('Segoe UI', 10),
                       padding=8, background='#28a745')
        
        style.configure('Progress.TProgressbar', thickness=25)
        
    def _build_ui(self):
        """Build the user interface"""
        
        # Header
        header_frame = tk.Frame(self.root, bg='#667eea', height=100)
        header_frame.pack(fill='x', side='top')
        header_frame.pack_propagate(False)
        
        title_label = ttk.Label(header_frame, text="🛡️ Windows Security Auditor",
                               style='Title.TLabel')
        title_label.pack(pady=(10, 0))
        
        subtitle_label = ttk.Label(header_frame, 
                                   text="Advanced Security & Code Quality Analysis for Windows Projects",
                                   style='Subtitle.TLabel')
        subtitle_label.pack()
        
        # Main container
        main_container = ttk.Frame(self.root, padding="20")
        main_container.pack(fill='both', expand=True)
        
        # Left panel - Configuration
        left_panel = ttk.LabelFrame(main_container, text="Configuration", padding="15")
        left_panel.grid(row=0, column=0, sticky='nsew', padx=(0, 10))
        
        # Target directory selection
        ttk.Label(left_panel, text="Target Directory:", style='Section.TLabel').pack(anchor='w', pady=(0, 5))
        
        dir_frame = ttk.Frame(left_panel)
        dir_frame.pack(fill='x', pady=(0, 15))
        
        self.dir_entry = ttk.Entry(dir_frame, width=40)
        self.dir_entry.pack(side='left', fill='x', expand=True, padx=(0, 5))
        
        browse_btn = ttk.Button(dir_frame, text="Browse...", command=self._browse_directory)
        browse_btn.pack(side='left')
        
        # Analyzer selection
        ttk.Label(left_panel, text="Analysis Modules:", style='Section.TLabel').pack(anchor='w', pady=(10, 5))
        
        self.analyzer_vars = {
            'security': tk.BooleanVar(value=True),
            'quality': tk.BooleanVar(value=True),
            'config': tk.BooleanVar(value=True)
        }
        
        analyzers_frame = ttk.Frame(left_panel)
        analyzers_frame.pack(fill='x', pady=(0, 15))
        
        ttk.Checkbutton(analyzers_frame, text="🔒 Security Analysis (OWASP, CWE)",
                       variable=self.analyzer_vars['security']).pack(anchor='w', pady=2)
        ttk.Checkbutton(analyzers_frame, text="📊 Code Quality & Architecture",
                       variable=self.analyzer_vars['quality']).pack(anchor='w', pady=2)
        ttk.Checkbutton(analyzers_frame, text="⚙️ Configuration & Dependencies",
                       variable=self.analyzer_vars['config']).pack(anchor='w', pady=2)
        
        # Scan options
        ttk.Label(left_panel, text="Scan Options:", style='Section.TLabel').pack(anchor='w', pady=(10, 5))
        
        options_frame = ttk.Frame(left_panel)
        options_frame.pack(fill='x', pady=(0, 15))
        
        self.deep_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Deep Scan Mode",
                       variable=self.deep_scan_var).pack(anchor='w', pady=2)
        
        # Action buttons
        actions_frame = ttk.Frame(left_panel)
        actions_frame.pack(fill='x', pady=(20, 0))
        
        self.start_btn = ttk.Button(actions_frame, text="▶️ Start Scan",
                                    command=self._start_scan, style='Primary.TButton')
        self.start_btn.pack(fill='x', pady=(0, 5))
        
        self.stop_btn = ttk.Button(actions_frame, text="⏹️ Stop Scan",
                                   command=self._stop_scan, state='disabled')
        self.stop_btn.pack(fill='x', pady=(0, 5))
        
        self.export_btn = ttk.Button(actions_frame, text="💾 Export Report",
                                     command=self._export_report, state='disabled',
                                     style='Success.TButton')
        self.export_btn.pack(fill='x')
        
        # Right panel - Progress and Results
        right_panel = ttk.Frame(main_container)
        right_panel.grid(row=0, column=1, sticky='nsew')
        
        # Progress section
        progress_frame = ttk.LabelFrame(right_panel, text="Scan Progress", padding="15")
        progress_frame.pack(fill='x', pady=(0, 10))
        
        self.progress_label = ttk.Label(progress_frame, text="Ready to scan...", style='Info.TLabel')
        self.progress_label.pack(anchor='w', pady=(0, 5))
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='determinate',
                                           style='Progress.TProgressbar')
        self.progress_bar.pack(fill='x', pady=(0, 5))
        
        self.progress_percent = ttk.Label(progress_frame, text="0%", style='Info.TLabel')
        self.progress_percent.pack(anchor='w')
        
        # Results section
        results_frame = ttk.LabelFrame(right_panel, text="Scan Results", padding="15")
        results_frame.pack(fill='both', expand=True)
        
        # Results text area
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD,
                                                      font=('Consolas', 9),
                                                      bg='#1e1e1e', fg='#d4d4d4',
                                                      insertbackground='white')
        self.results_text.pack(fill='both', expand=True)
        
        # Configure grid weights
        main_container.columnconfigure(1, weight=1)
        main_container.rowconfigure(0, weight=1)
        
        # Status bar
        status_frame = tk.Frame(self.root, bg='#667eea', height=30)
        status_frame.pack(fill='x', side='bottom')
        status_frame.pack_propagate(False)
        
        self.status_label = tk.Label(status_frame, text="Ready", 
                                     bg='#667eea', fg='white',
                                     font=('Segoe UI', 9))
        self.status_label.pack(side='left', padx=10)
        
    def _browse_directory(self):
        """Browse for target directory"""
        directory = filedialog.askdirectory(title="Select Project Directory")
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)
            
    def _start_scan(self):
        """Start the security scan"""
        target_dir = self.dir_entry.get()
        
        if not target_dir:
            messagebox.showerror("Error", "Please select a target directory")
            return
        
        if not Path(target_dir).exists():
            messagebox.showerror("Error", "Target directory does not exist")
            return
        
        # Disable start button, enable stop button
        self.start_btn.config(state='disabled')
        self.stop_btn.config(state='normal')
        self.export_btn.config(state='disabled')
        
        # Clear results
        self.results_text.delete('1.0', tk.END)
        self.progress_bar['value'] = 0
        
        # Initialize engine
        self.engine = AuditorEngine()
        self.engine.set_progress_callback(self._update_progress)
        
        # Register analyzers based on selection
        if self.analyzer_vars['security'].get():
            self.engine.register_analyzer(SecurityAnalyzer())
        if self.analyzer_vars['quality'].get():
            self.engine.register_analyzer(CodeQualityAnalyzer())
        if self.analyzer_vars['config'].get():
            self.engine.register_analyzer(ConfigAnalyzer())
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(target=self._run_scan, args=(target_dir,))
        self.scan_thread.daemon = True
        self.scan_thread.start()
        
    def _run_scan(self, target_dir):
        """Run the scan in background thread"""
        try:
            self._update_status("Scanning in progress...")
            result = self.engine.scan_directory(target_dir)
            self.current_result = result
            
            # Generate summary
            report_gen = ReportGenerator()
            summary = report_gen.generate_summary_text(result)
            
            # Update UI in main thread
            self.root.after(0, self._scan_complete, summary)
            
        except Exception as e:
            self.root.after(0, self._scan_error, str(e))
    
    def _scan_complete(self, summary):
        """Handle scan completion"""
        self.results_text.insert('1.0', summary)
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self.export_btn.config(state='normal')
        self._update_status("Scan completed successfully")
        messagebox.showinfo("Scan Complete", "Security scan completed successfully!")
        
    def _scan_error(self, error_msg):
        """Handle scan error"""
        self.results_text.insert('1.0', f"ERROR: {error_msg}")
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        self._update_status("Scan failed")
        messagebox.showerror("Scan Error", f"An error occurred during scan:\n{error_msg}")
        
    def _stop_scan(self):
        """Stop the current scan"""
        if self.engine:
            self.engine.stop()
            self._update_status("Scan stopped by user")
            self.start_btn.config(state='normal')
            self.stop_btn.config(state='disabled')
            
    def _update_progress(self, message, percent):
        """Update progress bar and label"""
        self.root.after(0, self._update_progress_ui, message, percent)
        
    def _update_progress_ui(self, message, percent):
        """Update progress UI elements (must be called from main thread)"""
        self.progress_label.config(text=message)
        self.progress_bar['value'] = percent
        self.progress_percent.config(text=f"{percent:.0f}%")
        
    def _update_status(self, message):
        """Update status bar"""
        self.root.after(0, lambda: self.status_label.config(text=message))
        
    def _export_report(self):
        """Export scan results to files"""
        if not self.current_result:
            messagebox.showerror("Error", "No scan results to export")
            return
        
        # Ask for output directory
        output_dir = filedialog.askdirectory(title="Select Output Directory")
        if not output_dir:
            return
        
        output_path = Path(output_dir)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        try:
            report_gen = ReportGenerator()
            
            # Generate HTML report
            html_path = output_path / f"security_report_{timestamp}.html"
            report_gen.generate_html_report(self.current_result, html_path)
            
            # Generate JSON report
            json_path = output_path / f"security_report_{timestamp}.json"
            report_gen.generate_json_report(self.current_result, json_path)
            
            messagebox.showinfo("Export Complete", 
                              f"Reports exported successfully:\n\n" +
                              f"HTML: {html_path.name}\n" +
                              f"JSON: {json_path.name}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export reports:\n{str(e)}")


def main():
    """Main entry point"""
    root = tk.Tk()
    app = AuditorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
