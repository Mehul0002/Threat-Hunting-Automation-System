import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
import threading
import os
from typing import List, Dict, Any
from log_parser import LogParser
from ioc_detector import IOCDetector
from sigma_engine import SigmaEngine
from behavior_analyzer import BehaviorAnalyzer
from database import ThreatDatabase
from report_generator import ReportGenerator
from utils import logger

class ThreatHunterGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Threat-Hunting Automation System")
        self.root.geometry("1000x700")
        
        # Initialize components
        self.log_parser = LogParser()
        self.ioc_detector = IOCDetector()
        self.sigma_engine = SigmaEngine()
        self.behavior_analyzer = BehaviorAnalyzer()
        self.database = ThreatDatabase()
        self.report_generator = ReportGenerator()
        
        # Variables
        self.log_file_path = ""
        self.os_type = tk.StringVar(value="windows")
        self.status_var = tk.StringVar(value="Idle")
        self.parsed_logs = []
        self.ioc_matches = []
        self.sigma_matches = []
        self.behavior_alerts = []
        
        self.setup_ui()
        
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        
        # File selection
        ttk.Label(main_frame, text="Log File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.file_entry = ttk.Entry(main_frame, width=50)
        self.file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=0, column=2, padx=(5,0), pady=5)
        
        # OS Type selection
        ttk.Label(main_frame, text="OS Type:").grid(row=1, column=0, sticky=tk.W, pady=5)
        os_frame = ttk.Frame(main_frame)
        os_frame.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5)
        ttk.Radiobutton(os_frame, text="Windows", variable=self.os_type, value="windows").pack(side=tk.LEFT)
        ttk.Radiobutton(os_frame, text="Linux", variable=self.os_type, value="linux").pack(side=tk.LEFT)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=10)
        ttk.Button(button_frame, text="Run Threat Hunt", command=self.run_threat_hunt).pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(button_frame, text="Generate TXT Report", command=lambda: self.generate_report("txt")).pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(button_frame, text="Generate PDF Report", command=lambda: self.generate_report("pdf")).pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(button_frame, text="Generate JSON Report", command=lambda: self.generate_report("json")).pack(side=tk.LEFT)
        
        # Status bar
        ttk.Label(main_frame, textvariable=self.status_var).grid(row=3, column=0, columnspan=3, sticky=tk.W, pady=5)
        
        # Output panel
        ttk.Label(main_frame, text="Detection Output:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.output_text = ScrolledText(main_frame, height=15, wrap=tk.WORD)
        self.output_text.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        
        # IOC Table
        ttk.Label(main_frame, text="IOC Matches:").grid(row=6, column=0, sticky=tk.W, pady=5)
        self.ioc_tree = ttk.Treeview(main_frame, columns=("Type", "Value", "Severity", "Description"), show="headings", height=8)
        self.ioc_tree.heading("Type", text="Type")
        self.ioc_tree.heading("Value", text="Value")
        self.ioc_tree.heading("Severity", text="Severity")
        self.ioc_tree.heading("Description", text="Description")
        self.ioc_tree.column("Type", width=100)
        self.ioc_tree.column("Value", width=150)
        self.ioc_tree.column("Severity", width=80)
        self.ioc_tree.column("Description", width=200)
        
        ioc_scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.ioc_tree.yview)
        self.ioc_tree.configure(yscrollcommand=ioc_scrollbar.set)
        self.ioc_tree.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=5)
        ioc_scrollbar.grid(row=7, column=2, sticky=(tk.N, tk.S))
        
        # Threat Severity Indicator
        severity_frame = ttk.LabelFrame(main_frame, text="Threat Severity Summary", padding="5")
        severity_frame.grid(row=8, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        self.severity_labels = {}
        severities = ["Low", "Medium", "High", "Critical"]
        colors = ["green", "yellow", "orange", "red"]
        
        for i, (sev, color) in enumerate(zip(severities, colors)):
            ttk.Label(severity_frame, text=f"{sev}: 0").grid(row=0, column=i, padx=10)
            self.severity_labels[sev.lower()] = ttk.Label(severity_frame, text="0")
            self.severity_labels[sev.lower()].grid(row=0, column=i, padx=10)
    
    def browse_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Log File",
            filetypes=[("Log files", "*.log *.txt *.evtx"), ("All files", "*.*")]
        )
        if file_path:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, file_path)
            self.log_file_path = file_path
    
    def run_threat_hunt(self):
        if not self.log_file_path:
            messagebox.showerror("Error", "Please select a log file first.")
            return
        
        self.status_var.set("Running...")
        self.output_text.delete(1.0, tk.END)
        self.ioc_tree.delete(*self.ioc_tree.get_children())
        
        # Run in separate thread to avoid freezing GUI
        thread = threading.Thread(target=self._run_hunt_process)
        thread.start()
    
    def _run_hunt_process(self):
        try:
            # Parse logs
            self.output_text.insert(tk.END, "Parsing logs...\n")
            self.root.update()
            
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_logs = f.readlines()
            
            self.parsed_logs = self.log_parser.parse_logs(raw_logs, self.os_type.get())
            
            # Store in database
            for log in self.parsed_logs:
                self.database.insert_log(log)
            
            self.output_text.insert(tk.END, f"Parsed {len(self.parsed_logs)} log entries.\n")
            self.root.update()
            
            # Detect IOCs
            self.output_text.insert(tk.END, "Detecting IOCs...\n")
            self.root.update()
            self.ioc_matches = self.ioc_detector.detect_iocs(self.parsed_logs)
            
            # Store IOC matches
            for match in self.ioc_matches:
                ioc_id = self.database.insert_ioc({
                    'type': match['ioc_type'],
                    'value': match['ioc_value'],
                    'severity': match['severity'],
                    'description': match['description']
                })
                self.database.insert_alert({
                    'log_id': match['log_id'],
                    'ioc_id': ioc_id,
                    'sigma_rule': None,
                    'severity': match['severity'],
                    'timestamp': match['timestamp']
                })
            
            self.output_text.insert(tk.END, f"Found {len(self.ioc_matches)} IOC matches.\n")
            self.root.update()
            
            # Run Sigma rules
            self.output_text.insert(tk.END, "Running Sigma rules...\n")
            self.root.update()
            self.sigma_matches = self.sigma_engine.match_rules(self.parsed_logs)
            
            # Store Sigma matches
            for match in self.sigma_matches:
                self.database.insert_alert({
                    'log_id': match['log_id'],
                    'ioc_id': None,
                    'sigma_rule': match['rule_title'],
                    'severity': match['severity'],
                    'timestamp': match['timestamp']
                })
            
            self.output_text.insert(tk.END, f"Found {len(self.sigma_matches)} Sigma rule matches.\n")
            self.root.update()
            
            # Analyze behavior
            self.output_text.insert(tk.END, "Analyzing behavior...\n")
            self.root.update()
            self.behavior_alerts = self.behavior_analyzer.analyze_all_behaviors(self.parsed_logs)
            
            self.output_text.insert(tk.END, f"Found {len(self.behavior_alerts)} behavior alerts.\n")
            self.root.update()
            
            # Update UI
            self._update_ui_with_results()
            
            self.status_var.set("Completed")
            self.output_text.insert(tk.END, "Threat hunt completed successfully!\n")
            
        except Exception as e:
            self.status_var.set("Error")
            self.output_text.insert(tk.END, f"Error during threat hunt: {str(e)}\n")
            logger.error(f"Error in threat hunt: {str(e)}")
    
    def _update_ui_with_results(self):
        # Update IOC table
        for match in self.ioc_matches:
            self.ioc_tree.insert("", tk.END, values=(
                match.get('ioc_type', ''),
                match.get('ioc_value', ''),
                match.get('severity', ''),
                match.get('description', '')
            ))
        
        # Update severity summary
        severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        
        for match in self.ioc_matches + self.sigma_matches + self.behavior_alerts:
            sev = match.get('severity', 'low').lower()
            if sev in severity_counts:
                severity_counts[sev] += 1
        
        for sev, count in severity_counts.items():
            if sev in self.severity_labels:
                self.severity_labels[sev].config(text=str(count))
    
    def generate_report(self, format_type):
        if not self.parsed_logs:
            messagebox.showerror("Error", "Please run threat hunt first.")
            return
        
        file_ext = {"txt": "txt", "pdf": "pdf", "json": "json"}.get(format_type, "txt")
        file_path = filedialog.asksaveasfilename(
            defaultextension=f".{file_ext}",
            filetypes=[(f"{file_ext.upper()} files", f"*.{file_ext}"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                if format_type == "txt":
                    self.report_generator.generate_txt_report(
                        [], self.ioc_matches, self.sigma_matches, self.behavior_alerts, file_path
                    )
                elif format_type == "pdf":
                    self.report_generator.generate_pdf_report(
                        [], self.ioc_matches, self.sigma_matches, self.behavior_alerts, file_path
                    )
                elif format_type == "json":
                    self.report_generator.generate_json_report(
                        [], self.ioc_matches, self.sigma_matches, self.behavior_alerts, file_path
                    )
                
                messagebox.showinfo("Success", f"Report generated: {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate report: {str(e)}")

def main():
    root = tk.Tk()
    app = ThreatHunterGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
