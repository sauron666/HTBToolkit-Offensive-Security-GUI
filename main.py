import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import threading
import os
import socket
import time
from typing import Dict, List, Optional

# Import our modules
from shell_tools import ShellTools
from reverse_shells import ReverseShellGenerator
from exploit_templates import ExploitTemplates
from bruteforce import BruteForce
from file_ops import FileOperations

class HTBToolkitApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HTBToolkit - Offensive Security Toolkit")
        self.root.geometry("1200x800")
        
        # Configure styles
        self.configure_styles()
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')
        
        # Create all tabs
        self.create_shell_tab()
        self.create_reverse_shell_tab()
        self.create_exploit_tab()
        self.create_bruteforce_tab()
        self.create_file_ops_tab()
        self.create_post_exploit_tab()
        self.create_persistence_tab()
        self.create_av_evasion_tab()
        self.create_redteam_tab()
        
        # Status bar
        self.status = tk.StringVar()
        self.status.set("Ready")
        ttk.Label(self.root, textvariable=self.status, relief='sunken').pack(fill='x')
        
    def configure_styles(self):
        """Configure ttk styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('.', 
                       background='#1e1e1e',
                       foreground='#d4d4d4',
                       fieldbackground='#2e2e2e',
                       insertcolor='white')
        
        style.configure('TNotebook', background='#1e1e1e')
        style.configure('TNotebook.Tab', 
                       background='#2e2e2e',
                       foreground='white',
                       padding=[10, 5])
        style.map('TNotebook.Tab',
                 background=[('selected', '#3e3e3e')],
                 foreground=[('selected', 'white')])
        
        style.configure('TFrame', background='#1e1e1e')
        style.configure('TLabel', background='#1e1e1e', foreground='white')
        style.configure('TButton', 
                       background='#2e2e2e',
                       foreground='white',
                       padding=5)
        style.map('TButton',
                 background=[('active', '#3e3e3e')],
                 foreground=[('active', 'lime')])
        
        style.configure('TEntry', fieldbackground='#2e2e2e')
        style.configure('TCombobox', fieldbackground='#2e2e2e')
        
    def create_shell_tab(self):
        """Create shell commands tab"""
        self.shell_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.shell_tab, text="Shell Tools")
        
        # Command input
        ttk.Label(self.shell_tab, text="Command:").pack(pady=5)
        self.shell_cmd = ttk.Entry(self.shell_tab, width=80)
        self.shell_cmd.pack(pady=5)
        
        # Execute button
        ttk.Button(self.shell_tab, 
                  text="Execute", 
                  command=self.execute_shell_command).pack(pady=5)
        
        # Output area
        self.shell_output = scrolledtext.ScrolledText(
            self.shell_tab,
            width=100,
            height=20,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.shell_output.pack(pady=10, padx=10, fill='both', expand=True)
        
    def create_reverse_shell_tab(self):
        """Create reverse shell generator tab"""
        self.reverse_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.reverse_tab, text="Reverse Shells")
        
        # IP and port inputs
        input_frame = ttk.Frame(self.reverse_tab)
        input_frame.pack(pady=10)
        
        ttk.Label(input_frame, text="LHOST:").grid(row=0, column=0, padx=5)
        self.reverse_ip = ttk.Entry(input_frame, width=20)
        self.reverse_ip.insert(0, "10.10.10.10")
        self.reverse_ip.grid(row=0, column=1, padx=5)
        
        ttk.Label(input_frame, text="LPORT:").grid(row=0, column=2, padx=5)
        self.reverse_port = ttk.Entry(input_frame, width=10)
        self.reverse_port.insert(0, "4444")
        self.reverse_port.grid(row=0, column=3, padx=5)
        
        # Shell type selection
        ttk.Label(self.reverse_tab, text="Shell Type:").pack(pady=5)
        self.shell_type = ttk.Combobox(
            self.reverse_tab,
            values=["Bash TCP", "Bash UDP", "Python", "PHP", "PowerShell", 
                   "Perl", "Ruby", "Netcat", "Socat", "Java"],
            state="readonly"
        )
        self.shell_type.current(0)
        self.shell_type.pack(pady=5)
        
        # Generate button
        ttk.Button(self.reverse_tab, 
                  text="Generate Payload", 
                  command=self.generate_reverse_shell).pack(pady=10)
        
        # Output area
        self.reverse_output = scrolledtext.ScrolledText(
            self.reverse_tab,
            width=100,
            height=15,
            bg='#2e2e2e',
            fg='lime',
            insertbackground='white'
        )
        self.reverse_output.pack(pady=10, padx=10, fill='both', expand=True)
        
        # Copy button
        ttk.Button(self.reverse_tab,
                  text="Copy to Clipboard",
                  command=self.copy_reverse_shell).pack(pady=5)
    
    def create_exploit_tab(self):
        """Create exploit templates tab"""
        self.exploit_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.exploit_tab, text="Exploit Templates")
        
        # Exploit type selection
        ttk.Label(self.exploit_tab, text="Exploit Type:").pack(pady=5)
        self.exploit_type = ttk.Combobox(
            self.exploit_tab,
            values=["LFI", "RFI", "Command Injection", "XXE", "SQL Injection",
                   "XSS", "SSRF", "File Upload Bypass"],
            state="readonly"
        )
        self.exploit_type.current(0)
        self.exploit_type.pack(pady=5)
        
        # Target URL input
        ttk.Label(self.exploit_tab, text="Target URL:").pack(pady=5)
        self.target_url = ttk.Entry(self.exploit_tab, width=60)
        self.target_url.insert(0, "http://example.com/vulnerable.php?param=")
        self.target_url.pack(pady=5)
        
        # Generate button
        ttk.Button(self.exploit_tab, 
                  text="Generate Payloads", 
                  command=self.generate_exploit_payloads).pack(pady=10)
        
        # Output area
        self.exploit_output = scrolledtext.ScrolledText(
            self.exploit_tab,
            width=100,
            height=20,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.exploit_output.pack(pady=10, padx=10, fill='both', expand=True)
    
    def create_bruteforce_tab(self):
        """Create brute force tab"""
        self.brute_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.brute_tab, text="Brute Force")
        
        # Service selection
        ttk.Label(self.brute_tab, text="Service:").pack(pady=5)
        self.brute_service = ttk.Combobox(
            self.brute_tab,
            values=["SSH", "FTP", "HTTP Basic Auth"],
            state="readonly"
        )
        self.brute_service.current(0)
        self.brute_service.pack(pady=5)
        
        # Target inputs
        input_frame = ttk.Frame(self.brute_tab)
        input_frame.pack(pady=10)
        
        ttk.Label(input_frame, text="Target:").grid(row=0, column=0, padx=5)
        self.brute_target = ttk.Entry(input_frame, width=20)
        self.brute_target.grid(row=0, column=1, padx=5)
        
        ttk.Label(input_frame, text="Port:").grid(row=0, column=2, padx=5)
        self.brute_port = ttk.Entry(input_frame, width=10)
        self.brute_port.insert(0, "22")
        self.brute_port.grid(row=0, column=3, padx=5)
        
        # File selection
        ttk.Label(self.brute_tab, text="Username List:").pack(pady=5)
        self.user_list_file = ttk.Entry(self.brute_tab, width=60)
        self.user_list_file.pack(pady=5)
        ttk.Button(self.brute_tab, 
                  text="Browse...", 
                  command=lambda: self.browse_file(self.user_list_file)).pack(pady=5)
        
        ttk.Label(self.brute_tab, text="Password List:").pack(pady=5)
        self.pass_list_file = ttk.Entry(self.brute_tab, width=60)
        self.pass_list_file.pack(pady=5)
        ttk.Button(self.brute_tab, 
                  text="Browse...", 
                  command=lambda: self.browse_file(self.pass_list_file)).pack(pady=5)
        
        # Start button
        ttk.Button(self.brute_tab, 
                  text="Start Attack", 
                  command=self.start_bruteforce).pack(pady=10)
        
        # Output area
        self.brute_output = scrolledtext.ScrolledText(
            self.brute_tab,
            width=100,
            height=15,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.brute_output.pack(pady=10, padx=10, fill='both', expand=True)
    
    def create_file_ops_tab(self):
        """Create file operations tab"""
        self.file_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.file_tab, text="File Operations")
        
        # Operation selection
        ttk.Label(self.file_tab, text="Operation:").pack(pady=5)
        self.file_op = ttk.Combobox(
            self.file_tab,
            values=["Read File", "Write File", "Delete File", "Upload File", 
                   "Download File", "Find Files", "Check Permissions"],
            state="readonly"
        )
        self.file_op.current(0)
        self.file_op.pack(pady=5)
        
        # Path input
        ttk.Label(self.file_tab, text="Path/URL:").pack(pady=5)
        self.file_path = ttk.Entry(self.file_tab, width=60)
        self.file_path.pack(pady=5)
        ttk.Button(self.file_tab, 
                  text="Browse...", 
                  command=lambda: self.browse_file(self.file_path)).pack(pady=5)
        
        # Content for write operations
        ttk.Label(self.file_tab, text="Content (for write operations):").pack(pady=5)
        self.file_content = scrolledtext.ScrolledText(
            self.file_tab,
            width=60,
            height=5,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.file_content.pack(pady=5)
        
        # Execute button
        ttk.Button(self.file_tab, 
                  text="Execute", 
                  command=self.execute_file_op).pack(pady=10)
        
        # Output area
        self.file_output = scrolledtext.ScrolledText(
            self.file_tab,
            width=100,
            height=15,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.file_output.pack(pady=10, padx=10, fill='both', expand=True)
    
    def create_post_exploit_tab(self):
        """Create post-exploitation tab"""
        self.post_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.post_tab, text="Post-Exploitation")
        
        # System info button
        ttk.Button(self.post_tab,
                  text="Get System Info",
                  command=self.get_system_info).pack(pady=5)
        
        # Network info button
        ttk.Button(self.post_tab,
                  text="Get Network Info",
                  command=self.get_network_info).pack(pady=5)
        
        # Process list button
        ttk.Button(self.post_tab,
                  text="List Processes",
                  command=self.list_processes).pack(pady=5)
        
        # Find SUID files button
        ttk.Button(self.post_tab,
                  text="Find SUID Files",
                  command=self.find_suid_files).pack(pady=5)
        
        # Output area
        self.post_output = scrolledtext.ScrolledText(
            self.post_tab,
            width=100,
            height=20,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.post_output.pack(pady=10, padx=10, fill='both', expand=True)
    
    def create_persistence_tab(self):
        """Create persistence techniques tab"""
        self.persist_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.persist_tab, text="Persistence")
        
        # Technique selection
        ttk.Label(self.persist_tab, text="Technique:").pack(pady=5)
        self.persist_tech = ttk.Combobox(
            self.persist_tab,
            values=["Cron Job", "Startup Script", "SSH Key", "Web Shell", 
                   "Service", "Registry Run Key"],
            state="readonly"
        )
        self.persist_tech.current(0)
        self.persist_tech.pack(pady=5)
        
        # Generate button
        ttk.Button(self.persist_tab, 
                  text="Generate Payload", 
                  command=self.generate_persistence).pack(pady=10)
        
        # Output area
        self.persist_output = scrolledtext.ScrolledText(
            self.persist_tab,
            width=100,
            height=20,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.persist_output.pack(pady=10, padx=10, fill='both', expand=True)
    
    def create_av_evasion_tab(self):
        """Create AV evasion tab"""
        self.evasion_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.evasion_tab, text="AV Evasion")
        
        # Technique selection
        ttk.Label(self.evasion_tab, text="Technique:").pack(pady=5)
        self.evasion_tech = ttk.Combobox(
            self.evasion_tab,
            values=["Base64 Encoding", "XOR Encryption", "PowerShell Obfuscation",
                   "HTA Wrapper", "Image Polyglot"],
            state="readonly"
        )
        self.evasion_tech.current(0)
        self.evasion_tech.pack(pady=5)
        
        # Generate button
        ttk.Button(self.evasion_tab, 
                  text="Generate Payload", 
                  command=self.generate_evasion).pack(pady=10)
        
        # Output area
        self.evasion_output = scrolledtext.ScrolledText(
            self.evasion_tab,
            width=100,
            height=20,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.evasion_output.pack(pady=10, padx=10, fill='both', expand=True)
    
    def create_redteam_tab(self):
        """Create red team operations tab"""
        self.redteam_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.redteam_tab, text="Red Team")
        
        # Operation selection
        ttk.Label(self.redteam_tab, text="Operation:").pack(pady=5)
        self.redteam_op = ttk.Combobox(
            self.redteam_tab,
            values=["Kerberoasting", "Pass the Hash", "Golden Ticket", 
                   "Lateral Movement", "Credential Dumping"],
            state="readonly"
        )
        self.redteam_op.current(0)
        self.redteam_op.pack(pady=5)
        
        # Generate button
        ttk.Button(self.redteam_tab, 
                  text="Generate Command", 
                  command=self.generate_redteam).pack(pady=10)
        
        # Output area
        self.redteam_output = scrolledtext.ScrolledText(
            self.redteam_tab,
            width=100,
            height=20,
            bg='#2e2e2e',
            fg='white',
            insertbackground='white'
        )
        self.redteam_output.pack(pady=10, padx=10, fill='both', expand=True)
    # Добавяне на новите табове
    def create_office_tab(self):
        """Create Office payload tab"""
        self.office_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.office_tab, text="Office Payloads")
        
        # Document type
        ttk.Label(self.office_tab, text="Document Type:").pack(pady=5)
        self.office_type = ttk.Combobox(
            self.office_tab,
            values=["Word Macro (DOCM)", "Excel Macro (XLSM)", "HTA Application"],
            state="readonly"
        )
        self.office_type.current(0)
        self.office_type.pack(pady=5)
        
        # Payload input
        ttk.Label(self.office_tab, text="Payload Code:").pack(pady=5)
        self.office_payload = scrolledtext.ScrolledText(
            self.office_tab,
            width=80,
            height=10,
            bg='#2e2e2e',
            fg='white'
        )
        self.office_payload.pack(pady=5)
        self.office_payload.insert(tk.END, 
            "Sub AutoOpen()\n    MsgBox \"Document loaded\", vbInformation\nEnd Sub")
        
        # Generate button
        ttk.Button(self.office_tab,
                  text="Generate Document",
                  command=self.generate_office_payload).pack(pady=10)
        
        # Output
        self.office_output = scrolledtext.ScrolledText(
            self.office_tab,
            width=80,
            height=10,
            bg='#2e2e2e',
            fg='white'
        )
        self.office_output.pack(pady=10)
    
    def create_obfuscation_tab(self):
        """Create code obfuscation tab"""
        self.obfuscate_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.obfuscate_tab, text="Code Obfuscation")
        
        # Language selection
        ttk.Label(self.obfuscate_tab, text="Language:").pack(pady=5)
        self.obfuscate_lang = ttk.Combobox(
            self.obfuscate_tab,
            values=["powershell", "vba", "bash"],
            state="readonly"
        )
        self.obfuscate_lang.current(0)
        self.obfuscate_lang.pack(pady=5)
        
        # Code input
        ttk.Label(self.obfuscate_tab, text="Original Code:").pack(pady=5)
        self.obfuscate_input = scrolledtext.ScrolledText(
            self.obfuscate_tab,
            width=80,
            height=10,
            bg='#2e2e2e',
            fg='white'
        )
        self.obfuscate_input.pack(pady=5)
        
        # Obfuscate button
        ttk.Button(self.obfuscate_tab,
                  text="Obfuscate Code",
                  command=self.obfuscate_code).pack(pady=10)
        
        # Output
        self.obfuscate_output = scrolledtext.ScrolledText(
            self.obfuscate_tab,
            width=80,
            height=10,
            bg='#2e2e2e',
            fg='white'
        )
        self.obfuscate_output.pack(pady=10)
    
    # Добавяне на методи за обработка
    def generate_office_payload(self):
        """Generate Office payload document"""
        doc_type = self.office_type.get()
        payload = self.office_payload.get("1.0", tk.END).strip()
        
        if not payload:
            messagebox.showerror("Error", "Please enter payload code")
            return
        
        output_file = filedialog.asksaveasfilename(
            defaultextension=".docm" if "Word" in doc_type else ".xlsm" if "Excel" in doc_type else ".hta",
            filetypes=[
                ("Word Macro-Enabled", "*.docm"),
                ("Excel Macro-Enabled", "*.xlsm"),
                ("HTA Application", "*.hta")
            ]
        )
        
        if not output_file:
            return
        
        if "Word" in doc_type:
            # For demo purposes - in real implementation use template file
            result = OfficePayload.inject_macro_into_docx(
                "template.docx",  # Should be provided
                output_file,
                payload
            )
        elif "Excel" in doc_type:
            result = OfficePayload.generate_evil_excel_macro(
                output_file,
                payload
            )
        else:  # HTA
            result = OfficePayload.generate_hta_payload(
                payload,
                output_file
            )
        
        self.office_output.delete("1.0", tk.END)
        self.office_output.insert(tk.END, result)
    
    def obfuscate_code(self):
        """Obfuscate input code"""
        lang = self.obfuscate_lang.get()
        code = self.obfuscate_input.get("1.0", tk.END).strip()
        
        if not code:
            messagebox.showerror("Error", "Please enter code to obfuscate")
            return
        
        obfuscators = CodeObfuscator.get_obfuscators()
        if lang not in obfuscators:
            messagebox.showerror("Error", f"No obfuscator for {lang}")
            return
        
        try:
            obfuscated = obfuscators[lang](code)
            self.obfuscate_output.delete("1.0", tk.END)
            self.obfuscate_output.insert(tk.END, obfuscated)
        except Exception as e:
            messagebox.showerror("Error", f"Obfuscation failed: {str(e)}")
        # ... (additional methods for functionality would go here)
        def execute_shell_command(self):
            """Execute shell command and display output"""
            cmd = self.shell_cmd.get()
            if not cmd:
                messagebox.showerror("Error", "Please enter a command")
                return
    
            self.status.set("Executing command...")
            self.shell_output.insert(tk.END, f"$ {cmd}\n")
    
    def run_command():
        result = ShellTools.run_command(cmd)
        self.shell_output.insert(tk.END, result + "\n")
        self.status.set("Ready")
    
    threading.Thread(target=run_command, daemon=True).start()

    def generate_reverse_shell(self):
        """Generate reverse shell payload"""
        ip = self.reverse_ip.get()
        port = self.reverse_port.get()
        shell_type = self.shell_type.get()
        
        if not ip or not port:
            messagebox.showerror("Error", "Please enter IP and port")
            return
        
        shells = ReverseShellGenerator.get_reverse_shells(ip, port)
        payload = shells.get(shell_type, "Invalid shell type selected")
        
        self.reverse_output.delete(1.0, tk.END)
        self.reverse_output.insert(tk.END, payload)

    def copy_reverse_shell(self):
        """Copy reverse shell to clipboard"""
        payload = self.reverse_output.get(1.0, tk.END).strip()
        if payload:
            self.root.clipboard_clear()
            self.root.clipboard_append(payload)
            self.status.set("Payload copied to clipboard")
        else:
            messagebox.showerror("Error", "No payload to copy")

    def generate_exploit_payloads(self):
        """Generate exploit payloads based on selected type"""
        exploit_type = self.exploit_type.get()
        target_url = self.target_url.get()
        
        if not target_url:
            messagebox.showerror("Error", "Please enter target URL")
            return
        
        self.exploit_output.delete(1.0, tk.END)
        
        if exploit_type == "LFI":
            payloads = ExploitTemplates.get_lfi_templates(target_url)
        elif exploit_type == "RFI":
            payloads = ExploitTemplates.get_rfi_templates(target_url)
        elif exploit_type == "Command Injection":
            payloads = ExploitTemplates.get_cmd_injection_templates(target_url)
        elif exploit_type == "XXE":
            payloads = ExploitTemplates.get_xxe_payloads()
        elif exploit_type == "SQL Injection":
            payloads = ExploitTemplates.get_sqli_payloads()
        elif exploit_type == "XSS":
            payloads = ExploitTemplates.get_xss_payloads()
        elif exploit_type == "SSRF":
            payloads = ExploitTemplates.get_ssrf_payloads()
        elif exploit_type == "File Upload Bypass":
            payloads = ExploitTemplates.get_file_upload_bypass()
        
        if isinstance(payloads, dict):
            for category, items in payloads.items():
                self.exploit_output.insert(tk.END, f"\n=== {category} ===\n")
                for item in items:
                    self.exploit_output.insert(tk.END, f"{item}\n")
        else:
            for payload in payloads:
                self.exploit_output.insert(tk.END, f"{payload}\n")

    def browse_file(self, entry_widget):
        """Open file dialog and update entry widget"""
        filename = filedialog.askopenfilename()
        if filename:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filename)

    def start_bruteforce(self):
        """Start brute force attack"""
        service = self.brute_service.get()
        target = self.brute_target.get()
        port = self.brute_port.get()
        user_file = self.user_list_file.get()
        pass_file = self.pass_list_file.get()
        
        # Validate inputs
        if not all([service, target, port, user_file, pass_file]):
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        try:
            port = int(port)
        except ValueError:
            messagebox.showerror("Error", "Port must be a number")
            return
        
        # Read wordlists
        try:
            with open(user_file, 'r') as f:
                users = [line.strip() for line in f if line.strip()]
            with open(pass_file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read wordlists: {str(e)}")
            return
        
        if not users or not passwords:
            messagebox.showerror("Error", "Wordlists cannot be empty")
            return
        
        self.status.set(f"Starting {service} brute force...")
        self.brute_output.delete(1.0, tk.END)
        self.brute_output.insert(tk.END, f"Starting {service} brute force on {target}:{port}\n")
        
        def run_bruteforce():
            try:
                if service == "SSH":
                    result = BruteForce.ssh_bruteforce(
                        target, port, users, passwords
                    )
                elif service == "FTP":
                    result = BruteForce.ftp_bruteforce(
                        target, users, passwords
                    )
                elif service == "HTTP Basic Auth":
                    result = BruteForce.http_basic_bruteforce(
                        f"http://{target}:{port}", users, passwords
                    )
                
                if isinstance(result, str):
                    self.brute_output.insert(tk.END, result + "\n")
                else:
                    for username, password in result:
                        self.brute_output.insert(tk.END, f"[+] Found credentials: {username}:{password}\n")
                
                self.brute_output.insert(tk.END, "\nBrute force completed\n")
                self.status.set("Ready")
            except Exception as e:
                self.brute_output.insert(tk.END, f"[!] Error: {str(e)}\n")
                self.status.set("Error occurred")

        threading.Thread(target=run_bruteforce, daemon=True).start()


if __name__ == "__main__":
    root = tk.Tk()
    app = HTBToolkitApp(root)
    root.mainloop()
