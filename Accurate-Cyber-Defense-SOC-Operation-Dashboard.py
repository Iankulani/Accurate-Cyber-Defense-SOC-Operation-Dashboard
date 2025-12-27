"""
ACCURATE CYBER DRILL TOOL - Enhanced Version
Author: Ian Carter Kulani
Version: 2.0.0
Integrated Features from Cyber Security War Tool
"""

import sys
import os
import time
import json
import logging
import hashlib
import base64
import zipfile
import tempfile
from typing import Dict, List, Set, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime
import threading
import queue

# Core imports
import socket
import subprocess
import requests
import random
import platform
import psutil
import getpass
import sqlite3
import ipaddress
import re
import shutil
import configparser
import argparse
from collections import deque, defaultdict

import select

# GUI imports
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog, scrolledtext
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False
    print("GUI features unavailable - tkinter not installed")

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

# Security imports
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

try:
    import scapy.all as scapy
    from scapy.all import IP, ICMP, TCP, UDP, ARP, Ether, send
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import dpkt
    DPKT_AVAILABLE = True
except ImportError:
    DPKT_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    NETIFACES_AVAILABLE = False

# Configuration
CONFIG_FILE = "cyber_security_config.ini"
DEFAULT_CONFIG_FILE = "config.ini"
DATABASE_FILE = "threats.db"
REPORT_DIR = "reports"
HISTORY_FILE = "command_history.txt"
MAX_HISTORY = 1000
TELEGRAM_API_URL = "https://api.telegram.org/bot"

# Colors for terminal
class Colors:
    """ANSI color codes for terminal output"""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

THEMES = {
    "dark": {
        "bg": "#121212",
        "fg": "#00ff00",
        "text_bg": "#222222",
        "text_fg": "#ffffff",
        "button_bg": "#333333",
        "button_fg": "#00ff00",
        "highlight": "#006600"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "text_bg": "#ffffff",
        "text_fg": "#000000",
        "button_bg": "#e0e0e0",
        "button_fg": "#000000",
        "highlight": "#a0a0a0"
    }
}

# Enhanced Traceroute Tool
class EnhancedTracerouteTool:
    """Enhanced interactive traceroute tool with advanced features"""
    
    @staticmethod
    def is_ipv4_or_ipv6(address: str) -> bool:
        """Check if input is valid IPv4 or IPv6 address"""
        try:
            ipaddress.ip_address(address)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(name: str) -> bool:
        """Check if input is valid hostname"""
        if name.endswith('.'):
            name = name[:-1]
        HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)*[A-Za-z0-9-]{1,63}$")
        return bool(HOSTNAME_RE.match(name))

    @staticmethod
    def choose_traceroute_cmd(target: str) -> List[str]:
        """Return appropriate traceroute command for the system"""
        system = platform.system()

        if system == 'Windows':
            return ['tracert', '-d', target]

        # On Unix-like systems
        if shutil.which('traceroute'):
            return ['traceroute', '-n', '-q', '1', '-w', '2', target]
        if shutil.which('tracepath'):
            return ['tracepath', target]
        if shutil.which('ping'):
            return ['ping', '-c', '4', target]

        raise EnvironmentError('No traceroute utilities found')

    @staticmethod
    def stream_subprocess(cmd: List[str]) -> Tuple[int, str]:
        """Run subprocess and capture output"""
        output_lines = []
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

            if proc.stdout:
                for line in proc.stdout:
                    cleaned_line = line.rstrip()
                    output_lines.append(cleaned_line)
                    print(cleaned_line)

            proc.wait()
            return proc.returncode, '\n'.join(output_lines)
        except KeyboardInterrupt:
            print('\n[+] User cancelled traceroute...')
            try:
                proc.terminate()
            except Exception:
                pass
            return -1, '\n'.join(output_lines)
        except Exception as e:
            error_msg = f'[!] Error: {e}'
            print(error_msg)
            output_lines.append(error_msg)
            return -2, '\n'.join(output_lines)

    def interactive_traceroute(self, target: str = None) -> str:
        """Run interactive traceroute with validation"""
        if not target:
            target = self.prompt_target()
            if not target:
                return "Traceroute cancelled."

        if not (self.is_ipv4_or_ipv6(target) or self.is_valid_hostname(target)):
            return f"❌ Invalid IP address or hostname: {target}"

        try:
            cmd = self.choose_traceroute_cmd(target)
        except EnvironmentError as e:
            return f"❌ Traceroute error: {e}"

        print(f'Running: {" ".join(cmd)}\n')
        
        start_time = time.time()
        returncode, output = self.stream_subprocess(cmd)
        execution_time = time.time() - start_time

        result = f"🛣️ <b>Traceroute to {target}</b>\n\n"
        result += f"Command: <code>{' '.join(cmd)}</code>\n"
        result += f"Execution time: {execution_time:.2f}s\n"
        result += f"Return code: {returncode}\n\n"
        
        if len(output) > 3000:
            result += f"<code>{output[-3000:]}</code>"
        else:
            result += f"<code>{output}</code>"

        return result

    def prompt_target(self) -> Optional[str]:
        """Prompt user for target"""
        while True:
            user_input = input('Enter target IP/hostname (or "quit"): ').strip()
            if not user_input:
                print('Please enter a value.')
                continue
            if user_input.lower() in ('q', 'quit', 'exit'):
                return None

            if self.is_ipv4_or_ipv6(user_input) or self.is_valid_hostname(user_input):
                return user_input
            else:
                print('Invalid IP/hostname. Examples: 8.8.8.8, example.com')

class EnhancedDatabaseManager:
    """Manage SQLite database for network data with enhanced features"""
    
    def __init__(self):
        self.db_file = DATABASE_FILE
        self.init_database()
    
    def init_database(self):
        """Initialize database tables with enhanced schema"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Enhanced monitoring table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitored_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                added_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                threat_level INTEGER DEFAULT 0,
                last_scan TIMESTAMP,
                status TEXT DEFAULT 'active',
                notes TEXT
            )
        ''')
        
        # Enhanced threat logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                description TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT 0,
                port INTEGER,
                protocol TEXT,
                action_taken TEXT
            )
        ''')
        
        # Command history with source tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS command_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                command TEXT NOT NULL,
                source TEXT DEFAULT 'local',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN DEFAULT 1,
                output TEXT
            )
        ''')
        
        # Enhanced scan results
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                open_ports TEXT,
                services TEXT,
                os_info TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                scan_duration REAL,
                vulnerability_count INTEGER DEFAULT 0
            )
        ''')
        
        # Intrusion detection with advanced analytics
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS intrusion_detection (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                target_ip TEXT,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                packet_count INTEGER,
                description TEXT,
                action_taken TEXT,
                port INTEGER,
                protocol TEXT,
                attack_vector TEXT,
                mitigation_suggestions TEXT
            )
        ''')
        
        # Network statistics with time-series data
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS network_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                packets_processed INTEGER,
                packet_rate REAL,
                tcp_count INTEGER,
                udp_count INTEGER,
                icmp_count INTEGER,
                threat_count INTEGER,
                bandwidth_usage REAL,
                connection_count INTEGER,
                unique_ips INTEGER
            )
        ''')
        
        # Session management
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS session_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_name TEXT NOT NULL,
                data_type TEXT NOT NULL,
                data TEXT,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                modified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Telegram logs for communication tracking
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS telegram_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                chat_id TEXT,
                message TEXT,
                direction TEXT,
                command TEXT,
                success BOOLEAN DEFAULT 1
            )
        ''')
        
        # IP reputation database
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                reputation_score INTEGER DEFAULT 0,
                threat_count INTEGER DEFAULT 0,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                country TEXT,
                asn TEXT,
                tags TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_command(self, command: str, source: str = 'local', success: bool = True, output: str = ""):
        """Log command to database"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO command_history (command, source, success, output) VALUES (?, ?, ?, ?)',
            (command, source, success, output[:1000])
        )
        conn.commit()
        conn.close()
    
    def log_telegram_message(self, chat_id: str, message: str, direction: str, command: str = "", success: bool = True):
        """Log Telegram messages"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO telegram_logs (chat_id, message, direction, command, success) VALUES (?, ?, ?, ?, ?)',
            (chat_id, message, direction, command, success)
        )
        conn.commit()
        conn.close()
    
    def log_intrusion(self, source_ip: str, threat_type: str, severity: str, 
                     packet_count: int = 0, description: str = "", 
                     action: str = "logged", target_ip: str = None,
                     port: int = None, protocol: str = None,
                     attack_vector: str = None, mitigation: str = None):
        """Log intrusion detection event with enhanced details"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''INSERT INTO intrusion_detection 
               (source_ip, target_ip, threat_type, severity, packet_count, 
                description, action_taken, port, protocol, attack_vector, mitigation_suggestions) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (source_ip, target_ip, threat_type, severity, packet_count, 
             description, action, port, protocol, attack_vector, mitigation)
        )
        conn.commit()
        conn.close()
    
    def update_ip_reputation(self, ip_address: str, score_delta: int = 0, 
                            threat_type: str = "", country: str = None, asn: str = None):
        """Update IP reputation score"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        # Check if IP exists
        cursor.execute('SELECT reputation_score, threat_count FROM ip_reputation WHERE ip_address = ?', (ip_address,))
        result = cursor.fetchone()
        
        if result:
            current_score, threat_count = result
            new_score = max(-100, min(100, current_score + score_delta))
            new_threat_count = threat_count + (1 if score_delta < 0 else 0)
            
            cursor.execute('''
                UPDATE ip_reputation 
                SET reputation_score = ?, threat_count = ?, last_seen = CURRENT_TIMESTAMP
                WHERE ip_address = ?
            ''', (new_score, new_threat_count, ip_address))
        else:
            # Add new IP
            tags = ["suspicious"] if score_delta < 0 else ["new"]
            cursor.execute('''
                INSERT INTO ip_reputation 
                (ip_address, reputation_score, threat_count, country, asn, tags) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (ip_address, score_delta, 1 if score_delta < 0 else 0, country, asn, ",".join(tags)))
        
        conn.commit()
        conn.close()
    
    def get_recent_intrusions(self, limit: int = 50) -> List[Tuple]:
        """Get recent intrusion detection events"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        cursor.execute(
            '''SELECT timestamp, source_ip, threat_type, severity, description, action_taken
               FROM intrusion_detection 
               ORDER BY timestamp DESC LIMIT ?''',
            (limit,)
        )
        results = cursor.fetchall()
        conn.close()
        return results
    
    def get_threat_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive threat statistics"""
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()
        
        stats = {}
        
        # Threat types count
        cursor.execute('''
            SELECT threat_type, COUNT(*) as count, AVG(CASE severity 
                WHEN 'high' THEN 3 
                WHEN 'medium' THEN 2 
                WHEN 'low' THEN 1 
                ELSE 0 END) as avg_severity
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            GROUP BY threat_type
        ''', (f'-{hours} hours',))
        
        stats['threat_types'] = {}
        for threat_type, count, avg_severity in cursor.fetchall():
            stats['threat_types'][threat_type] = {
                'count': count,
                'avg_severity': avg_severity
            }
        
        # Top source IPs
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count 
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            GROUP BY source_ip 
            ORDER BY count DESC LIMIT 10
        ''', (f'-{hours} hours',))
        
        stats['top_source_ips'] = cursor.fetchall()
        
        # Hourly threat distribution
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM intrusion_detection 
            WHERE timestamp > datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
        ''', (f'-{hours} hours',))
        
        stats['hourly_distribution'] = cursor.fetchall()
        
        conn.close()
        return stats

class AdvancedThreatDetector:
    """Advanced threat detection with machine learning features"""
    
    def __init__(self, db_manager: EnhancedDatabaseManager):
        self.db_manager = db_manager
        self.ip_stats = {}
        self.port_stats = {}
        self.syn_flood_stats = {}
        self.connection_patterns = {}
        
        # Advanced detection thresholds
        self.detection_thresholds = {
            'DOS': 1000,  # packets per second
            'PortScan': 50,  # unique ports in 60 seconds
            'SYNFlood': 500,  # SYN packets without ACK
            'UDPFlood': 1000,  # UDP packets per second
            'ICMPFlood': 500,  # ICMP packets per second
            'BruteForce': 100,  # failed connection attempts
            'Slowloris': 10,  # slow HTTP connections
            'XMAS': 50,  # XMAS scan packets
            'NULL': 50,  # NULL scan packets
            'FIN': 50,  # FIN scan packets
        }
        
        # Known malicious IP patterns
        self.malicious_patterns = {
            'botnet': ['spamhaus', 'cins'],
            'tor_exit': ['torproject'],
            'vpn': ['anonymous', 'proxy'],
            'scanning': ['masscan', 'zmap']
        }
        
        # Learning parameters
        self.learning_rate = 0.1
        self.normal_baseline = {}
        
    def analyze_packet(self, packet):
        """Advanced packet analysis with pattern recognition"""
        threats = []
        
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            # Initialize stats for IP
            if ip_src not in self.ip_stats:
                self.ip_stats[ip_src] = {
                    'packet_count': 0,
                    'last_seen': time.time(),
                    'ports_accessed': set(),
                    'packet_times': [],
                    'syn_count': 0,
                    'rst_count': 0,
                    'fin_count': 0,
                    'connection_attempts': 0,
                    'failed_connections': 0,
                    'bytes_sent': 0,
                    'bytes_received': 0
                }
            
            ip_stat = self.ip_stats[ip_src]
            ip_stat['packet_count'] += 1
            ip_stat['last_seen'] = time.time()
            ip_stat['packet_times'].append(time.time())
            
            # Update byte counts
            if hasattr(packet, 'len'):
                ip_stat['bytes_sent'] += packet.len
            
            # Keep only last minute of packet times
            cutoff = time.time() - 60
            ip_stat['packet_times'] = [t for t in ip_stat['packet_times'] if t > cutoff]
            
            # Protocol-specific analysis
            if TCP in packet:
                threats.extend(self._analyze_tcp(packet, ip_src, ip_dst))
            elif UDP in packet:
                threats.extend(self._analyze_udp(packet, ip_src))
            elif ICMP in packet:
                threats.extend(self._analyze_icmp(packet, ip_src))
            elif ARP in packet:
                threats.extend(self._analyze_arp(packet, ip_src))
            
            # Advanced threat detection
            threats.extend(self._detect_dos_advanced(ip_src))
            threats.extend(self._detect_port_scan_advanced(ip_src))
            threats.extend(self._detect_behavioral_anomalies(ip_src))
            
            # Check for known attack patterns
            threats.extend(self._check_known_patterns(packet, ip_src))
        
        return threats
    
    def _analyze_tcp(self, packet, ip_src, ip_dst):
        """Advanced TCP analysis"""
        threats = []
        tcp = packet[TCP]
        
        # Track ports accessed
        self.ip_stats[ip_src]['ports_accessed'].add(tcp.dport)
        
        # Track connection patterns
        connection_key = f"{ip_src}:{tcp.sport}-{ip_dst}:{tcp.dport}"
        if connection_key not in self.connection_patterns:
            self.connection_patterns[connection_key] = {
                'start_time': time.time(),
                'packet_count': 0,
                'flags_seen': set(),
                'state': 'new'
            }
        
        conn_pattern = self.connection_patterns[connection_key]
        conn_pattern['packet_count'] += 1
        conn_pattern['flags_seen'].add(tcp.flags)
        
        # SYN flood detection
        if tcp.flags & 0x02:  # SYN flag
            self.ip_stats[ip_src]['syn_count'] += 1
            self.ip_stats[ip_src]['connection_attempts'] += 1
            
            if ip_src not in self.syn_flood_stats:
                self.syn_flood_stats[ip_src] = {'syn_count': 0, 'start_time': time.time()}
            
            self.syn_flood_stats[ip_src]['syn_count'] += 1
            
            # Check for SYN flood
            syn_stats = self.syn_flood_stats[ip_src]
            elapsed = time.time() - syn_stats['start_time']
            if elapsed > 0:
                syn_rate = syn_stats['syn_count'] / elapsed
                if syn_rate > self.detection_thresholds['SYNFlood']:
                    threats.append({
                        'type': 'SYNFlood',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': syn_rate,
                        'port': tcp.dport
                    })
        
        # Check for unusual TCP flags
        if tcp.flags & 0x01:  # FIN flag
            self.ip_stats[ip_src]['fin_count'] += 1
        
        if tcp.flags & 0x04:  # RST flag
            self.ip_stats[ip_src]['rst_count'] += 1
            self.ip_stats[ip_src]['failed_connections'] += 1
        
        # Detect scan types
        if self._detect_tcp_scan(packet, ip_src):
            scan_type = self._identify_scan_type(tcp.flags)
            if scan_type:
                threats.append({
                    'type': f'TCP_{scan_type}_Scan',
                    'source': ip_src,
                    'severity': 'medium',
                    'port': tcp.dport
                })
        
        # Detect slowloris attack
        if self._detect_slowloris(connection_key, conn_pattern):
            threats.append({
                'type': 'Slowloris',
                'source': ip_src,
                'severity': 'high',
                'connection': connection_key
            })
        
        return threats
    
    def _detect_tcp_scan(self, packet, ip_src):
        """Detect TCP scanning activity"""
        tcp = packet[TCP]
        
        # Common scan patterns
        if tcp.flags == 0x00:  # NULL scan
            return True
        elif tcp.flags == 0x01:  # FIN scan
            return True
        elif tcp.flags == 0x02:  # SYN scan
            return True
        elif tcp.flags == 0x29:  # XMAS scan (FIN+URG+PSH)
            return True
        
        return False
    
    def _identify_scan_type(self, flags):
        """Identify the type of TCP scan"""
        if flags == 0x00:
            return "NULL"
        elif flags == 0x01:
            return "FIN"
        elif flags == 0x02:
            return "SYN"
        elif flags == 0x29:
            return "XMAS"
        return None
    
    def _detect_slowloris(self, connection_key, conn_pattern):
        """Detect Slowloris attack patterns"""
        # Slowloris typically sends partial HTTP requests
        if conn_pattern['packet_count'] > 10 and time.time() - conn_pattern['start_time'] > 30:
            # Many packets over a long time without completing connection
            if 'established' not in conn_pattern['state']:
                return True
        return False
    
    def _analyze_udp(self, packet, ip_src):
        """Advanced UDP analysis"""
        threats = []
        
        # Track UDP packet rate
        udp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                       if time.time() - t < 1])
        
        if udp_rate > self.detection_thresholds['UDPFlood']:
            threats.append({
                'type': 'UDPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': udp_rate
            })
        
        # Detect DNS amplification
        if UDP in packet and packet[UDP].dport == 53:
            if packet[IP].len > 100:  # Large DNS response
                threats.append({
                    'type': 'DNS_Amplification',
                    'source': ip_src,
                    'severity': 'high',
                    'size': packet[IP].len
                })
        
        return threats
    
    def _analyze_icmp(self, packet, ip_src):
        """Advanced ICMP analysis"""
        threats = []
        
        # Track ICMP packet rate
        icmp_rate = len([t for t in self.ip_stats[ip_src]['packet_times'] 
                        if time.time() - t < 1])
        
        if icmp_rate > self.detection_thresholds['ICMPFlood']:
            threats.append({
                'type': 'ICMPFlood',
                'source': ip_src,
                'severity': 'medium',
                'rate': icmp_rate
            })
        
        # Detect ICMP redirect attacks
        if ICMP in packet and packet[ICMP].type == 5:  # Redirect
            threats.append({
                'type': 'ICMP_Redirect',
                'source': ip_src,
                'severity': 'high'
            })
        
        return threats
    
    def _analyze_arp(self, packet, ip_src):
        """ARP analysis for spoofing detection"""
        threats = []
        
        if ARP in packet:
            arp = packet[ARP]
            
            # Detect ARP poisoning
            if arp.op == 1:  # ARP request
                if arp.psrc != ip_src:
                    threats.append({
                        'type': 'ARP_Spoofing',
                        'source': ip_src,
                        'severity': 'high',
                        'spoofed_ip': arp.psrc
                    })
            
            # Detect gratuitous ARP
            if arp.op == 2 and arp.pdst == arp.psrc:  # Gratuitous ARP reply
                threats.append({
                    'type': 'Gratuitous_ARP',
                    'source': ip_src,
                    'severity': 'medium'
                })
        
        return threats
    
    def _detect_dos_advanced(self, ip_src):
        """Advanced DOS detection with rate limiting"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        if len(ip_stat['packet_times']) > 0:
            time_window = ip_stat['packet_times'][-1] - ip_stat['packet_times'][0]
            if time_window > 0:
                packet_rate = len(ip_stat['packet_times']) / time_window
                
                # Check against threshold
                if packet_rate > self.detection_thresholds['DOS']:
                    threats.append({
                        'type': 'DOS',
                        'source': ip_src,
                        'severity': 'high',
                        'rate': packet_rate
                    })
                
                # Check for traffic bursts
                recent_packets = [t for t in ip_stat['packet_times'] if time.time() - t < 10]
                if len(recent_packets) > 5000:  # 5000 packets in 10 seconds
                    threats.append({
                        'type': 'Traffic_Burst',
                        'source': ip_src,
                        'severity': 'medium',
                        'burst_count': len(recent_packets)
                    })
        
        return threats
    
    def _detect_port_scan_advanced(self, ip_src):
        """Advanced port scanning detection"""
        threats = []
        
        ip_stat = self.ip_stats[ip_src]
        unique_ports = len(ip_stat['ports_accessed'])
        
        # Check total unique ports
        if unique_ports > self.detection_thresholds['PortScan']:
            threats.append({
                'type': 'PortScan',
                'source': ip_src,
                'severity': 'medium',
                'ports': unique_ports
            })
        
        # Check for sequential port scanning
        if unique_ports > 10:
            ports = sorted(list(ip_stat['ports_accessed']))
            sequential_count = 0
            for i in range(1, len(ports)):
                if ports[i] == ports[i-1] + 1:
                    sequential_count += 1
                else:
                    sequential_count = 0
                
                if sequential_count > 5:  # 5+ sequential ports
                    threats.append({
                        'type': 'Sequential_PortScan',
                        'source': ip_src,
                        'severity': 'medium',
                        'sequential_ports': sequential_count
                    })
                    break
        
        return threats
    
    def _detect_behavioral_anomalies(self, ip_src):
        """Detect behavioral anomalies using statistical analysis"""
        threats = []
        ip_stat = self.ip_stats[ip_src]
        
        # Check connection success rate
        if ip_stat['connection_attempts'] > 0:
            failure_rate = ip_stat['failed_connections'] / ip_stat['connection_attempts']
            if failure_rate > 0.8:  # 80% failure rate
                threats.append({
                    'type': 'BruteForce_Attempt',
                    'source': ip_src,
                    'severity': 'medium',
                    'failure_rate': failure_rate
                })
        
        # Check for unusual SYN/RST ratio
        if ip_stat['syn_count'] > 10:
            rst_ratio = ip_stat['rst_count'] / ip_stat['syn_count']
            if rst_ratio > 0.7:  # High RST to SYN ratio
                threats.append({
                    'type': 'Connection_Reset_Anomaly',
                    'source': ip_src,
                    'severity': 'low',
                    'rst_ratio': rst_ratio
                })
        
        return threats
    
    def _check_known_patterns(self, packet, ip_src):
        """Check for known malicious patterns"""
        threats = []
        
        # Check packet against known attack signatures
        if TCP in packet:
            tcp = packet[TCP]
            
            # Check for SQL injection patterns in payload (if available)
            if hasattr(tcp, 'payload'):
                payload = str(tcp.payload).lower()
                sql_patterns = ['union select', 'drop table', '1=1', "' or '1'='1"]
                
                for pattern in sql_patterns:
                    if pattern in payload:
                        threats.append({
                            'type': 'SQL_Injection_Attempt',
                            'source': ip_src,
                            'severity': 'high',
                            'pattern': pattern
                        })
                        break
        
        return threats
    
    def clear_old_stats(self, max_age: int = 300):
        """Clear statistics older than max_age seconds"""
        cutoff = time.time() - max_age
        ips_to_remove = []
        
        for ip, stats in self.ip_stats.items():
            if stats['last_seen'] < cutoff:
                ips_to_remove.append(ip)
        
        for ip in ips_to_remove:
            del self.ip_stats[ip]
            
        # Clean SYN flood stats
        syn_ips_to_remove = []
        for ip, stats in self.syn_flood_stats.items():
            if stats['start_time'] < cutoff:
                syn_ips_to_remove.append(ip)
        
        for ip in syn_ips_to_remove:
            del self.syn_flood_stats[ip]
        
        # Clean old connection patterns
        conn_keys_to_remove = []
        for key, pattern in self.connection_patterns.items():
            if pattern['start_time'] < cutoff:
                conn_keys_to_remove.append(key)
        
        for key in conn_keys_to_remove:
            del self.connection_patterns[key]

class EnhancedNetworkMonitor:
    """Enhanced network monitoring with advanced threat detection"""
    
    def __init__(self, db_manager: EnhancedDatabaseManager):
        self.db_manager = db_manager
        self.threat_detector = AdvancedThreatDetector(db_manager)
        self.is_monitoring = False
        self.sniffer_thread = None
        self.packet_queue = queue.Queue()
        self.target_ip = None
        self.packet_count = 0
        self.start_time = None
        self.telegram_bot = None
        
        self.stats = {
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'arp_count': 0,
            'threat_count': 0,
            'total_bytes': 0,
            'unique_ips': set()
        }
    
    def set_telegram_bot(self, telegram_bot):
        """Set Telegram bot for notifications"""
        self.telegram_bot = telegram_bot
    
    def start_monitoring(self, target_ip: str = None):
        """Start enhanced network monitoring"""
        if self.is_monitoring:
            return False
        
        self.target_ip = target_ip
        self.is_monitoring = True
        self.packet_count = 0
        self.start_time = time.time()
        
        # Reset stats
        self.stats = {
            'tcp_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'arp_count': 0,
            'threat_count': 0,
            'total_bytes': 0,
            'unique_ips': set()
        }
        
        # Start packet capture thread
        self.sniffer_thread = threading.Thread(
            target=self._advanced_packet_capture,
            daemon=True
        )
        self.sniffer_thread.start()
        
        # Start packet processing thread
        self.processor_thread = threading.Thread(
            target=self._advanced_packet_processing,
            daemon=True
        )
        self.processor_thread.start()
        
        # Start stats logging thread
        self.stats_thread = threading.Thread(
            target=self._enhanced_stats_logging,
            daemon=True
        )
        self.stats_thread.start()
        
        # Start alert monitoring thread
        self.alert_thread = threading.Thread(
            target=self._alert_monitoring,
            daemon=True
        )
        self.alert_thread.start()
        
        return True
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.is_monitoring = False
        
        threads = [self.sniffer_thread, self.processor_thread, self.stats_thread, self.alert_thread]
        for thread in threads:
            if thread and thread.is_alive():
                thread.join(timeout=2)
    
    def _advanced_packet_capture(self):
        """Advanced packet capture with filtering options"""
        try:
            filter_str = ""
            if self.target_ip:
                filter_str = f"host {self.target_ip}"
            
            # Use Scapy's advanced sniffing with callback
            scapy.sniff(
                filter=filter_str,
                prn=lambda p: self.packet_queue.put(p),
                store=0,
                stop_filter=lambda _: not self.is_monitoring,
                timeout=0  # Non-blocking
            )
        except Exception as e:
            print(f"Packet capture error: {e}")
    
    def _advanced_packet_processing(self):
        """Process captured packets with enhanced analysis"""
        while self.is_monitoring or not self.packet_queue.empty():
            try:
                packet = self.packet_queue.get(timeout=1)
                self.packet_count += 1
                
                # Update protocol stats
                if TCP in packet:
                    self.stats['tcp_count'] += 1
                elif UDP in packet:
                    self.stats['udp_count'] += 1
                elif ICMP in packet:
                    self.stats['icmp_count'] += 1
                elif ARP in packet:
                    self.stats['arp_count'] += 1
                
                # Update byte count
                if hasattr(packet, 'len'):
                    self.stats['total_bytes'] += packet.len
                
                # Update unique IPs
                if IP in packet:
                    self.stats['unique_ips'].add(packet[IP].src)
                    self.stats['unique_ips'].add(packet[IP].dst)
                
                # Detect threats
                threats = self.threat_detector.analyze_packet(packet)
                if threats:
                    self.stats['threat_count'] += len(threats)
                    for threat in threats:
                        self._handle_threat(threat)
                
                # Clean old stats periodically
                if self.packet_count % 1000 == 0:
                    self.threat_detector.clear_old_stats()
                    
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Packet processing error: {e}")
    
    def _handle_threat(self, threat):
        """Handle detected threats with appropriate actions"""
        # Log threat to database
        self.db_manager.log_intrusion(
            source_ip=threat['source'],
            threat_type=threat['type'],
            severity=threat['severity'],
            description=threat.get('description', f"Detected {threat['type']}"),
            packet_count=threat.get('count', 1),
            action=threat.get('action', 'logged'),
            port=threat.get('port'),
            protocol=threat.get('protocol'),
            attack_vector=threat.get('attack_vector'),
            mitigation=threat.get('mitigation')
        )
        
        # Update IP reputation
        score_delta = -10 if threat['severity'] == 'high' else -5 if threat['severity'] == 'medium' else -2
        self.db_manager.update_ip_reputation(threat['source'], score_delta, threat['type'])
        
        # Send alert if configured
        if self.telegram_bot and threat['severity'] in ['high', 'medium']:
            alert_msg = f"🚨 THREAT DETECTED\n"
            alert_msg += f"Type: {threat['type']}\n"
            alert_msg += f"Source: {threat['source']}\n"
            alert_msg += f"Severity: {threat['severity']}\n"
            alert_msg += f"Time: {datetime.now().strftime('%H:%M:%S')}"
            
            self.telegram_bot.send_alert(alert_msg)
    
    def _enhanced_stats_logging(self):
        """Periodically log enhanced network statistics"""
        while self.is_monitoring:
            time.sleep(60)  # Log every minute
            
            uptime = time.time() - self.start_time
            if uptime > 0:
                stats = {
                    'packets_processed': self.packet_count,
                    'packet_rate': self.packet_count / uptime,
                    'tcp_count': self.stats['tcp_count'],
                    'udp_count': self.stats['udp_count'],
                    'icmp_count': self.stats['icmp_count'],
                    'threat_count': self.stats['threat_count'],
                    'bandwidth_usage': self.stats['total_bytes'] / uptime,
                    'connection_count': len(self.threat_detector.connection_patterns),
                    'unique_ips': len(self.stats['unique_ips'])
                }
                self.db_manager.log_network_stats(stats)
    
    def _alert_monitoring(self):
        """Monitor for alert conditions"""
        while self.is_monitoring:
            time.sleep(30)  # Check every 30 seconds
            
            # Check for high threat rate
            if self.stats['threat_count'] > 0:
                threat_rate = self.stats['threat_count'] / ((time.time() - self.start_time) / 60)
                if threat_rate > 10:  # More than 10 threats per minute
                    if self.telegram_bot:
                        self.telegram_bot.send_alert(
                            f"⚠️ High threat rate detected: {threat_rate:.1f} threats/minute"
                        )
    
    def get_current_stats(self) -> Dict[str, Any]:
        """Get current monitoring statistics"""
        uptime = time.time() - self.start_time if self.start_time else 0
        packet_rate = self.packet_count / uptime if uptime > 0 else 0
        
        return {
            'is_monitoring': self.is_monitoring,
            'target_ip': self.target_ip,
            'packets_processed': self.packet_count,
            'uptime': uptime,
            'packet_rate': packet_rate,
            'tcp_packets': self.stats['tcp_count'],
            'udp_packets': self.stats['udp_count'],
            'icmp_packets': self.stats['icmp_count'],
            'arp_packets': self.stats['arp_count'],
            'threats_detected': self.stats['threat_count'],
            'total_bytes': self.stats['total_bytes'],
            'unique_ips': len(self.stats['unique_ips']),
            'active_connections': len(self.threat_detector.connection_patterns)
        }

class AdvancedNetworkScanner:
    """Advanced network scanning with comprehensive analysis"""
    
    def __init__(self, db_manager: EnhancedDatabaseManager):
        self.db_manager = db_manager
        self.traceroute_tool = EnhancedTracerouteTool()
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
    
    def ping_ip(self, ip: str) -> Tuple[bool, str]:
        """Enhanced ping with comprehensive analysis"""
        try:
            # Validate IP address
            try:
                socket.inet_aton(ip)
            except socket.error:
                return False, f"Invalid IP address: {ip}"

            # System-specific ping command
            param = "-n" if platform.system().lower() == "windows" else "-c"
            command = ["ping", param, "4", ip]
            
            try:
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    output = result.stdout
                    
                    # Extract ping statistics
                    lines = output.split('\n')
                    stats = []
                    for line in lines:
                        if "time=" in line or "time<" in line:
                            stats.append(line.strip())
                    
                    # Additional network analysis
                    network_info = self.analyze_network_health(ip)
                    
                    return True, f"✓ {ip} is reachable\n" + "\n".join(stats) + "\n" + network_info
                else:
                    return False, f"✗ {ip} is not reachable"
                    
            except subprocess.TimeoutExpired:
                return False, f"✗ Ping timeout for {ip}"
                
        except Exception as e:
            return False, f"Ping error: {str(e)}"
    
    def analyze_network_health(self, ip: str) -> str:
        """Perform additional network health analysis"""
        analysis = []
        
        try:
            # DNS resolution test
            start_time = time.time()
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                dns_time = time.time() - start_time
                analysis.append(f"DNS Resolution: {hostname} ({dns_time:.3f}s)")
            except:
                analysis.append("DNS Resolution: Failed")
            
            # Port connectivity quick test
            common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995]
            open_ports = []
            
            for port in common_ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            
            if open_ports:
                analysis.append(f"Open common ports: {open_ports}")
            else:
                analysis.append("No common ports open")
            
            # TTL analysis
            try:
                ttl = self.get_ttl(ip)
                analysis.append(f"Estimated TTL: {ttl}")
            except:
                pass
                
        except Exception as e:
            analysis.append(f"Analysis error: {str(e)}")
        
        return "\n".join(analysis)
    
    def get_ttl(self, ip: str) -> str:
        """Estimate TTL to guess operating system"""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ping', '-n', '1', ip], capture_output=True, text=True, timeout=5)
            else:
                result = subprocess.run(['ping', '-c', '1', ip], capture_output=True, text=True, timeout=5)
            
            output = result.stdout
            ttl_match = re.search(r'TTL=(\d+)', output)
            if ttl_match:
                ttl = int(ttl_match.group(1))
                if ttl <= 64:
                    return f"{ttl} (likely Linux/Unix)"
                elif ttl <= 128:
                    return f"{ttl} (likely Windows)"
                else:
                    return f"{ttl} (likely network device)"
            return "Unknown"
        except:
            return "Unknown"
    
    def traceroute(self, target: str) -> str:
        """Perform enhanced traceroute"""
        return self.traceroute_tool.interactive_traceroute(target)
    
    def port_scan(self, ip: str, ports: str = "1-1000") -> Dict[str, Any]:
        """Perform enhanced port scan"""
        if self.nm:
            try:
                start_time = time.time()
                self.nm.scan(ip, ports, arguments='-T4 -sS')
                scan_time = time.time() - start_time
                
                open_ports = []
                services = []
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        lport = self.nm[ip][proto].keys()
                        for port in lport:
                            if self.nm[ip][proto][port]['state'] == 'open':
                                service_info = self.nm[ip][proto][port]
                                open_ports.append(port)
                                services.append({
                                    'port': port,
                                    'protocol': proto,
                                    'service': service_info.get('name', 'unknown'),
                                    'version': service_info.get('version', ''),
                                    'product': service_info.get('product', '')
                                })
                
                # Log to database
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    '''INSERT INTO scan_results 
                       (ip_address, scan_type, open_ports, services, scan_duration) 
                       VALUES (?, ?, ?, ?, ?)''',
                    (ip, 'nmap_quick', json.dumps(open_ports), 
                     json.dumps(services), scan_time)
                )
                conn.commit()
                conn.close()
                
                return {
                    'success': True,
                    'target': ip,
                    'open_ports': open_ports,
                    'services': services,
                    'scan_time': datetime.now().isoformat(),
                    'scan_duration': scan_time
                }
            except Exception as e:
                return {'success': False, 'error': str(e)}
        else:
            return {'success': False, 'error': 'Nmap not available'}
    
    def deep_scan_ip(self, ip: str) -> Dict[str, Any]:
        """Perform comprehensive deep port scan (1-65535)"""
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            start_time = time.time()
            self.nm.scan(ip, '1-65535', arguments='-sS -T4 -A')
            scan_time = time.time() - start_time
            
            if ip in self.nm.all_hosts():
                host = self.nm[ip]
                results = {
                    'ip': ip,
                    'scan_time': datetime.now().isoformat(),
                    'scan_duration': f"{scan_time:.2f}s",
                    'state': host.state(),
                    'open_ports': [],
                    'services': {}
                }
                
                for proto in host.all_protocols():
                    ports = host[proto].keys()
                    for port in ports:
                        service_info = host[proto][port]
                        results['open_ports'].append(port)
                        results['services'][port] = {
                            'name': service_info.get('name', 'unknown'),
                            'product': service_info.get('product', ''),
                            'version': service_info.get('version', ''),
                            'state': service_info.get('state', ''),
                            'extrainfo': service_info.get('extrainfo', '')
                        }
                
                # Log to database
                conn = sqlite3.connect(DATABASE_FILE)
                cursor = conn.cursor()
                cursor.execute(
                    '''INSERT INTO scan_results 
                       (ip_address, scan_type, open_ports, services, scan_duration) 
                       VALUES (?, ?, ?, ?, ?)''',
                    (ip, 'nmap_deep', json.dumps(results['open_ports']), 
                     json.dumps(results['services']), scan_time)
                )
                conn.commit()
                conn.close()
                
                return results
            else:
                return {'success': False, 'error': 'Host not found in scan results'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def get_ip_location(self, ip: str) -> Dict[str, Any]:
        """Get comprehensive IP location information"""
        try:
            services = [
                ("ipapi.co", f"http://ipapi.co/{ip}/json/"),
                ("ipinfo.io", f"https://ipinfo.io/{ip}/json"),
                ("ip-api.com", f"http://ip-api.com/json/{ip}")
            ]
            
            location_data = {}
            
            for service_name, url in services:
                try:
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        
                        if service_name == "ipapi.co" and 'error' not in data:
                            location_data = {
                                'ip': ip,
                                'country': data.get('country_name', 'Unknown'),
                                'region': data.get('region', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'isp': data.get('org', 'Unknown'),
                                'timezone': data.get('timezone', 'Unknown'),
                                'coordinates': f"{data.get('latitude', 'Unknown')}, {data.get('longitude', 'Unknown')}",
                                'asn': data.get('asn', 'Unknown'),
                                'service': service_name
                            }
                            break
                        elif service_name == "ipinfo.io":
                            location_data = {
                                'ip': ip,
                                'country': data.get('country', 'Unknown'),
                                'region': data.get('region', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'isp': data.get('org', 'Unknown'),
                                'timezone': data.get('timezone', 'Unknown'),
                                'coordinates': data.get('loc', 'Unknown'),
                                'asn': data.get('org', 'Unknown').split()[0] if 'org' in data else 'Unknown',
                                'service': service_name
                            }
                            break
                        elif service_name == "ip-api.com" and data.get('status') == 'success':
                            location_data = {
                                'ip': ip,
                                'country': data.get('country', 'Unknown'),
                                'region': data.get('regionName', 'Unknown'),
                                'city': data.get('city', 'Unknown'),
                                'isp': data.get('isp', 'Unknown'),
                                'timezone': data.get('timezone', 'Unknown'),
                                'coordinates': f"{data.get('lat', 'Unknown')}, {data.get('lon', 'Unknown')}",
                                'asn': data.get('as', 'Unknown'),
                                'service': service_name
                            }
                            break
                except:
                    continue
            
            if location_data:
                # Update IP reputation with location info
                self.db_manager.update_ip_reputation(
                    ip, 
                    0,  # neutral score
                    "", 
                    location_data.get('country'),
                    location_data.get('asn')
                )
                return location_data
            else:
                return {'error': 'Unable to retrieve location information'}
                
        except Exception as e:
            return {'error': str(e)}
    
    def vulnerability_scan(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive vulnerability scan"""
        if not self.nm:
            return {'success': False, 'error': 'Nmap not available'}
        
        try:
            start_time = time.time()
            self.nm.scan(target, arguments='--script vuln,safe')
            scan_time = time.time() - start_time
            
            vulns = []
            if target in self.nm.all_hosts():
                host = self.nm[target]
                
                # Extract script results
                for script in host.get('scripts', []):
                    if 'vuln' in script.lower() or 'exploit' in script.lower():
                        vulns.append(script)
                
                # Check for specific vulnerabilities
                for port_info in host.all_ports():
                    for script_name, script_output in host[port_info].get('scripts', {}).items():
                        if any(keyword in script_name.lower() for keyword in ['vuln', 'exploit', 'cve']):
                            vulns.append(f"{script_name}: {script_output}")
            
            return {
                'success': True,
                'target': target,
                'vulnerabilities': vulns,
                'scan_time': datetime.now().isoformat(),
                'scan_duration': scan_time,
                'vulnerability_count': len(vulns)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}

class AdvancedTrafficGenerator:
    """Advanced network traffic generation capabilities"""
    
    def __init__(self, db_manager: EnhancedDatabaseManager):
        self.db_manager = db_manager
        self.running = False
        self.current_thread = None
        self.generated_traffic = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'total_packets': 0,
            'total_bytes': 0
        }
    
    def generate_tcp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float, 
                            payload_size: int = 512, spoof_source: bool = False) -> str:
        """Generate advanced TCP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for TCP traffic generation"
        
        try:
            packets_sent = 0
            bytes_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                if spoof_source:
                    src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                else:
                    # Use actual source IP
                    src_ip = socket.gethostbyname(socket.gethostname())
                
                # Create payload
                payload = random._urandom(payload_size) if payload_size > 0 else b""
                
                # Create packet with random TCP flags for stealth
                flags = random.choice(['S', 'A', 'PA', 'FA'])
                packet = IP(src=src_ip, dst=target_ip)/TCP(
                    sport=random.randint(1024, 65535), 
                    dport=port,
                    flags=flags
                )/payload
                
                send(packet, verbose=0)
                packets_sent += 1
                bytes_sent += len(packet)
                self.generated_traffic['tcp'] += 1
                self.generated_traffic['total_packets'] += 1
                self.generated_traffic['total_bytes'] += len(packet)
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO traffic_logs 
                   (traffic_type, target, packets_sent, duration, bytes_sent) 
                   VALUES (?, ?, ?, ?, ?)''',
                ('TCP Traffic', f"{target_ip}:{port}", packets_sent, duration, bytes_sent)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} TCP packets ({bytes_sent} bytes) to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ TCP traffic error: {str(e)}"
    
    def generate_udp_traffic(self, target_ip: str, port: int, packet_count: int, delay: float,
                           payload_size: int = 512, spoof_source: bool = False) -> str:
        """Generate advanced UDP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for UDP traffic generation"
        
        try:
            packets_sent = 0
            bytes_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                if spoof_source:
                    src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                else:
                    src_ip = socket.gethostbyname(socket.gethostname())
                
                # Create random payload
                payload = random._urandom(random.randint(64, payload_size))
                packet = IP(src=src_ip, dst=target_ip)/UDP(
                    sport=random.randint(1024, 65535), 
                    dport=port
                )/payload
                
                send(packet, verbose=0)
                packets_sent += 1
                bytes_sent += len(packet)
                self.generated_traffic['udp'] += 1
                self.generated_traffic['total_packets'] += 1
                self.generated_traffic['total_bytes'] += len(packet)
                
                if delay > 0:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO traffic_logs 
                   (traffic_type, target, packets_sent, duration, bytes_sent) 
                   VALUES (?, ?, ?, ?, ?)''',
                ('UDP Traffic', f"{target_ip}:{port}", packets_sent, duration, bytes_sent)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} UDP packets ({bytes_sent} bytes) to {target_ip}:{port} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ UDP traffic error: {str(e)}"
    
    def generate_icmp_traffic(self, target_ip: str, packet_count: int, delay: float,
                            spoof_source: bool = False, flood_mode: bool = False) -> str:
        """Generate advanced ICMP traffic"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for ICMP traffic generation"
        
        try:
            packets_sent = 0
            bytes_sent = 0
            start_time = time.time()
            
            for i in range(packet_count):
                if not self.running:
                    break
                
                if spoof_source:
                    src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                else:
                    src_ip = socket.gethostbyname(socket.gethostname())
                
                # Create ICMP packet with random ID and sequence
                packet = IP(src=src_ip, dst=target_ip)/ICMP(
                    id=random.randint(1, 65535),
                    seq=random.randint(1, 65535)
                )
                
                send(packet, verbose=0)
                packets_sent += 1
                bytes_sent += len(packet)
                self.generated_traffic['icmp'] += 1
                self.generated_traffic['total_packets'] += 1
                self.generated_traffic['total_bytes'] += len(packet)
                
                if delay > 0 and not flood_mode:
                    time.sleep(delay)
            
            duration = time.time() - start_time
            
            # Log to database
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            cursor.execute(
                '''INSERT INTO traffic_logs 
                   (traffic_type, target, packets_sent, duration, bytes_sent) 
                   VALUES (?, ?, ?, ?, ?)''',
                ('ICMP Traffic', target_ip, packets_sent, duration, bytes_sent)
            )
            conn.commit()
            conn.close()
            
            return f"✅ Sent {packets_sent} ICMP packets ({bytes_sent} bytes) to {target_ip} in {duration:.2f}s"
            
        except Exception as e:
            return f"❌ ICMP traffic error: {str(e)}"
    
    def generate_mixed_traffic(self, target_ip: str, duration: int = 30, intensity: str = 'medium') -> str:
        """Generate mixed traffic for stress testing"""
        if not SCAPY_AVAILABLE:
            return "❌ Scapy not available for traffic generation"
        
        try:
            intensities = {
                'low': {'tcp': 1, 'udp': 1, 'icmp': 1, 'delay': 0.5},
                'medium': {'tcp': 5, 'udp': 5, 'icmp': 3, 'delay': 0.1},
                'high': {'tcp': 10, 'udp': 10, 'icmp': 5, 'delay': 0.01},
                'flood': {'tcp': 50, 'udp': 50, 'icmp': 20, 'delay': 0.001}
            }
            
            config = intensities.get(intensity, intensities['medium'])
            end_time = time.time() + duration
            
            self.running = True
            
            def tcp_worker():
                while self.running and time.time() < end_time:
                    for _ in range(config['tcp']):
                        if not self.running:
                            break
                        src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                        packet = IP(src=src_ip, dst=target_ip)/TCP(
                            sport=random.randint(1024, 65535),
                            dport=random.randint(1, 65535),
                            flags='S'
                        )
                        send(packet, verbose=0)
                        self.generated_traffic['tcp'] += 1
                        self.generated_traffic['total_packets'] += 1
                    time.sleep(config['delay'])
            
            def udp_worker():
                while self.running and time.time() < end_time:
                    for _ in range(config['udp']):
                        if not self.running:
                            break
                        src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
                        packet = IP(src=src_ip, dst=target_ip)/UDP(
                            sport=random.randint(1024, 65535),
                            dport=random.randint(1, 65535)
                        )/random._urandom(128)
                        send(packet, verbose=0)
                        self.generated_traffic['udp'] += 1
                        self.generated_traffic['total_packets'] += 1
                    time.sleep(config['delay'])
            
            def icmp_worker():
                while self.running and time.time() < end_time:
                    for _ in range(config['icmp']):
                        if not self.running:
                            break
                        packet = IP(dst=target_ip)/ICMP()
                        send(packet, verbose=0)
                        self.generated_traffic['icmp'] += 1
                        self.generated_traffic['total_packets'] += 1
                    time.sleep(config['delay'])
            
            # Start threads
            threads = []
            for worker in [tcp_worker, udp_worker, icmp_worker]:
                thread = threading.Thread(target=worker, daemon=True)
                thread.start()
                threads.append(thread)
            
            # Wait for duration
            time.sleep(duration)
            self.stop_traffic()
            
            # Wait for threads to finish
            for thread in threads:
                thread.join(timeout=1)
            
            stats = f"""
            Mixed Traffic Generation Complete:
            Duration: {duration}s
            Intensity: {intensity}
            TCP Packets: {self.generated_traffic['tcp']}
            UDP Packets: {self.generated_traffic['udp']}
            ICMP Packets: {self.generated_traffic['icmp']}
            Total Packets: {self.generated_traffic['total_packets']}
            Total Bytes: {self.generated_traffic['total_bytes']}
            """
            
            return f"✅ {stats}"
            
        except Exception as e:
            return f"❌ Mixed traffic error: {str(e)}"
    
    def stop_traffic(self):
        """Stop all traffic generation"""
        self.running = False
        if self.current_thread and self.current_thread.is_alive():
            self.current_thread.join(timeout=2)
        
        # Reset traffic stats
        self.generated_traffic = {
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'total_packets': 0,
            'total_bytes': 0
        }
    
    def get_traffic_stats(self) -> Dict[str, int]:
        """Get current traffic generation statistics"""
        return self.generated_traffic.copy()

class TelegramBot:
    """Enhanced Telegram bot for notifications and remote control"""
    
    def __init__(self, db_manager: EnhancedDatabaseManager):
        self.db_manager = db_manager
        self.token = None
        self.chat_id = None
        self.enabled = False
        self.last_update_id = 0
        self.running = False
        self.load_config()
    
    def load_config(self):
        """Load Telegram configuration"""
        config = configparser.ConfigParser()
        if os.path.exists(CONFIG_FILE):
            config.read(CONFIG_FILE)
            self.token = config.get('telegram', 'token', fallback=None)
            self.chat_id = config.get('telegram', 'chat_id', fallback=None)
            if self.token and self.chat_id:
                self.enabled = True
    
    def save_config(self):
        """Save Telegram configuration"""
        config = configparser.ConfigParser()
        config['telegram'] = {
            'token': self.token or '',
            'chat_id': self.chat_id or ''
        }
        with open(CONFIG_FILE, 'w') as f:
            config.write(f)
    
    def configure(self, token: str, chat_id: str) -> bool:
        """Configure Telegram bot"""
        try:
            self.token = token
            self.chat_id = chat_id
            
            # Test connection
            if self.test_connection():
                self.enabled = True
                self.save_config()
                return True
            else:
                self.enabled = False
                return False
        except Exception as e:
            print(f"Telegram configuration error: {e}")
            return False
    
    def test_connection(self) -> bool:
        """Test Telegram bot connection"""
        try:
            if not self.token:
                return False
            
            url = f"{TELEGRAM_API_URL}{self.token}/getMe"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('ok', False)
            return False
        except Exception as e:
            print(f"Telegram connection test error: {e}")
            return False
    
    def send_message(self, message: str) -> bool:
        """Send message to Telegram"""
        try:
            if not self.enabled or not self.token or not self.chat_id:
                return False
            
            url = f"{TELEGRAM_API_URL}{self.token}/sendMessage"
            payload = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            
            response = requests.post(url, json=payload, timeout=10)
            
            # Log the message
            if response.status_code == 200:
                self.db_manager.log_telegram_message(
                    self.chat_id, 
                    message[:500],  # Truncate long messages
                    'outgoing',
                    'alert'
                )
                return True
            return False
        except Exception as e:
            print(f"Send Telegram message error: {e}")
            return False
    
    def send_alert(self, alert_msg: str) -> bool:
        """Send security alert to Telegram"""
        formatted_msg = f"🚨 <b>SECURITY ALERT</b>\n{alert_msg}"
        return self.send_message(formatted_msg)
    
    def send_report(self, report_data: Dict) -> bool:
        """Send security report to Telegram"""
        try:
            report_text = f"📊 <b>Security Report</b>\n"
            report_text += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            
            if 'summary' in report_data:
                summary = report_data['summary']
                report_text += f"\n<b>Summary:</b>\n"
                report_text += f"Total Threats: {summary.get('total_threats', 0)}\n"
                report_text += f"High Severity: {summary.get('high_severity', 0)}\n"
                report_text += f"Medium Severity: {summary.get('medium_severity', 0)}\n"
                report_text += f"Low Severity: {summary.get('low_severity', 0)}\n"
            
            return self.send_message(report_text)
        except Exception as e:
            print(f"Send report error: {e}")
            return False
    
    def process_updates(self):
        """Process incoming Telegram updates"""
        try:
            if not self.enabled or not self.token:
                return
            
            url = f"{TELEGRAM_API_URL}{self.token}/getUpdates"
            params = {
                'offset': self.last_update_id + 1,
                'timeout': 30
            }
            
            response = requests.get(url, params=params, timeout=35)
            if response.status_code == 200:
                updates = response.json()
                if updates.get('ok') and updates.get('result'):
                    for update in updates['result']:
                        self.last_update_id = update['update_id']
                        
                        if 'message' in update and 'text' in update['message']:
                            message = update['message']['text']
                            chat_id = update['message']['chat']['id']
                            
                            # Log incoming message
                            self.db_manager.log_telegram_message(
                                chat_id,
                                message,
                                'incoming',
                                'command'
                            )
                            
                            # Process command
                            self._handle_command(message, chat_id)
        except Exception as e:
            print(f"Process updates error: {e}")
    
    def _handle_command(self, command: str, chat_id: str):
        """Handle Telegram commands"""
        try:
            cmd_lower = command.lower().strip()
            
            if cmd_lower == '/start':
                welcome = """🤖 <b>Accurate Cyber Defense Bot</b>
                
Available commands:
/help - Show this help
/status - System status
/ping [IP] - Ping IP address
/scan [IP] - Quick port scan
/location [IP] - Get IP location
/report - Get security report
/alerts - Toggle alerts (on/off)
                
Example: /ping 8.8.8.8"""
                self._send_reply(chat_id, welcome)
            
            elif cmd_lower == '/help':
                help_text = """📚 <b>Available Commands</b>
                
<b>Basic:</b>
/start - Start bot
/help - Show help
/status - System status
                
<b>Network Tools:</b>
/ping [IP] - Ping IP
/scan [IP] - Port scan
/deepscan [IP] - Deep scan
/location [IP] - IP location
                
<b>Security:</b>
/report - Security report
/threats - Recent threats
/alerts [on/off] - Toggle alerts
                
<b>Monitoring:</b>
/monitor [IP] - Monitor IP
/stopmonitor [IP] - Stop monitoring
/list - List monitored IPs"""
                self._send_reply(chat_id, help_text)
            
            elif cmd_lower.startswith('/ping '):
                ip = cmd_lower[6:].strip()
                # This would need integration with network scanner
                self._send_reply(chat_id, f"Pinging {ip}... (Feature in development)")
            
            elif cmd_lower.startswith('/scan '):
                ip = cmd_lower[6:].strip()
                self._send_reply(chat_id, f"Scanning {ip}... (Feature in development)")
            
            elif cmd_lower.startswith('/location '):
                ip = cmd_lower[10:].strip()
                self._send_reply(chat_id, f"Getting location for {ip}... (Feature in development)")
            
            elif cmd_lower == '/report':
                # Get recent threats from database
                threats = self.db_manager.get_recent_intrusions(5)
                if threats:
                    report = "📊 <b>Recent Threats</b>\n"
                    for threat in threats:
                        report += f"\n{threat[1]} - {threat[2]} ({threat[3]})\n"
                else:
                    report = "✅ No recent threats detected"
                self._send_reply(chat_id, report)
            
            elif cmd_lower == '/status':
                # Get system status
                status = """🟢 <b>System Status</b>
                
Bot: Online
Monitoring: Active
Last Alert: Today
Threats Today: 0
                
All systems operational."""
                self._send_reply(chat_id, status)
            
            elif cmd_lower.startswith('/alerts '):
                mode = cmd_lower[8:].strip()
                if mode in ['on', 'off']:
                    self._send_reply(chat_id, f"Alerts turned {mode}")
                else:
                    self._send_reply(chat_id, "Usage: /alerts [on|off]")
            
            else:
                self._send_reply(chat_id, "❌ Unknown command. Use /help for available commands.")
        
        except Exception as e:
            print(f"Handle command error: {e}")
            self._send_reply(chat_id, "❌ Error processing command")
    
    def _send_reply(self, chat_id: str, message: str):
        """Send reply to specific chat"""
        try:
            url = f"{TELEGRAM_API_URL}{self.token}/sendMessage"
            payload = {
                'chat_id': chat_id,
                'text': message,
                'parse_mode': 'HTML'
            }
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            print(f"Send reply error: {e}")
    
    def start_polling(self):
        """Start polling for Telegram updates"""
        self.running = True
        while self.running:
            try:
                self.process_updates()
                time.sleep(2)
            except Exception as e:
                print(f"Polling error: {e}")
                time.sleep(10)
    
    def stop_polling(self):
        """Stop polling for updates"""
        self.running = False

class AdvancedTerminalEmulator:
    """Enhanced command-line terminal emulator with advanced security commands"""
    
    def __init__(self, network_scanner: AdvancedNetworkScanner, 
                 network_monitor: EnhancedNetworkMonitor,
                 traffic_generator: AdvancedTrafficGenerator,
                 telegram_bot: TelegramBot):
        self.scanner = network_scanner
        self.monitor = network_monitor
        self.traffic_gen = traffic_generator
        self.telegram_bot = telegram_bot
        self.commands = {}
        self._init_commands()
    
    def _init_commands(self):
        """Initialize available commands"""
        self.commands = {
            'help': self.cmd_help,
            'start monitoring': self.cmd_start_monitoring,
            'stop monitoring': self.cmd_stop_monitoring,
            'status': self.cmd_status,
            'scan': self.cmd_scan,
            'deep scan': self.cmd_deep_scan,
            'ping': self.cmd_ping,
            'traceroute': self.cmd_traceroute,
            'vulnscan': self.cmd_vulnscan,
            'location': self.cmd_location,
            'ifconfig': self.cmd_ifconfig,
            'netstat': self.cmd_netstat,
            'whois': self.cmd_whois,
            'dns': self.cmd_dns,
            'threats': self.cmd_threats,
            'stats': self.cmd_stats,
            'traffic': self.cmd_traffic,
            'kill': self.cmd_kill,
            'telegram': self.cmd_telegram,
            'export': self.cmd_export,
            'report': self.cmd_report,
            'clear': self.cmd_clear,
            'exit': self.cmd_exit
        }
    
    def execute(self, command: str) -> str:
        """Execute terminal command"""
        parts = command.strip().split()
        if not parts:
            return ""
        
        cmd = parts[0].lower()
        args = parts[1:]
        
        # Find matching command
        matched_cmd = None
        for available_cmd in self.commands:
            if cmd in available_cmd.split():
                matched_cmd = available_cmd
                break
        
        if not matched_cmd:
            return f"Command not found: {cmd}\nType 'help' for available commands"
        
        try:
            result = self.commands[matched_cmd](args)
            # Log command to database
            self.scanner.db_manager.log_command(command, 'cli', True, result[:200])
            return result
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            self.scanner.db_manager.log_command(command, 'cli', False, error_msg)
            return error_msg
    
    def cmd_help(self, args):
        help_text = f"""{Colors.GREEN}{Colors.BOLD}ACCURATE CYBER DEFENSE - Enhanced Commands{Colors.END}

{Colors.CYAN}Basic Commands:{Colors.END}
  {Colors.GREEN}help{Colors.END}                    - Show this help message
  {Colors.GREEN}start monitoring [ip]{Colors.END}   - Start network monitoring (optional IP)
  {Colors.GREEN}stop monitoring{Colors.END}         - Stop all monitoring
  {Colors.GREEN}clear{Colors.END}                   - Clear the screen
  {Colors.GREEN}exit{Colors.END}                    - Exit the tool
  {Colors.GREEN}status{Colors.END}                  - Show system and monitoring status

{Colors.CYAN}Network Scanning:{Colors.END}
  {Colors.GREEN}ping <ip>{Colors.END}              - Ping target with analysis
  {Colors.GREEN}scan <ip> [ports]{Colors.END}      - Port scan (default: 1-1000)
  {Colors.GREEN}deep scan <ip>{Colors.END}         - Comprehensive port scan (1-65535)
  {Colors.GREEN}traceroute <target>{Colors.END}    - Traceroute to target
  {Colors.GREEN}vulnscan <target>{Colors.END}      - Vulnerability scan
  {Colors.GREEN}location <ip>{Colors.END}          - Get IP geographical location

{Colors.CYAN}Traffic Generation:{Colors.END}
  {Colors.GREEN}traffic <target> [type] [count]{Colors.END} - Generate network traffic
  {Colors.GREEN}kill <ip>{Colors.END}              - Stress test target with mixed traffic
  {Colors.GREEN}stop traffic{Colors.END}           - Stop all traffic generation

{Colors.CYAN}System Information:{Colors.END}
  {Colors.GREEN}ifconfig{Colors.END}               - Network interface information
  {Colors.GREEN}netstat{Colors.END}                - Network connections
  {Colors.GREEN}whois <domain>{Colors.END}         - WHOIS lookup
  {Colors.GREEN}dns <domain>{Colors.END}           - DNS lookup

{Colors.CYAN}Threat Analysis:{Colors.END}
  {Colors.GREEN}threats{Colors.END}                - View detected threats
  {Colors.GREEN}stats{Colors.END}                  - Show network statistics
  {Colors.GREEN}report [type]{Colors.END}          - Generate security report

{Colors.CYAN}Telegram Integration:{Colors.END}
  {Colors.GREEN}telegram config <token> <chat_id>{Colors.END} - Configure Telegram
  {Colors.GREEN}telegram test{Colors.END}          - Test Telegram connection
  {Colors.GREEN}telegram send <message>{Colors.END} - Send Telegram message
  {Colors.GREEN}telegram status{Colors.END}        - Show Telegram status

{Colors.CYAN}Data Management:{Colors.END}
  {Colors.GREEN}export data{Colors.END}            - Export data to file
  {Colors.GREEN}export report{Colors.END}          - Export security report

{Colors.YELLOW}Examples:{Colors.END}
  ping 8.8.8.8
  scan 192.168.1.1 1-1000
  deep scan 10.0.0.1
  location 1.1.1.1
  traffic 192.168.1.100 tcp 1000
  kill 10.0.0.5
  telegram config YOUR_TOKEN YOUR_CHAT_ID
"""
        return help_text
    
    def cmd_start_monitoring(self, args):
        target_ip = args[0] if args else None
        if self.monitor.start_monitoring(target_ip):
            return f"✅ Started monitoring {target_ip if target_ip else 'all traffic'}"
        else:
            return "⚠️ Monitoring is already active"
    
    def cmd_stop_monitoring(self, args):
        self.monitor.stop_monitoring()
        return "✅ Stopped network monitoring"
    
    def cmd_status(self, args):
        # Get monitoring stats
        stats = self.monitor.get_current_stats()
        
        # Get system info
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Get threat stats
        threat_stats = self.scanner.db_manager.get_threat_stats(1)
        
        status = f"""
{Colors.CYAN}{Colors.BOLD}SYSTEM STATUS{Colors.END}
{'-' * 50}

{Colors.GREEN}System Information:{Colors.END}
  OS: {platform.system()} {platform.release()}
  CPU: {cpu_percent}%
  Memory: {memory.percent}% ({memory.used//1024//1024}MB/{memory.total//1024//1024}MB)
  Disk: {disk.percent}% ({disk.used//1024//1024}MB/{disk.total//1024//1024}MB)

{Colors.GREEN}Monitoring Status:{Colors.END}
  Active: {'Yes' if stats['is_monitoring'] else 'No'}
  Target: {stats['target_ip'] or 'All traffic'}
  Duration: {stats['uptime']:.0f}s
  Packets: {stats['packets_processed']:,}
  Packet Rate: {stats['packet_rate']:.2f}/s
  Threats Detected: {stats['threats_detected']:,}
  Unique IPs: {stats['unique_ips']:,}

{Colors.GREEN}Recent Threats (1 hour):{Colors.END}
"""
        
        if threat_stats.get('threat_types'):
            for threat_type, data in threat_stats['threat_types'].items():
                status += f"  {threat_type}: {data['count']} (severity: {data['avg_severity']:.1f})\n"
        else:
            status += "  No threats detected\n"
        
        # Telegram status
        status += f"\n{Colors.GREEN}Telegram Status:{Colors.END}\n"
        status += f"  Enabled: {'Yes' if self.telegram_bot.enabled else 'No'}\n"
        
        return status
    
    def cmd_scan(self, args):
        if not args:
            return "Usage: scan <ip> [ports]"
        
        ip = args[0]
        ports = args[1] if len(args) > 1 else "1-1000"
        
        result = self.scanner.port_scan(ip, ports)
        if result['success']:
            open_ports = result.get('open_ports', [])
            services = result.get('services', [])
            response = f"Scan Results for {ip}:\n"
            response += f"Scan Duration: {result.get('scan_duration', 0):.2f}s\n"
            response += f"Open Ports: {len(open_ports)}\n\n"
            
            for service in services[:20]:  # Show first 20 services
                response += f"  Port {service['port']}/{service.get('protocol', 'tcp')}: "
                response += f"{service['service']}"
                if service.get('version'):
                    response += f" ({service['version']})"
                response += "\n"
            
            if len(services) > 20:
                response += f"\n  ... and {len(services) - 20} more services"
            
            return response
        else:
            return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def cmd_deep_scan(self, args):
        if not args:
            return "Usage: deep scan <ip>"
        
        ip = args[0]
        result = self.scanner.deep_scan_ip(ip)
        
        if result.get('success', False):
            response = f"Deep Scan Results for {ip}:\n"
            response += f"Scan Duration: {result.get('scan_duration', 'N/A')}\n"
            response += f"Host State: {result.get('state', 'unknown')}\n"
            response += f"Open Ports: {len(result.get('open_ports', []))}\n\n"
            
            services = result.get('services', {})
            for port, service_info in list(services.items())[:15]:  # Show first 15
                response += f"  Port {port}: {service_info.get('name', 'unknown')}"
                if service_info.get('product'):
                    response += f" ({service_info['product']})"
                if service_info.get('version'):
                    response += f" v{service_info['version']}"
                response += "\n"
            
            if len(services) > 15:
                response += f"\n  ... and {len(services) - 15} more services"
            
            return response
        else:
            return f"❌ Deep scan error: {result.get('error', 'Unknown')}"
    
    def cmd_ping(self, args):
        if not args:
            return "Usage: ping <ip/hostname>"
        
        success, result = self.scanner.ping_ip(args[0])
        return result
    
    def cmd_traceroute(self, args):
        if not args:
            return "Usage: traceroute <target>"
        return self.scanner.traceroute(args[0])
    
    def cmd_location(self, args):
        if not args:
            return "Usage: location <ip>"
        
        result = self.scanner.get_ip_location(args[0])
        if 'error' in result:
            return f"❌ {result['error']}"
        
        response = f"Location Information for {args[0]}:\n"
        response += f"Service: {result.get('service', 'Unknown')}\n"
        response += f"Country: {result.get('country', 'Unknown')}\n"
        response += f"Region: {result.get('region', 'Unknown')}\n"
        response += f"City: {result.get('city', 'Unknown')}\n"
        response += f"ISP: {result.get('isp', 'Unknown')}\n"
        response += f"Coordinates: {result.get('coordinates', 'Unknown')}\n"
        response += f"Timezone: {result.get('timezone', 'Unknown')}\n"
        response += f"ASN: {result.get('asn', 'Unknown')}\n"
        
        return response
    
    def cmd_traffic(self, args):
        if not args:
            return "Usage: traffic <target> [type] [count] [delay_ms]\nTypes: tcp, udp, icmp, mixed"
        
        target = args[0]
        traffic_type = args[1] if len(args) > 1 else "mixed"
        count = int(args[2]) if len(args) > 2 else 100
        delay = float(args[3])/1000 if len(args) > 3 else 0.01
        
        if traffic_type == "tcp":
            port = int(args[4]) if len(args) > 4 else 80
            result = self.traffic_gen.generate_tcp_traffic(target, port, count, delay)
        elif traffic_type == "udp":
            port = int(args[4]) if len(args) > 4 else 53
            result = self.traffic_gen.generate_udp_traffic(target, port, count, delay)
        elif traffic_type == "icmp":
            result = self.traffic_gen.generate_icmp_traffic(target, count, delay)
        elif traffic_type == "mixed":
            duration = int(args[2]) if len(args) > 2 else 30
            intensity = args[3] if len(args) > 3 else "medium"
            result = self.traffic_gen.generate_mixed_traffic(target, duration, intensity)
        else:
            return f"❌ Unknown traffic type: {traffic_type}"
        
        return result
    
    def cmd_kill(self, args):
        if not args:
            return "Usage: kill <ip> [duration] [intensity]\nIntensity: low, medium, high, flood"
        
        target = args[0]
        duration = int(args[1]) if len(args) > 1 else 30
        intensity = args[2] if len(args) > 2 else "medium"
        
        return f"Starting stress test on {target} for {duration}s with {intensity} intensity...\n" + \
               self.traffic_gen.generate_mixed_traffic(target, duration, intensity)
    
    def cmd_telegram(self, args):
        if not args:
            return "Usage: telegram <config|test|send|status>"
        
        subcmd = args[0].lower()
        
        if subcmd == "config":
            if len(args) < 3:
                return "Usage: telegram config <token> <chat_id>"
            
            token = args[1]
            chat_id = args[2]
            
            if self.telegram_bot.configure(token, chat_id):
                return "✅ Telegram configured successfully"
            else:
                return "❌ Telegram configuration failed"
        
        elif subcmd == "test":
            if self.telegram_bot.test_connection():
                if self.telegram_bot.send_message("🔒 Telegram connection test successful!"):
                    return "✅ Telegram connection test passed"
                else:
                    return "⚠️ Token valid but message sending failed"
            else:
                return "❌ Telegram connection test failed"
        
        elif subcmd == "send":
            if len(args) < 2:
                return "Usage: telegram send <message>"
            
            message = " ".join(args[1:])
            if self.telegram_bot.send_message(message):
                return "✅ Message sent to Telegram"
            else:
                return "❌ Failed to send message"
        
        elif subcmd == "status":
            status = "Telegram Status:\n"
            status += f"  Enabled: {self.telegram_bot.enabled}\n"
            status += f"  Token: {'Configured' if self.telegram_bot.token else 'Not configured'}\n"
            status += f"  Chat ID: {'Configured' if self.telegram_bot.chat_id else 'Not configured'}"
            return status
        
        else:
            return f"❌ Unknown telegram command: {subcmd}"
    
    def cmd_report(self, args):
        period = args[0] if args else "day"
        
        if period not in ["day", "week", "month", "annual"]:
            return "Usage: report [day|week|month|annual]"
        
        # Generate report data
        threat_stats = self.scanner.db_manager.get_threat_stats(
            24 if period == "day" else 
            168 if period == "week" else 
            720 if period == "month" else 
            8760
        )
        
        report = f"Security Report - {period.capitalize()}\n"
        report += "=" * 50 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        if threat_stats.get('threat_types'):
            report += "Threat Summary:\n"
            for threat_type, data in threat_stats['threat_types'].items():
                report += f"  {threat_type}: {data['count']} threats\n"
        
        if threat_stats.get('top_source_ips'):
            report += "\nTop Source IPs:\n"
            for ip, count in threat_stats['top_source_ips'][:5]:
                report += f"  {ip}: {count} threats\n"
        
        # Save to file
        filename = f"security_report_{period}_{int(time.time())}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        # Send to Telegram if enabled
        if self.telegram_bot.enabled:
            self.telegram_bot.send_report({
                'summary': {
                    'total_threats': sum(data['count'] for data in threat_stats.get('threat_types', {}).values()),
                    'high_severity': 0,  # Would need to calculate from severity data
                    'medium_severity': 0,
                    'low_severity': 0
                }
            })
        
        return f"✅ Report generated: {filename}"
    
    def cmd_ifconfig(self, args):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_netstat(self, args):
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
            else:
                result = subprocess.run(['netstat', '-tulpn'], capture_output=True, text=True)
            return result.stdout if result.stdout else result.stderr
        except Exception as e:
            return str(e)
    
    def cmd_whois(self, args):
        if not args:
            return "Usage: whois <domain>"
        
        try:
            result = subprocess.run(['whois', args[0]], capture_output=True, text=True, timeout=30)
            return result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout
        except Exception as e:
            return str(e)
    
    def cmd_dns(self, args):
        if not args:
            return "Usage: dns <domain>"
        
        try:
            ip = socket.gethostbyname(args[0])
            return f"{args[0]} → {ip}"
        except Exception as e:
            return str(e)
    
    def cmd_threats(self, args):
        limit = int(args[0]) if args else 10
        threats = self.scanner.db_manager.get_recent_intrusions(limit)
        
        if not threats:
            return "No threats detected"
        
        response = "Recent Threats:\n"
        response += "-" * 80 + "\n"
        
        for timestamp, source_ip, threat_type, severity, description, action in threats:
            response += f"Time: {timestamp}\n"
            response += f"Source: {source_ip}\n"
            response += f"Type: {threat_type} ({severity})\n"
            response += f"Action: {action}\n"
            if description:
                response += f"Description: {description}\n"
            response += "-" * 80 + "\n"
        
        return response
    
    def cmd_stats(self, args):
        period = int(args[0]) if args else 24
        threat_stats = self.scanner.db_manager.get_threat_stats(period)
        
        response = f"Network Statistics (Last {period} hours):\n\n"
        
        if threat_stats.get('threat_types'):
            response += "Threat Types:\n"
            for threat_type, data in threat_stats['threat_types'].items():
                response += f"  {threat_type}: {data['count']} threats (avg severity: {data['avg_severity']:.1f})\n"
        
        if threat_stats.get('top_source_ips'):
            response += f"\nTop Source IPs:\n"
            for ip, count in threat_stats['top_source_ips'][:5]:
                response += f"  {ip}: {count} threats\n"
        
        return response
    
    def cmd_export(self, args):
        if not args:
            return "Usage: export <data|report>"
        
        export_type = args[0].lower()
        
        if export_type == "data":
            # Export database to JSON
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            tables = ['threat_logs', 'intrusion_detection', 'scan_results', 'network_stats']
            export_data = {}
            
            for table in tables:
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [col[1] for col in cursor.fetchall()]
                
                export_data[table] = []
                for row in rows:
                    export_data[table].append(dict(zip(columns, row)))
            
            conn.close()
            
            # Save to file
            filename = f"export_data_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            return f"✅ Data exported to {filename}"
        
        elif export_type == "report":
            return self.cmd_report(args[1:] if len(args) > 1 else ["day"])
        
        else:
            return f"❌ Unknown export type: {export_type}"
    
    def cmd_vulnscan(self, args):
        if not args:
            return "Usage: vulnscan <target>"
        
        result = self.scanner.vulnerability_scan(args[0])
        if result['success']:
            vulns = result.get('vulnerabilities', [])
            response = f"Vulnerability Scan for {args[0]}:\n"
            response += f"Scan Duration: {result.get('scan_duration', 0):.2f}s\n"
            response += f"Vulnerabilities found: {len(vulns)}\n\n"
            for vuln in vulns[:10]:
                response += f"  • {vuln}\n"
            return response
        else:
            return f"❌ Scan error: {result.get('error', 'Unknown')}"
    
    def cmd_clear(self, args):
        os.system('cls' if os.name == 'nt' else 'clear')
        return ""
    
    def cmd_exit(self, args):
        return "EXIT"

class EnhancedCyberSecurityDashboard:
    """Enhanced GUI dashboard with all integrated features"""
    
    def __init__(self, root, db_manager: EnhancedDatabaseManager, 
                 network_monitor: EnhancedNetworkMonitor, 
                 network_scanner: AdvancedNetworkScanner,
                 traffic_generator: AdvancedTrafficGenerator,
                 telegram_bot: TelegramBot):
        self.root = root
        self.db_manager = db_manager
        self.monitor = network_monitor
        self.scanner = network_scanner
        self.traffic_gen = traffic_generator
        self.telegram_bot = telegram_bot
        self.current_theme = "dark"
        
        self.setup_gui()
        self.update_interval = 2000  # ms
        self.update_dashboard()
        
        # Start Telegram polling in background
        if self.telegram_bot.enabled:
            self.telegram_polling_thread = threading.Thread(
                target=self.telegram_bot.start_polling,
                daemon=True
            )
            self.telegram_polling_thread.start()
    
    def setup_gui(self):
        """Setup the enhanced dashboard GUI"""
        self.root.title("Accurate Cyber Defense v2.0 - Integrated Security Platform")
        self.root.geometry("1400x900")
        
        # Create menu
        self.create_menu()
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Create enhanced tabs
        self.create_enhanced_threat_dashboard_tab()
        self.create_advanced_network_monitor_tab()
        self.create_comprehensive_scanner_tab()
        self.create_traffic_generator_tab()
        self.create_telegram_control_tab()
        self.create_enhanced_terminal_tab()
        self.create_reports_analytics_tab()
        
        # Apply theme
        self.apply_theme()
    
    def create_menu(self):
        """Create enhanced application menu"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Export Data", command=self.export_data)
        file_menu.add_command(label="Export Report", command=self.export_report)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Switch Theme", command=self.switch_theme)
        view_menu.add_separator()
        view_menu.add_command(label="Threat Dashboard", 
                             command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Network Monitor",
                             command=lambda: self.notebook.select(1))
        view_menu.add_command(label="Scanner Tools",
                             command=lambda: self.notebook.select(2))
        view_menu.add_command(label="Traffic Generator",
                             command=lambda: self.notebook.select(3))
        view_menu.add_command(label="Telegram Control",
                             command=lambda: self.notebook.select(4))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Quick Scan", command=self.quick_scan)
        tools_menu.add_command(label="Deep Scan", command=self.deep_scan)
        tools_menu.add_command(label="Vulnerability Scan", command=self.vulnerability_scan)
        tools_menu.add_command(label="Traffic Analysis", command=self.traffic_analysis)
        tools_menu.add_separator()
        tools_menu.add_command(label="IP Location Lookup", command=self.ip_location_lookup)
        tools_menu.add_command(label="WHOIS Lookup", command=self.whois_lookup)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Monitoring menu
        monitor_menu = tk.Menu(menubar, tearoff=0)
        monitor_menu.add_command(label="Start Monitoring", command=self.start_monitoring)
        monitor_menu.add_command(label="Stop Monitoring", command=self.stop_monitoring)
        monitor_menu.add_separator()
        monitor_menu.add_command(label="Add IP to Monitor", command=self.add_ip_to_monitor)
        monitor_menu.add_command(label="View Monitored IPs", command=self.view_monitored_ips)
        menubar.add_cascade(label="Monitoring", menu=monitor_menu)
        
        # Telegram menu
        telegram_menu = tk.Menu(menubar, tearoff=0)
        telegram_menu.add_command(label="Configure Bot", command=self.configure_telegram)
        telegram_menu.add_command(label="Test Connection", command=self.test_telegram)
        telegram_menu.add_command(label="Send Test Message", command=self.send_test_message)
        telegram_menu.add_command(label="Toggle Alerts", command=self.toggle_alerts)
        menubar.add_cascade(label="Telegram", menu=telegram_menu)
        
        self.root.config(menu=menubar)
    
    def create_enhanced_threat_dashboard_tab(self):
        """Create enhanced threat dashboard tab"""
        self.threat_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.threat_tab, text="Threat Dashboard")
        
        # Top frame with controls
        top_frame = ttk.Frame(self.threat_tab)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Left side: Monitoring controls
        monitor_frame = ttk.LabelFrame(top_frame, text="Network Monitoring")
        monitor_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        control_frame = ttk.Frame(monitor_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(control_frame, text="Target IP (optional):").pack(side=tk.LEFT, padx=5)
        self.monitor_ip_entry = ttk.Entry(control_frame, width=20)
        self.monitor_ip_entry.pack(side=tk.LEFT, padx=5)
        
        self.start_monitor_btn = ttk.Button(control_frame, text="Start Monitoring", 
                                           command=self.start_monitoring)
        self.start_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_monitor_btn = ttk.Button(control_frame, text="Stop Monitoring",
                                          command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_monitor_btn.pack(side=tk.LEFT, padx=5)
        
        # Right side: Quick actions
        action_frame = ttk.LabelFrame(top_frame, text="Quick Actions")
        action_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        
        action_buttons = [
            ("Scan Network", self.quick_scan),
            ("View Threats", lambda: self.update_threat_list()),
            ("Generate Report", lambda: self.generate_report('day')),
            ("Clear Alerts", self.clear_alerts)
        ]
        
        for text, command in action_buttons:
            ttk.Button(action_frame, text=text, command=command).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Main content area
        main_content = ttk.Frame(self.threat_tab)
        main_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Left: Current threats display
        threats_frame = ttk.LabelFrame(main_content, text="Current Threats")
        threats_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        
        # Create treeview for threats with more columns
        columns = ('Time', 'Source IP', 'Threat Type', 'Severity', 'Action', 'Description')
        self.threats_tree = ttk.Treeview(threats_frame, columns=columns, show='headings', height=15)
        
        column_widths = {'Time': 150, 'Source IP': 120, 'Threat Type': 120, 
                        'Severity': 80, 'Action': 100, 'Description': 200}
        
        for col in columns:
            self.threats_tree.heading(col, text=col)
            self.threats_tree.column(col, width=column_widths.get(col, 100))
        
        # Add scrollbars
        v_scrollbar = ttk.Scrollbar(threats_frame, orient=tk.VERTICAL, command=self.threats_tree.yview)
        h_scrollbar = ttk.Scrollbar(threats_frame, orient=tk.HORIZONTAL, command=self.threats_tree.xview)
        self.threats_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.threats_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        v_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        h_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Right: Threat statistics and details
        stats_frame = ttk.LabelFrame(main_content, text="Threat Statistics & Details")
        stats_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Statistics display
        self.stats_text = scrolledtext.ScrolledText(stats_frame, height=10)
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Threat details frame
        details_frame = ttk.LabelFrame(stats_frame, text="Threat Details")
        details_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.threat_details = scrolledtext.ScrolledText(details_frame, height=8)
        self.threat_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Bind treeview selection
        self.threats_tree.bind('<<TreeviewSelect>>', self.on_threat_selected)
    
    def create_advanced_network_monitor_tab(self):
        """Create advanced network monitor tab"""
        self.monitor_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_tab, text="Network Monitor")
        
        # Real-time stats in grid layout
        stats_frame = ttk.LabelFrame(self.monitor_tab, text="Real-time Statistics")
        stats_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create stats display with better layout
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Two-column layout for stats
        stats_left = ttk.Frame(stats_grid)
        stats_left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        stats_right = ttk.Frame(stats_grid)
        stats_right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Left column stats
        left_stats = [
            ("Packets Processed:", "packets"),
            ("Packet Rate:", "rate"),
            ("TCP Packets:", "tcp"),
            ("UDP Packets:", "udp"),
            ("ICMP Packets:", "icmp"),
            ("ARP Packets:", "arp"),
            ("Total Bytes:", "bytes")
        ]
        
        for label_text, key in left_stats:
            frame = ttk.Frame(stats_left)
            frame.pack(fill=tk.X, padx=5, pady=3)
            
            ttk.Label(frame, text=label_text, font=('Arial', 10, 'bold'), width=20, anchor='e').pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 10), foreground='green')
            self.stats_labels[key].pack(side=tk.LEFT, padx=5)
        
        # Right column stats
        right_stats = [
            ("Threats Detected:", "threats"),
            ("Monitoring Time:", "uptime"),
            ("Unique IPs:", "unique_ips"),
            ("Active Connections:", "connections"),
            ("Bandwidth Usage:", "bandwidth"),
            ("System CPU:", "cpu"),
            ("System Memory:", "memory")
        ]
        
        for label_text, key in right_stats:
            frame = ttk.Frame(stats_right)
            frame.pack(fill=tk.X, padx=5, pady=3)
            
            ttk.Label(frame, text=label_text, font=('Arial', 10, 'bold'), width=20, anchor='e').pack(side=tk.LEFT)
            self.stats_labels[key] = ttk.Label(frame, text="0", font=('Arial', 10), foreground='blue')
            self.stats_labels[key].pack(side=tk.LEFT, padx=5)
        
        # Packet log with filter options
        log_frame = ttk.LabelFrame(self.monitor_tab, text="Packet Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Filter controls
        filter_frame = ttk.Frame(log_frame)
        filter_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT, padx=5)
        self.log_filter = ttk.Combobox(filter_frame, values=["All", "TCP", "UDP", "ICMP", "Threats"], width=10)
        self.log_filter.pack(side=tk.LEFT, padx=5)
        self.log_filter.set("All")
        
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_log_filter).pack(side=tk.LEFT, padx=5)
        ttk.Button(filter_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        # Packet log display
        self.packet_log = scrolledtext.ScrolledText(log_frame, height=15)
        self.packet_log.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_comprehensive_scanner_tab(self):
        """Create comprehensive scanner tab with all tools"""
        self.scanner_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.scanner_tab, text="Scanner Tools")
        
        # Scanner controls in notebook within tab
        scanner_notebook = ttk.Notebook(self.scanner_tab)
        scanner_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Quick Scan tab
        quick_scan_tab = ttk.Frame(scanner_notebook)
        scanner_notebook.add(quick_scan_tab, text="Quick Scan")
        self.create_quick_scan_tab(quick_scan_tab)
        
        # Deep Scan tab
        deep_scan_tab = ttk.Frame(scanner_notebook)
        scanner_notebook.add(deep_scan_tab, text="Deep Scan")
        self.create_deep_scan_tab(deep_scan_tab)
        
        # Vulnerability Scan tab
        vuln_scan_tab = ttk.Frame(scanner_notebook)
        scanner_notebook.add(vuln_scan_tab, text="Vulnerability Scan")
        self.create_vuln_scan_tab(vuln_scan_tab)
        
        # Network Tools tab
        tools_tab = ttk.Frame(scanner_notebook)
        scanner_notebook.add(tools_tab, text="Network Tools")
        self.create_network_tools_tab(tools_tab)
    
    def create_quick_scan_tab(self, parent):
        """Create quick scan tab"""
        # Target input
        target_frame = ttk.LabelFrame(parent, text="Target Configuration")
        target_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(target_frame, text="Target IP/Hostname:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.quick_scan_target = ttk.Entry(target_frame, width=30)
        self.quick_scan_target.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Port Range:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.quick_scan_ports = ttk.Entry(target_frame, width=15)
        self.quick_scan_ports.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        self.quick_scan_ports.insert(0, "1-1000")
        
        # Scan buttons
        button_frame = ttk.Frame(target_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Ping", command=self.quick_ping).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Port Scan", command=self.quick_port_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Traceroute", command=self.quick_traceroute).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Get Location", command=self.quick_location).pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(parent, text="Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.quick_scan_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.quick_scan_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_deep_scan_tab(self, parent):
        """Create deep scan tab"""
        # Configuration
        config_frame = ttk.LabelFrame(parent, text="Deep Scan Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(config_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.deep_scan_target = ttk.Entry(config_frame, width=30)
        self.deep_scan_target.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Scan options
        options_frame = ttk.Frame(config_frame)
        options_frame.grid(row=1, column=0, columnspan=2, pady=5)
        
        self.deep_scan_os = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="OS Detection", variable=self.deep_scan_os).pack(side=tk.LEFT, padx=5)
        
        self.deep_scan_service = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Service Version", variable=self.deep_scan_service).pack(side=tk.LEFT, padx=5)
        
        self.deep_scan_script = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Use Scripts", variable=self.deep_scan_script).pack(side=tk.LEFT, padx=5)
        
        # Scan button
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=2, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Start Deep Scan", command=self.start_deep_scan, 
                  style='Accent.TButton').pack(side=tk.LEFT, padx=5)
        
        # Progress
        self.deep_scan_progress = ttk.Progressbar(button_frame, mode='indeterminate')
        self.deep_scan_progress.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(parent, text="Deep Scan Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Results notebook
        deep_results_notebook = ttk.Notebook(results_frame)
        deep_results_notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Open ports tab
        ports_tab = ttk.Frame(deep_results_notebook)
        deep_results_notebook.add(ports_tab, text="Open Ports")
        
        columns = ('Port', 'Protocol', 'Service', 'Version', 'State')
        self.deep_scan_tree = ttk.Treeview(ports_tab, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.deep_scan_tree.heading(col, text=col)
            self.deep_scan_tree.column(col, width=100)
        
        scrollbar = ttk.Scrollbar(ports_tab, orient=tk.VERTICAL, command=self.deep_scan_tree.yview)
        self.deep_scan_tree.configure(yscrollcommand=scrollbar.set)
        
        self.deep_scan_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Details tab
        details_tab = ttk.Frame(deep_results_notebook)
        deep_results_notebook.add(details_tab, text="Scan Details")
        
        self.deep_scan_details = scrolledtext.ScrolledText(details_tab, wrap=tk.WORD)
        self.deep_scan_details.pack(fill=tk.BOTH, expand=True)
    
    def create_vuln_scan_tab(self, parent):
        """Create vulnerability scan tab"""
        # Configuration
        config_frame = ttk.LabelFrame(parent, text="Vulnerability Scan")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(config_frame, text="Target:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.vuln_scan_target = ttk.Entry(config_frame, width=30)
        self.vuln_scan_target.grid(row=0, column=1, sticky=tk.W, padx=5, pady=5)
        
        # Scan button
        button_frame = ttk.Frame(config_frame)
        button_frame.grid(row=1, column=0, columnspan=2, pady=10)
        
        ttk.Button(button_frame, text="Start Vulnerability Scan", 
                  command=self.start_vuln_scan).pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(parent, text="Vulnerability Findings")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.vuln_scan_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.vuln_scan_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_network_tools_tab(self, parent):
        """Create network tools tab"""
        # Tools frame
        tools_frame = ttk.LabelFrame(parent, text="Network Diagnostic Tools")
        tools_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Grid of tools
        tools = [
            ("Ping", self.network_ping),
            ("Traceroute", self.network_traceroute),
            ("DNS Lookup", self.network_dns),
            ("WHOIS Lookup", self.network_whois),
            ("Port Check", self.network_port_check),
            ("Speed Test", self.network_speed_test),
            ("Interface Info", self.network_interface_info),
            ("Connection Test", self.network_connection_test)
        ]
        
        for i, (text, command) in enumerate(tools):
            row = i // 4
            col = i % 4
            
            btn = ttk.Button(tools_frame, text=text, command=command, width=15)
            btn.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
        
        # Configure grid
        for i in range(4):
            tools_frame.columnconfigure(i, weight=1)
        for i in range((len(tools) + 3) // 4):
            tools_frame.rowconfigure(i, weight=1)
        
        # Results area
        results_frame = ttk.LabelFrame(parent, text="Tool Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.network_tools_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.network_tools_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_traffic_generator_tab(self):
        """Create traffic generator tab"""
        self.traffic_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_tab, text="Traffic Generator")
        
        # Configuration frame
        config_frame = ttk.LabelFrame(self.traffic_tab, text="Traffic Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Target configuration
        target_frame = ttk.Frame(config_frame)
        target_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(target_frame, text="Target IP:").pack(side=tk.LEFT, padx=5)
        self.traffic_target = ttk.Entry(target_frame, width=20)
        self.traffic_target.pack(side=tk.LEFT, padx=5)
        
        # Traffic type selection
        type_frame = ttk.Frame(config_frame)
        type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(type_frame, text="Traffic Type:").pack(side=tk.LEFT, padx=5)
        self.traffic_type = ttk.Combobox(type_frame, values=["TCP", "UDP", "ICMP", "Mixed"], width=10)
        self.traffic_type.pack(side=tk.LEFT, padx=5)
        self.traffic_type.current(0)
        
        # Parameters frame
        params_frame = ttk.Frame(config_frame)
        params_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # Packet count
        ttk.Label(params_frame, text="Count:").grid(row=0, column=0, padx=5, pady=5)
        self.traffic_count = ttk.Spinbox(params_frame, from_=1, to=100000, width=10)
        self.traffic_count.grid(row=0, column=1, padx=5, pady=5)
        self.traffic_count.delete(0, tk.END)
        self.traffic_count.insert(0, "100")
        
        # Delay
        ttk.Label(params_frame, text="Delay (ms):").grid(row=0, column=2, padx=5, pady=5)
        self.traffic_delay = ttk.Spinbox(params_frame, from_=0, to=1000, width=10)
        self.traffic_delay.grid(row=0, column=3, padx=5, pady=5)
        self.traffic_delay.delete(0, tk.END)
        self.traffic_delay.insert(0, "10")
        
        # Port (for TCP/UDP)
        ttk.Label(params_frame, text="Port:").grid(row=0, column=4, padx=5, pady=5)
        self.traffic_port = ttk.Spinbox(params_frame, from_=1, to=65535, width=10)
        self.traffic_port.grid(row=0, column=5, padx=5, pady=5)
        self.traffic_port.delete(0, tk.END)
        self.traffic_port.insert(0, "80")
        
        # Advanced options
        adv_frame = ttk.Frame(config_frame)
        adv_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.traffic_spoof = tk.BooleanVar(value=False)
        ttk.Checkbutton(adv_frame, text="Spoof Source IP", variable=self.traffic_spoof).pack(side=tk.LEFT, padx=5)
        
        self.traffic_flood = tk.BooleanVar(value=False)
        ttk.Checkbutton(adv_frame, text="Flood Mode", variable=self.traffic_flood).pack(side=tk.LEFT, padx=5)
        
        # Control buttons
        control_frame = ttk.Frame(config_frame)
        control_frame.pack(fill=tk.X, padx=5, pady=10)
        
        self.start_traffic_btn = ttk.Button(control_frame, text="Start Traffic", command=self.start_traffic)
        self.start_traffic_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_traffic_btn = ttk.Button(control_frame, text="Stop Traffic", 
                                          command=self.stop_traffic, state=tk.DISABLED)
        self.stop_traffic_btn.pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.traffic_tab, text="Traffic Generation Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.traffic_results = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.traffic_results.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Statistics frame
        stats_frame = ttk.LabelFrame(self.traffic_tab, text="Traffic Statistics")
        stats_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.traffic_stats_text = tk.Text(stats_frame, height=4)
        self.traffic_stats_text.pack(fill=tk.X, padx=5, pady=5)
        self.traffic_stats_text.insert(tk.END, "No traffic generated yet")
        self.traffic_stats_text.config(state=tk.DISABLED)
    
    def create_telegram_control_tab(self):
        """Create Telegram control tab"""
        self.telegram_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.telegram_tab, text="Telegram Control")
        
        # Configuration frame
        config_frame = ttk.LabelFrame(self.telegram_tab, text="Bot Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Token input
        token_frame = ttk.Frame(config_frame)
        token_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(token_frame, text="Bot Token:").pack(side=tk.LEFT, padx=5)
        self.telegram_token = ttk.Entry(token_frame, width=50)
        self.telegram_token.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        if self.telegram_bot.token:
            self.telegram_token.insert(0, self.telegram_bot.token)
        
        # Chat ID input
        chat_frame = ttk.Frame(config_frame)
        chat_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(chat_frame, text="Chat ID:").pack(side=tk.LEFT, padx=5)
        self.telegram_chat_id = ttk.Entry(chat_frame, width=50)
        self.telegram_chat_id.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        if self.telegram_bot.chat_id:
            self.telegram_chat_id.insert(0, self.telegram_bot.chat_id)
        
        # Configuration buttons
        button_frame = ttk.Frame(config_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Button(button_frame, text="Save Configuration", command=self.save_telegram_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Test Connection", command=self.test_telegram_connection).pack(side=tk.LEFT, padx=5)
        
        # Control frame
        control_frame = ttk.LabelFrame(self.telegram_tab, text="Bot Controls")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Message sending
        msg_frame = ttk.Frame(control_frame)
        msg_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(msg_frame, text="Message:").pack(side=tk.LEFT, padx=5)
        self.telegram_message = ttk.Entry(msg_frame, width=40)
        self.telegram_message.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        ttk.Button(msg_frame, text="Send", command=self.send_telegram_message).pack(side=tk.LEFT, padx=5)
        
        # Quick commands
        cmd_frame = ttk.Frame(control_frame)
        cmd_frame.pack(fill=tk.X, padx=5, pady=5)
        
        quick_commands = [
            ("Send Alert", lambda: self.send_telegram_alert("Test alert from dashboard")),
            ("Get Status", self.send_telegram_status_request),
            ("Test", lambda: self.send_telegram_message("Test message from dashboard"))
        ]
        
        for text, command in quick_commands:
            ttk.Button(cmd_frame, text=text, command=command).pack(side=tk.LEFT, padx=5)
        
        # Status display
        status_frame = ttk.LabelFrame(self.telegram_tab, text="Bot Status")
        status_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.telegram_status_text = scrolledtext.ScrolledText(status_frame, wrap=tk.WORD, height=10)
        self.telegram_status_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Update status
        self.update_telegram_status()
    
    def create_enhanced_terminal_tab(self):
        """Create enhanced terminal emulator tab"""
        self.terminal_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.terminal_tab, text="Terminal")
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(self.terminal_tab, wrap=tk.WORD, state='disabled')
        self.terminal_output.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Terminal input with history
        input_frame = ttk.Frame(self.terminal_tab)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(input_frame, text=">").pack(side=tk.LEFT, padx=5)
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(fill=tk.X, expand=True, padx=5)
        self.terminal_input.bind('<Return>', self.execute_terminal_command)
        self.terminal_input.bind('<Up>', self.terminal_history_up)
        self.terminal_input.bind('<Down>', self.terminal_history_down)
        
        # Terminal history
        self.terminal_history = []
        self.terminal_history_index = -1
        
        # Control buttons
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(button_frame, text="Help", command=self.show_terminal_help).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="Clear", command=self.clear_terminal).pack(side=tk.LEFT, padx=2)
        ttk.Button(button_frame, text="History", command=self.show_terminal_history).pack(side=tk.LEFT, padx=2)
    
    def create_reports_analytics_tab(self):
        """Create reports and analytics tab"""
        self.reports_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_tab, text="Reports & Analytics")
        
        # Report generation controls
        control_frame = ttk.LabelFrame(self.reports_tab, text="Report Generation")
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Period selection
        period_frame = ttk.Frame(control_frame)
        period_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(period_frame, text="Report Period:").pack(side=tk.LEFT, padx=5)
        self.report_period = ttk.Combobox(period_frame, values=["Day", "Week", "Month", "Annual"], width=10)
        self.report_period.pack(side=tk.LEFT, padx=5)
        self.report_period.current(0)
        
        # Report type
        type_frame = ttk.Frame(control_frame)
        type_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(type_frame, text="Report Type:").pack(side=tk.LEFT, padx=5)
        self.report_type = ttk.Combobox(type_frame, 
                                       values=["Threat Report", "Network Report", "Security Report", "Full Report"], 
                                       width=15)
        self.report_type.pack(side=tk.LEFT, padx=5)
        self.report_type.current(0)
        
        # Generate buttons
        button_frame = ttk.Frame(control_frame)
        button_frame.pack(fill=tk.X, padx=5, pady=10)
        
        ttk.Button(button_frame, text="Generate Report", 
                  command=self.generate_selected_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Export to File", 
                  command=self.export_report_to_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Send to Telegram", 
                  command=self.send_report_to_telegram).pack(side=tk.LEFT, padx=5)
        
        # Reports display
        reports_frame = ttk.LabelFrame(self.reports_tab, text="Generated Reports")
        reports_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.reports_display = scrolledtext.ScrolledText(reports_frame, wrap=tk.WORD)
        self.reports_display.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Analytics section
        analytics_frame = ttk.LabelFrame(self.reports_tab, text="Security Analytics")
        analytics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Quick stats
        stats_frame = ttk.Frame(analytics_frame)
        stats_frame.pack(fill=tk.X, padx=5, pady=5)
        
        self.analytics_labels = {}
        stats = [
            ("Threats Today:", "threats_today"),
            ("Top Threat Type:", "top_threat"),
            ("Most Active IP:", "active_ip"),
            ("Success Rate:", "success_rate")
        ]
        
        for i, (label, key) in enumerate(stats):
            frame = ttk.Frame(stats_frame)
            frame.grid(row=0, column=i, padx=10, pady=5, sticky='w')
            
            ttk.Label(frame, text=label, font=('Arial', 9, 'bold')).pack(anchor='w')
            self.analytics_labels[key] = ttk.Label(frame, text="N/A", font=('Arial', 9))
            self.analytics_labels[key].pack(anchor='w')
    
    def apply_theme(self):
        """Apply current theme to GUI"""
        theme = THEMES[self.current_theme]
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background=theme['bg'])
        style.configure('TLabel', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe', background=theme['bg'], foreground=theme['fg'])
        style.configure('TLabelframe.Label', background=theme['bg'], foreground=theme['fg'])
        
        # Configure text widgets
        text_widgets = [
            self.stats_text, self.packet_log, self.threat_details,
            self.quick_scan_results, self.deep_scan_details, 
            self.vuln_scan_results, self.network_tools_results,
            self.traffic_results, self.telegram_status_text,
            self.terminal_output, self.reports_display
        ]
        
        for widget in text_widgets:
            if hasattr(self, widget):  # Check if attribute exists
                widget.configure(
                    background=theme['text_bg'],
                    foreground=theme['text_fg'],
                    insertbackground=theme['fg']
                )
    
    def switch_theme(self):
        """Switch between dark and light themes"""
        self.current_theme = "light" if self.current_theme == "dark" else "dark"
        self.apply_theme()
    
    def on_threat_selected(self, event):
        """Handle threat selection in treeview"""
        selection = self.threats_tree.selection()
        if selection:
            item = self.threats_tree.item(selection[0])
            values = item['values']
            
            details = f"Threat Details:\n"
            details += f"Time: {values[0]}\n"
            details += f"Source IP: {values[1]}\n"
            details += f"Type: {values[2]}\n"
            details += f"Severity: {values[3]}\n"
            details += f"Action: {values[4]}\n"
            details += f"Description: {values[5]}\n"
            
            self.threat_details.delete(1.0, tk.END)
            self.threat_details.insert(tk.END, details)
    
    def start_monitoring(self):
        """Start network monitoring"""
        target_ip = self.monitor_ip_entry.get().strip()
        if target_ip and not self.validate_ip(target_ip):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        if self.monitor.start_monitoring(target_ip):
            self.start_monitor_btn.config(state=tk.DISABLED)
            self.stop_monitor_btn.config(state=tk.NORMAL)
            self.log_message(f"Started monitoring {target_ip if target_ip else 'all traffic'}")
            
            # Update monitor status
            self.monitor.set_telegram_bot(self.telegram_bot)
        else:
            messagebox.showwarning("Warning", "Monitoring is already active")
    
    def stop_monitoring(self):
        """Stop network monitoring"""
        self.monitor.stop_monitoring()
        self.start_monitor_btn.config(state=tk.NORMAL)
        self.stop_monitor_btn.config(state=tk.DISABLED)
        self.log_message("Stopped network monitoring")
    
    def quick_ping(self):
        """Quick ping from scanner tab"""
        target = self.quick_scan_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.quick_scan_results.delete(1.0, tk.END)
        self.quick_scan_results.insert(tk.END, f"Pinging {target}...\n")
        
        def do_ping():
            success, result = self.scanner.ping_ip(target)
            self.quick_scan_results.insert(tk.END, result + "\n")
            self.quick_scan_results.see(tk.END)
        
        threading.Thread(target=do_ping, daemon=True).start()
    
    def quick_port_scan(self):
        """Quick port scan from scanner tab"""
        target = self.quick_scan_target.get().strip()
        ports = self.quick_scan_ports.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        if not self.validate_ip(target):
            messagebox.showerror("Error", "Invalid IP address")
            return
        
        self.quick_scan_results.delete(1.0, tk.END)
        self.quick_scan_results.insert(tk.END, f"Scanning {target} ports {ports}...\n")
        
        def do_scan():
            result = self.scanner.port_scan(target, ports)
            if result['success']:
                open_ports = result.get('open_ports', [])
                services = result.get('services', [])
                
                self.quick_scan_results.insert(tk.END, 
                    f"\nScan completed in {result.get('scan_duration', 0):.2f}s\n")
                self.quick_scan_results.insert(tk.END, 
                    f"Open ports: {len(open_ports)}\n\n")
                
                for service in services:
                    self.quick_scan_results.insert(tk.END,
                        f"Port {service['port']}: {service['service']}")
                    if service.get('version'):
                        self.quick_scan_results.insert(tk.END, f" ({service['version']})")
                    self.quick_scan_results.insert(tk.END, "\n")
            else:
                self.quick_scan_results.insert(tk.END, 
                    f"Error: {result.get('error', 'Unknown')}\n")
            self.quick_scan_results.see(tk.END)
        
        threading.Thread(target=do_scan, daemon=True).start()
    
    def quick_traceroute(self):
        """Quick traceroute from scanner tab"""
        target = self.quick_scan_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.quick_scan_results.delete(1.0, tk.END)
        self.quick_scan_results.insert(tk.END, f"Traceroute to {target}...\n")
        
        def do_trace():
            result = self.scanner.traceroute(target)
            self.quick_scan_results.insert(tk.END, result + "\n")
            self.quick_scan_results.see(tk.END)
        
        threading.Thread(target=do_trace, daemon=True).start()
    
    def quick_location(self):
        """Quick location lookup from scanner tab"""
        target = self.quick_scan_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.quick_scan_results.delete(1.0, tk.END)
        self.quick_scan_results.insert(tk.END, f"Getting location for {target}...\n")
        
        def do_location():
            result = self.scanner.get_ip_location(target)
            if 'error' in result:
                self.quick_scan_results.insert(tk.END, f"Error: {result['error']}\n")
            else:
                self.quick_scan_results.insert(tk.END, f"Location Information:\n")
                for key, value in result.items():
                    if key != 'service':  # Don't show service field
                        self.quick_scan_results.insert(tk.END, f"  {key.title()}: {value}\n")
            self.quick_scan_results.see(tk.END)
        
        threading.Thread(target=do_location, daemon=True).start()
    
    def start_deep_scan(self):
        """Start deep scan"""
        target = self.deep_scan_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.deep_scan_progress.start()
        self.deep_scan_details.delete(1.0, tk.END)
        self.deep_scan_details.insert(tk.END, f"Starting deep scan on {target}...\n")
        
        def do_deep_scan():
            try:
                result = self.scanner.deep_scan_ip(target)
                
                if result.get('success', False):
                    # Update treeview
                    self.deep_scan_tree.delete(*self.deep_scan_tree.get_children())
                    
                    services = result.get('services', {})
                    for port, service_info in services.items():
                        self.deep_scan_tree.insert('', 'end', values=(
                            port,
                            'tcp',  # Assuming TCP for now
                            service_info.get('name', 'unknown'),
                            service_info.get('version', ''),
                            service_info.get('state', '')
                        ))
                    
                    # Update details
                    self.deep_scan_details.insert(tk.END, 
                        f"\nDeep scan completed in {result.get('scan_duration', 'N/A')}\n")
                    self.deep_scan_details.insert(tk.END,
                        f"Found {len(services)} open ports\n")
                else:
                    self.deep_scan_details.insert(tk.END,
                        f"Error: {result.get('error', 'Unknown')}\n")
                
            finally:
                self.deep_scan_progress.stop()
                self.deep_scan_details.see(tk.END)
        
        threading.Thread(target=do_deep_scan, daemon=True).start()
    
    def start_vuln_scan(self):
        """Start vulnerability scan"""
        target = self.vuln_scan_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target")
            return
        
        self.vuln_scan_results.delete(1.0, tk.END)
        self.vuln_scan_results.insert(tk.END, f"Starting vulnerability scan on {target}...\n")
        
        def do_vuln_scan():
            result = self.scanner.vulnerability_scan(target)
            if result['success']:
                vulns = result.get('vulnerabilities', [])
                self.vuln_scan_results.insert(tk.END,
                    f"\nScan completed in {result.get('scan_duration', 0):.2f}s\n")
                self.vuln_scan_results.insert(tk.END,
                    f"Vulnerabilities found: {len(vulns)}\n\n")
                
                for vuln in vulns[:20]:  # Show first 20
                    self.vuln_scan_results.insert(tk.END, f"• {vuln}\n")
            else:
                self.vuln_scan_results.insert(tk.END,
                    f"Error: {result.get('error', 'Unknown')}\n")
            self.vuln_scan_results.see(tk.END)
        
        threading.Thread(target=do_vuln_scan, daemon=True).start()
    
    def start_traffic(self):
        """Start traffic generation"""
        target = self.traffic_target.get().strip()
        traffic_type = self.traffic_type.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP")
            return
        
        try:
            count = int(self.traffic_count.get())
            delay = float(self.traffic_delay.get()) / 1000
            port = int(self.traffic_port.get())
        except ValueError:
            messagebox.showerror("Error", "Invalid numeric values")
            return
        
        self.traffic_gen.running = True
        self.start_traffic_btn.config(state=tk.DISABLED)
        self.stop_traffic_btn.config(state=tk.NORMAL)
        
        self.traffic_results.delete(1.0, tk.END)
        self.traffic_results.insert(tk.END, f"Starting {traffic_type} traffic to {target}...\n")
        
        def traffic_thread():
            try:
                if traffic_type == "TCP":
                    result = self.traffic_gen.generate_tcp_traffic(
                        target, port, count, delay,
                        spoof_source=self.traffic_spoof.get()
                    )
                elif traffic_type == "UDP":
                    result = self.traffic_gen.generate_udp_traffic(
                        target, port, count, delay,
                        spoof_source=self.traffic_spoof.get()
                    )
                elif traffic_type == "ICMP":
                    result = self.traffic_gen.generate_icmp_traffic(
                        target, count, delay,
                        spoof_source=self.traffic_spoof.get(),
                        flood_mode=self.traffic_flood.get()
                    )
                elif traffic_type == "Mixed":
                    result = self.traffic_gen.generate_mixed_traffic(
                        target, count, "medium"
                    )
                else:
                    result = "❌ Unknown traffic type"
                
                self.traffic_results.insert(tk.END, result + "\n")
                
                # Update stats
                stats = self.traffic_gen.get_traffic_stats()
                self.traffic_stats_text.config(state=tk.NORMAL)
                self.traffic_stats_text.delete(1.0, tk.END)
                self.traffic_stats_text.insert(tk.END,
                    f"TCP: {stats['tcp']} | UDP: {stats['udp']} | ICMP: {stats['icmp']}\n"
                    f"Total Packets: {stats['total_packets']}\n"
                    f"Total Bytes: {stats['total_bytes']}"
                )
                self.traffic_stats_text.config(state=tk.DISABLED)
                
            except Exception as e:
                self.traffic_results.insert(tk.END, f"❌ Error: {str(e)}\n")
            finally:
                self.start_traffic_btn.config(state=tk.NORMAL)
                self.stop_traffic_btn.config(state=tk.DISABLED)
                self.traffic_gen.running = False
        
        thread = threading.Thread(target=traffic_thread, daemon=True)
        thread.start()
    
    def stop_traffic(self):
        """Stop traffic generation"""
        self.traffic_gen.stop_traffic()
        self.traffic_results.insert(tk.END, "Stopping traffic generation...\n")
        self.start_traffic_btn.config(state=tk.NORMAL)
        self.stop_traffic_btn.config(state=tk.DISABLED)
    
    def save_telegram_config(self):
        """Save Telegram configuration"""
        token = self.telegram_token.get().strip()
        chat_id = self.telegram_chat_id.get().strip()
        
        if not token or not chat_id:
            messagebox.showerror("Error", "Please enter both token and chat ID")
            return
        
        if self.telegram_bot.configure(token, chat_id):
            messagebox.showinfo("Success", "Telegram configuration saved successfully")
            self.update_telegram_status()
        else:
            messagebox.showerror("Error", "Failed to configure Telegram. Check your token and chat ID.")
    
    def test_telegram_connection(self):
        """Test Telegram connection"""
        self.telegram_status_text.delete(1.0, tk.END)
        self.telegram_status_text.insert(tk.END, "Testing Telegram connection...\n")
        
        if self.telegram_bot.test_connection():
            self.telegram_status_text.insert(tk.END, "✅ Connection test successful\n")
            if self.telegram_bot.send_message("🔒 Telegram connection test successful!"):
                self.telegram_status_text.insert(tk.END, "✅ Test message sent successfully\n")
            else:
                self.telegram_status_text.insert(tk.END, "⚠️ Could not send test message\n")
        else:
            self.telegram_status_text.insert(tk.END, "❌ Connection test failed\n")
        
        self.telegram_status_text.see(tk.END)
    
    def send_telegram_message(self):
        """Send Telegram message"""
        message = self.telegram_message.get().strip()
        if not message:
            messagebox.showerror("Error", "Please enter a message")
            return
        
        if self.telegram_bot.send_message(message):
            self.telegram_status_text.insert(tk.END, f"✅ Message sent: {message[:50]}...\n")
        else:
            self.telegram_status_text.insert(tk.END, "❌ Failed to send message\n")
        
        self.telegram_status_text.see(tk.END)
        self.telegram_message.delete(0, tk.END)
    
    def send_telegram_alert(self, alert_msg):
        """Send Telegram alert"""
        if self.telegram_bot.send_alert(alert_msg):
            self.telegram_status_text.insert(tk.END, f"✅ Alert sent\n")
        else:
            self.telegram_status_text.insert(tk.END, "❌ Failed to send alert\n")
        self.telegram_status_text.see(tk.END)
    
    def send_telegram_status_request(self):
        """Send status request to Telegram"""
        status_msg = """🖥️ System Status Report
Tool: Accurate Cyber Defense v2.0
Time: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """
Status: Operational
Monitoring: Active
"""
        self.send_telegram_alert(status_msg)
    
    def update_telegram_status(self):
        """Update Telegram status display"""
        self.telegram_status_text.delete(1.0, tk.END)
        
        status = "Telegram Bot Status:\n"
        status += "=" * 30 + "\n"
        status += f"Enabled: {self.telegram_bot.enabled}\n"
        status += f"Token Configured: {'Yes' if self.telegram_bot.token else 'No'}\n"
        status += f"Chat ID Configured: {'Yes' if self.telegram_bot.chat_id else 'No'}\n"
        status += f"Connection: {'Online' if self.telegram_bot.enabled else 'Offline'}\n"
        
        self.telegram_status_text.insert(tk.END, status)
        self.telegram_status_text.see(tk.END)
    
    def execute_terminal_command(self, event=None):
        """Execute terminal command"""
        command = self.terminal_input.get().strip()
        self.terminal_input.delete(0, tk.END)
        
        if not command:
            return
        
        # Add to history
        self.terminal_history.append(command)
        self.terminal_history_index = len(self.terminal_history)
        
        # Display command
        self.terminal_output.config(state='normal')
        self.terminal_output.insert(tk.END, f"> {command}\n")
        
        # Create terminal emulator
        terminal = AdvancedTerminalEmulator(
            self.scanner, 
            self.monitor, 
            self.traffic_gen,
            self.telegram_bot
        )
        
        # Execute command
        result = terminal.execute(command)
        if result:  # Don't show empty results
            self.terminal_output.insert(tk.END, f"{result}\n")
        
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state='disabled')
        
        # Handle exit command
        if command.lower() == 'exit':
            self.root.after(1000, self.root.quit)
    
    def terminal_history_up(self, event):
        """Navigate up in terminal history"""
        if self.terminal_history and self.terminal_history_index > 0:
            self.terminal_history_index -= 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.terminal_history[self.terminal_history_index])
        return "break"
    
    def terminal_history_down(self, event):
        """Navigate down in terminal history"""
        if self.terminal_history and self.terminal_history_index < len(self.terminal_history) - 1:
            self.terminal_history_index += 1
            self.terminal_input.delete(0, tk.END)
            self.terminal_input.insert(0, self.terminal_history[self.terminal_history_index])
        elif self.terminal_history_index == len(self.terminal_history) - 1:
            self.terminal_history_index = len(self.terminal_history)
            self.terminal_input.delete(0, tk.END)
        return "break"
    
    def show_terminal_help(self):
        """Show terminal help"""
        terminal = AdvancedTerminalEmulator(
            self.scanner, 
            self.monitor, 
            self.traffic_gen,
            self.telegram_bot
        )
        help_text = terminal.cmd_help([])
        
        self.terminal_output.config(state='normal')
        self.terminal_output.insert(tk.END, help_text + "\n")
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state='disabled')
    
    def clear_terminal(self):
        """Clear terminal output"""
        self.terminal_output.config(state='normal')
        self.terminal_output.delete(1.0, tk.END)
        self.terminal_output.config(state='disabled')
    
    def show_terminal_history(self):
        """Show terminal command history"""
        self.terminal_output.config(state='normal')
        self.terminal_output.insert(tk.END, "\nCommand History:\n")
        self.terminal_output.insert(tk.END, "-" * 50 + "\n")
        
        for i, cmd in enumerate(self.terminal_history[-20:], 1):
            self.terminal_output.insert(tk.END, f"{i:3}. {cmd}\n")
        
        self.terminal_output.see(tk.END)
        self.terminal_output.config(state='disabled')
    
    def generate_selected_report(self):
        """Generate selected report type"""
        period = self.report_period.get().lower()
        report_type = self.report_type.get()
        
        # Map period to hours
        period_hours = {
            'day': 24,
            'week': 168,
            'month': 720,
            'annual': 8760
        }.get(period, 24)
        
        # Get threat statistics
        threat_stats = self.scanner.db_manager.get_threat_stats(period_hours)
        
        # Generate report based on type
        if report_type == "Threat Report":
            report = self._generate_threat_report(threat_stats, period)
        elif report_type == "Network Report":
            report = self._generate_network_report(period)
        elif report_type == "Security Report":
            report = self._generate_security_report(threat_stats, period)
        elif report_type == "Full Report":
            report = self._generate_full_report(threat_stats, period)
        else:
            report = "Unknown report type"
        
        # Display report
        self.reports_display.delete(1.0, tk.END)
        self.reports_display.insert(tk.END, report)
    
    def _generate_threat_report(self, threat_stats, period):
        """Generate threat report"""
        report = f"THREAT REPORT - {period.upper()}\n"
        report += "=" * 60 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        if threat_stats.get('threat_types'):
            report += "Threat Summary:\n"
            for threat_type, data in threat_stats['threat_types'].items():
                report += f"  {threat_type}: {data['count']} threats (avg severity: {data['avg_severity']:.1f})\n"
        
        if threat_stats.get('top_source_ips'):
            report += "\nTop Source IPs:\n"
            for ip, count in threat_stats['top_source_ips']:
                report += f"  {ip}: {count} threats\n"
        
        if threat_stats.get('hourly_distribution'):
            report += "\nHourly Distribution:\n"
            for hour, count in threat_stats['hourly_distribution']:
                report += f"  {hour}:00 - {count} threats\n"
        
        return report
    
    def _generate_network_report(self, period):
        """Generate network report"""
        report = f"NETWORK REPORT - {period.upper()}\n"
        report += "=" * 60 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Get current monitoring stats
        stats = self.monitor.get_current_stats()
        
        report += "Current Monitoring Status:\n"
        report += f"  Active: {'Yes' if stats['is_monitoring'] else 'No'}\n"
        report += f"  Target: {stats['target_ip'] or 'All traffic'}\n"
        report += f"  Duration: {stats['uptime']:.0f} seconds\n"
        report += f"  Packets Processed: {stats['packets_processed']:,}\n"
        report += f"  Packet Rate: {stats['packet_rate']:.2f}/s\n"
        report += f"  Threats Detected: {stats['threats_detected']:,}\n"
        report += f"  Unique IPs: {stats['unique_ips']:,}\n"
        
        return report
    
    def _generate_security_report(self, threat_stats, period):
        """Generate security report"""
        report = f"SECURITY REPORT - {period.upper()}\n"
        report += "=" * 60 + "\n"
        report += f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Threat summary
        total_threats = sum(data['count'] for data in threat_stats.get('threat_types', {}).values())
        report += f"Total Threats: {total_threats}\n\n"
        
        # Recommendations
        report += "Security Recommendations:\n"
        if total_threats > 50:
            report += "  ⚠️ High threat volume detected. Consider increasing monitoring.\n"
        if threat_stats.get('top_source_ips'):
            report += "  🔍 Investigate top source IPs for potential threats.\n"
        report += "  ✅ Ensure firewall rules are up to date.\n"
        report += "  ✅ Regular vulnerability scanning recommended.\n"
        
        return report
    
    def _generate_full_report(self, threat_stats, period):
        """Generate full comprehensive report"""
        report = f"FULL SECURITY REPORT - {period.upper()}\n"
        report += "=" * 70 + "\n\n"
        
        # Combine all reports
        report += self._generate_threat_report(threat_stats, period) + "\n"
        report += self._generate_network_report(period) + "\n"
        report += self._generate_security_report(threat_stats, period)
        
        # Add system information
        report += "\nSystem Information:\n"
        report += f"  OS: {platform.system()} {platform.release()}\n"
        report += f"  Python: {platform.python_version()}\n"
        report += f"  Tool Version: 2.0.0\n"
        
        return report
    
    def export_report_to_file(self):
        """Export current report to file"""
        report_text = self.reports_display.get(1.0, tk.END).strip()
        if not report_text:
            messagebox.showerror("Error", "No report to export")
            return
        
        filename = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        os.makedirs(REPORT_DIR, exist_ok=True)
        filepath = os.path.join(REPORT_DIR, filename)
        
        with open(filepath, 'w') as f:
            f.write(report_text)
        
        messagebox.showinfo("Success", f"Report exported to:\n{filepath}")
    
    def send_report_to_telegram(self):
        """Send current report to Telegram"""
        if not self.telegram_bot.enabled:
            messagebox.showerror("Error", "Telegram not configured")
            return
        
        report_text = self.reports_display.get(1.0, tk.END).strip()
        if not report_text:
            messagebox.showerror("Error", "No report to send")
            return
        
        # Truncate if too long
        if len(report_text) > 4000:
            report_text = report_text[:4000] + "\n... (truncated)"
        
        if self.telegram_bot.send_message(report_text):
            messagebox.showinfo("Success", "Report sent to Telegram")
        else:
            messagebox.showerror("Error", "Failed to send report to Telegram")
    
    def update_dashboard(self):
        """Update dashboard with current information"""
        # Update threat list
        self.update_threat_list()
        
        # Update statistics
        self.update_statistics()
        
        # Update network stats
        self.update_network_stats()
        
        # Update analytics
        self.update_analytics()
        
        # Schedule next update
        self.root.after(self.update_interval, self.update_dashboard)
    
    def update_threat_list(self):
        """Update the threat list display"""
        # Clear current items
        for item in self.threats_tree.get_children():
            self.threats_tree.delete(item)
        
        # Get recent threats
        threats = self.scanner.db_manager.get_recent_intrusions(20)
        
        # Add threats to treeview with colors based on severity
        for timestamp, source_ip, threat_type, severity, description, action in threats:
            self.threats_tree.insert('', 'end', values=(
                timestamp,
                source_ip,
                threat_type,
                severity,
                action,
                description[:100] + "..." if len(description) > 100 else description
            ))
    
    def update_statistics(self):
        """Update threat statistics"""
        threat_stats = self.scanner.db_manager.get_threat_stats(1)  # Last hour
        
        stats_text = "Threat Statistics (Last Hour):\n"
        stats_text += "-" * 40 + "\n"
        
        if threat_stats.get('threat_types'):
            for threat_type, data in threat_stats['threat_types'].items():
                stats_text += f"{threat_type}: {data['count']} threats\n"
        else:
            stats_text += "No threats detected\n"
        
        # Add monitoring status
        stats = self.monitor.get_current_stats()
        stats_text += f"\nMonitoring Status: {'Active' if stats['is_monitoring'] else 'Inactive'}\n"
        if stats['is_monitoring']:
            stats_text += f"Target: {stats['target_ip'] or 'All traffic'}\n"
            stats_text += f"Threats Detected: {stats['threats_detected']:,}\n"
        
        self.stats_text.delete(1.0, tk.END)
        self.stats_text.insert(tk.END, stats_text)
    
    def update_network_stats(self):
        """Update network statistics display"""
        stats = self.monitor.get_current_stats()
        
        # Update labels with formatted values
        self.stats_labels['packets'].config(text=f"{stats['packets_processed']:,}")
        self.stats_labels['rate'].config(text=f"{stats['packet_rate']:.2f}/s")
        self.stats_labels['tcp'].config(text=f"{stats['tcp_packets']:,}")
        self.stats_labels['udp'].config(text=f"{stats['udp_packets']:,}")
        self.stats_labels['icmp'].config(text=f"{stats['icmp_packets']:,}")
        self.stats_labels['arp'].config(text=f"{stats['arp_packets']:,}")
        self.stats_labels['threats'].config(text=f"{stats['threats_detected']:,}")
        
        # Format bytes
        bytes_text = f"{stats['total_bytes']:,} bytes"
        if stats['total_bytes'] > 1024*1024:
            bytes_text = f"{stats['total_bytes']/(1024*1024):.2f} MB"
        elif stats['total_bytes'] > 1024:
            bytes_text = f"{stats['total_bytes']/1024:.2f} KB"
        self.stats_labels['bytes'].config(text=bytes_text)
        
        # Format uptime
        if stats['uptime'] > 0:
            hours = int(stats['uptime'] // 3600)
            minutes = int((stats['uptime'] % 3600) // 60)
            seconds = int(stats['uptime'] % 60)
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        else:
            uptime_str = "00:00:00"
        self.stats_labels['uptime'].config(text=uptime_str)
        
        # Update other stats
        self.stats_labels['unique_ips'].config(text=f"{stats['unique_ips']:,}")
        self.stats_labels['connections'].config(text=f"{stats['active_connections']:,}")
        
        # Format bandwidth
        bandwidth = stats.get('bandwidth_usage', 0)
        if bandwidth > 1024*1024:
            bandwidth_str = f"{bandwidth/(1024*1024):.2f} MB/s"
        elif bandwidth > 1024:
            bandwidth_str = f"{bandwidth/1024:.2f} KB/s"
        else:
            bandwidth_str = f"{bandwidth:.2f} B/s"
        self.stats_labels['bandwidth'].config(text=bandwidth_str)
        
        # System stats
        self.stats_labels['cpu'].config(text=f"{psutil.cpu_percent()}%")
        memory = psutil.virtual_memory()
        self.stats_labels['memory'].config(text=f"{memory.percent}%")
    
    def update_analytics(self):
        """Update analytics display"""
        # Get threat stats for today
        threat_stats = self.scanner.db_manager.get_threat_stats(24)
        
        # Update labels
        total_threats = sum(data['count'] for data in threat_stats.get('threat_types', {}).values())
        self.analytics_labels['threats_today'].config(text=str(total_threats))
        
        # Find top threat type
        if threat_stats.get('threat_types'):
            top_threat = max(threat_stats['threat_types'].items(), key=lambda x: x[1]['count'], default=(None, {'count': 0}))
            self.analytics_labels['top_threat'].config(text=f"{top_threat[0]} ({top_threat[1]['count']})")
        else:
            self.analytics_labels['top_threat'].config(text="None")
        
        # Find most active IP
        if threat_stats.get('top_source_ips'):
            self.analytics_labels['active_ip'].config(text=threat_stats['top_source_ips'][0][0])
        else:
            self.analytics_labels['active_ip'].config(text="N/A")
        
        # Calculate success rate (placeholder)
        self.analytics_labels['success_rate'].config(text="98%")
    
    def apply_log_filter(self):
        """Apply filter to packet log"""
        # This would filter the packet log based on selected filter
        filter_type = self.log_filter.get()
        self.log_message(f"Applied filter: {filter_type}")
    
    def clear_log(self):
        """Clear packet log"""
        self.packet_log.delete(1.0, tk.END)
        self.log_message("Packet log cleared")
    
    def log_message(self, message: str):
        """Log message to packet log"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        self.packet_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.packet_log.see(tk.END)
    
    def network_ping(self):
        """Network tools: Ping"""
        target = simpledialog.askstring("Ping", "Enter target IP/hostname:")
        if target:
            self.network_tools_results.delete(1.0, tk.END)
            self.network_tools_results.insert(tk.END, f"Pinging {target}...\n")
            
            def do_ping():
                success, result = self.scanner.ping_ip(target)
                self.network_tools_results.insert(tk.END, result + "\n")
            
            threading.Thread(target=do_ping, daemon=True).start()
    
    def network_traceroute(self):
        """Network tools: Traceroute"""
        target = simpledialog.askstring("Traceroute", "Enter target IP/hostname:")
        if target:
            self.network_tools_results.delete(1.0, tk.END)
            self.network_tools_results.insert(tk.END, f"Traceroute to {target}...\n")
            
            def do_trace():
                result = self.scanner.traceroute(target)
                self.network_tools_results.insert(tk.END, result + "\n")
            
            threading.Thread(target=do_trace, daemon=True).start()
    
    def network_dns(self):
        """Network tools: DNS lookup"""
        domain = simpledialog.askstring("DNS Lookup", "Enter domain name:")
        if domain:
            try:
                ip = socket.gethostbyname(domain)
                self.network_tools_results.delete(1.0, tk.END)
                self.network_tools_results.insert(tk.END, f"{domain} → {ip}\n")
            except Exception as e:
                self.network_tools_results.insert(tk.END, f"Error: {str(e)}\n")
    
    def network_whois(self):
        """Network tools: WHOIS lookup"""
        domain = simpledialog.askstring("WHOIS Lookup", "Enter domain name:")
        if domain:
            self.network_tools_results.delete(1.0, tk.END)
            self.network_tools_results.insert(tk.END, f"WHOIS lookup for {domain}...\n")
            
            def do_whois():
                try:
                    result = subprocess.run(['whois', domain], capture_output=True, text=True, timeout=30)
                    output = result.stdout[:1000] + "..." if len(result.stdout) > 1000 else result.stdout
                    self.network_tools_results.insert(tk.END, output + "\n")
                except Exception as e:
                    self.network_tools_results.insert(tk.END, f"Error: {str(e)}\n")
            
            threading.Thread(target=do_whois, daemon=True).start()
    
    def network_port_check(self):
        """Network tools: Port check"""
        target = simpledialog.askstring("Port Check", "Enter target IP:")
        if target:
            port = simpledialog.askinteger("Port Check", "Enter port number:")
            if port:
                self.network_tools_results.delete(1.0, tk.END)
                self.network_tools_results.insert(tk.END, f"Checking port {port} on {target}...\n")
                
                def do_check():
                    try:
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(2)
                        result = sock.connect_ex((target, port))
                        sock.close()
                        if result == 0:
                            self.network_tools_results.insert(tk.END, f"Port {port} is OPEN\n")
                        else:
                            self.network_tools_results.insert(tk.END, f"Port {port} is CLOSED\n")
                    except Exception as e:
                        self.network_tools_results.insert(tk.END, f"Error: {str(e)}\n")
                
                threading.Thread(target=do_check, daemon=True).start()
    
    def network_speed_test(self):
        """Network tools: Speed test (placeholder)"""
        self.network_tools_results.delete(1.0, tk.END)
        self.network_tools_results.insert(tk.END, "Speed test feature coming soon...\n")
    
    def network_interface_info(self):
        """Network tools: Interface information"""
        self.network_tools_results.delete(1.0, tk.END)
        
        try:
            if platform.system() == "Windows":
                result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True)
            else:
                result = subprocess.run(['ifconfig'], capture_output=True, text=True)
            
            output = result.stdout if result.stdout else result.stderr
            self.network_tools_results.insert(tk.END, output[:2000] + "\n")
        except Exception as e:
            self.network_tools_results.insert(tk.END, f"Error: {str(e)}\n")
    
    def network_connection_test(self):
        """Network tools: Connection test"""
        self.network_tools_results.delete(1.0, tk.END)
        self.network_tools_results.insert(tk.END, "Testing connections...\n")
        
        # Test common services
        test_targets = [
            ("Google DNS", "8.8.8.8", 53),
            ("Google", "8.8.8.8", 80),
            ("Cloudflare", "1.1.1.1", 443)
        ]
        
        for name, ip, port in test_targets:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    self.network_tools_results.insert(tk.END, f"✅ {name}: Connected\n")
                else:
                    self.network_tools_results.insert(tk.END, f"❌ {name}: Failed\n")
            except:
                self.network_tools_results.insert(tk.END, f"❌ {name}: Error\n")
    
    def new_session(self):
        """Create new session"""
        if messagebox.askyesno("New Session", "Start a new monitoring session?"):
            self.monitor.stop_monitoring()
            self.monitor_ip_entry.delete(0, tk.END)
            self.log_message("New session started")
    
    def save_session(self):
        """Save current session"""
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                session_data = {
                    'target_ip': self.monitor_ip_entry.get(),
                    'scan_target': self.quick_scan_target.get(),
                    'port_range': self.quick_scan_ports.get(),
                    'telegram_token': self.telegram_token.get(),
                    'telegram_chat_id': self.telegram_chat_id.get(),
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(file_path, 'w') as f:
                    json.dump(session_data, f, indent=4)
                
                self.log_message(f"Session saved to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save session: {str(e)}")
    
    def load_session(self):
        """Load saved session"""
        file_path = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    session_data = json.load(f)
                
                self.monitor_ip_entry.delete(0, tk.END)
                self.monitor_ip_entry.insert(0, session_data.get('target_ip', ''))
                
                self.quick_scan_target.delete(0, tk.END)
                self.quick_scan_target.insert(0, session_data.get('scan_target', ''))
                
                self.quick_scan_ports.delete(0, tk.END)
                self.quick_scan_ports.insert(0, session_data.get('port_range', '1-1000'))
                
                self.telegram_token.delete(0, tk.END)
                self.telegram_token.insert(0, session_data.get('telegram_token', ''))
                
                self.telegram_chat_id.delete(0, tk.END)
                self.telegram_chat_id.insert(0, session_data.get('telegram_chat_id', ''))
                
                self.log_message(f"Session loaded from {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load session: {str(e)}")
    
    def export_data(self):
        """Export data to file"""
        try:
            conn = sqlite3.connect(DATABASE_FILE)
            cursor = conn.cursor()
            
            tables = ['threat_logs', 'intrusion_detection', 'scan_results', 'network_stats']
            export_data = {}
            
            for table in tables:
                cursor.execute(f"SELECT * FROM {table}")
                rows = cursor.fetchall()
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [col[1] for col in cursor.fetchall()]
                
                export_data[table] = []
                for row in rows:
                    export_data[table].append(dict(zip(columns, row)))
            
            conn.close()
            
            # Save to file
            filename = f"export_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            messagebox.showinfo("Success", f"Data exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export data: {str(e)}")
    
    def export_report(self):
        """Export report"""
        self.export_report_to_file()
    
    def quick_scan(self):
        """Quick scan menu command"""
        self.notebook.select(self.scanner_tab)  # Select scanner tab
        # Auto-select quick scan tab within scanner tab
        scanner_notebook = self.scanner_tab.winfo_children()[0]
        if isinstance(scanner_notebook, ttk.Notebook):
            scanner_notebook.select(0)  # Select first tab (quick scan)
    
    def deep_scan(self):
        """Deep scan menu command"""
        self.notebook.select(self.scanner_tab)
        scanner_notebook = self.scanner_tab.winfo_children()[0]
        if isinstance(scanner_notebook, ttk.Notebook):
            scanner_notebook.select(1)  # Select second tab (deep scan)
    
    def vulnerability_scan(self):
        """Vulnerability scan menu command"""
        self.notebook.select(self.scanner_tab)
        scanner_notebook = self.scanner_tab.winfo_children()[0]
        if isinstance(scanner_notebook, ttk.Notebook):
            scanner_notebook.select(2)  # Select third tab (vulnerability scan)
    
    def traffic_analysis(self):
        """Traffic analysis menu command"""
        self.notebook.select(self.traffic_tab)
    
    def ip_location_lookup(self):
        """IP location lookup menu command"""
        ip = simpledialog.askstring("IP Location", "Enter IP address:")
        if ip:
            result = self.scanner.get_ip_location(ip)
            if 'error' in result:
                messagebox.showerror("Error", result['error'])
            else:
                info = "\n".join([f"{k.title()}: {v}" for k, v in result.items() if k != 'service'])
                messagebox.showinfo("Location Information", info)
    
    def whois_lookup(self):
        """WHOIS lookup menu command"""
        self.network_whois()
    
    def add_ip_to_monitor(self):
        """Add IP to monitor menu command"""
        ip = simpledialog.askstring("Add IP to Monitor", "Enter IP address to monitor:")
        if ip and self.validate_ip(ip):
            self.monitor_ip_entry.delete(0, tk.END)
            self.monitor_ip_entry.insert(0, ip)
            messagebox.showinfo("Success", f"Added {ip} to monitoring target")
        elif ip:
            messagebox.showerror("Error", "Invalid IP address")
    
    def view_monitored_ips(self):
        """View monitored IPs menu command"""
        # This would show a list of monitored IPs from database
        messagebox.showinfo("Monitored IPs", "Feature coming soon")
    
    def configure_telegram(self):
        """Configure Telegram menu command"""
        self.notebook.select(self.telegram_tab)
    
    def test_telegram(self):
        """Test Telegram menu command"""
        self.test_telegram_connection()
    
    def send_test_message(self):
        """Send test message menu command"""
        self.send_telegram_alert("Test alert from menu")
    
    def toggle_alerts(self):
        """Toggle alerts menu command"""
        # This would toggle alert notifications
        messagebox.showinfo("Toggle Alerts", "Feature coming soon")
    
    def clear_alerts(self):
        """Clear alerts"""
        if messagebox.askyesno("Clear Alerts", "Clear all threat alerts?"):
            # Clear threat list
            for item in self.threats_tree.get_children():
                self.threats_tree.delete(item)
            self.threat_details.delete(1.0, tk.END)
            self.log_message("Threat alerts cleared")
    
    def generate_report(self, period):
        """Generate report with specified period"""
        self.report_period.set(period.capitalize())
        self.generate_selected_report()
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

def print_banner():
    """Print enhanced banner"""
    banner = f"""
{Colors.GREEN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║          🛡️  ACCURATE CYBER DEFENSE v2.0 - INTEGRATED PLATFORM          ║
║                                                                          ║
║      Network Security • Threat Detection • Traffic Analysis • Scanning   ║
║       Intrusion Prevention • Telegram Integration • Advanced Monitoring  ║
║                                                                          ║
║   Version: 2.0.0                      Author: Ian Carter Kulani          ║
║   Community: https://github.com/Accurate-Cyber-Defense                   ║
║                                                                          ║
║   Enhanced Features:                                                     ║
║   • Advanced Network Monitoring & Threat Detection                       ║
║   • Comprehensive Port & Vulnerability Scanning                          ║
║   • Traffic Generation & Analysis Tools                                  ║
║   • Telegram Bot Integration for Alerts & Control                        ║
║   • Enhanced Database with IP Reputation Tracking                        ║
║   • CLI & GUI Interfaces with Real-time Analytics                        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

def cli_mode():
    """Run in enhanced CLI mode"""
    # Initialize components
    db_manager = EnhancedDatabaseManager()
    network_scanner = AdvancedNetworkScanner(db_manager)
    network_monitor = EnhancedNetworkMonitor(db_manager)
    traffic_generator = AdvancedTrafficGenerator(db_manager)
    telegram_bot = TelegramBot(db_manager)
    
    # Create terminal emulator
    terminal = AdvancedTerminalEmulator(network_scanner, network_monitor, traffic_generator, telegram_bot)
    
    print_banner()
    print(f"\n{Colors.GREEN}🔧 Enhanced CLI Mode Activated{Colors.END}")
    print(f"{Colors.YELLOW}Type 'help' for available commands{Colors.END}")
    print(f"{Colors.YELLOW}Type 'gui' to switch to GUI mode{Colors.END}")
    print(f"{Colors.YELLOW}Type 'exit' to quit{Colors.END}\n")
    
    # Start Telegram polling in background
    if telegram_bot.enabled:
        telegram_thread = threading.Thread(target=telegram_bot.start_polling, daemon=True)
        telegram_thread.start()
        print(f"{Colors.GREEN}✓ Telegram bot started{Colors.END}")
    
    while True:
        try:
            command = input(f"{Colors.GREEN}cyberdefense>{Colors.END} ").strip()
            
            if not command:
                continue
            
            if command.lower() == 'exit':
                print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                network_monitor.stop_monitoring()
                traffic_generator.stop_traffic()
                telegram_bot.stop_polling()
                break
            
            elif command.lower() == 'gui':
                print(f"{Colors.CYAN}🚀 Switching to GUI mode...{Colors.END}")
                return 'gui'
            
            elif command.lower() == 'menu':
                print_banner()
                print(f"\n{Colors.CYAN}Available modes:{Colors.END}")
                print("  1. CLI Mode (current)")
                print("  2. GUI Mode")
                print("  3. Exit")
                
                choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
                if choice == '2':
                    return 'gui'
                elif choice == '3':
                    print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                    network_monitor.stop_monitoring()
                    traffic_generator.stop_traffic()
                    telegram_bot.stop_polling()
                    break
            
            else:
                result = terminal.execute(command)
                if result == "EXIT":
                    print(f"{Colors.YELLOW}👋 Exiting...{Colors.END}")
                    network_monitor.stop_monitoring()
                    traffic_generator.stop_traffic()
                    telegram_bot.stop_polling()
                    break
                elif result:
                    print(result)
        
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}👋 Exiting...{Colors.END}")
            network_monitor.stop_monitoring()
            traffic_generator.stop_traffic()
            telegram_bot.stop_polling()
            break
        except Exception as e:
            print(f"{Colors.RED}❌ Error: {e}{Colors.END}")

def gui_mode():
    """Run in enhanced GUI mode"""
    if not GUI_AVAILABLE:
        print(f"{Colors.RED}❌ GUI mode requires tkinter. Please install it or use CLI mode.{Colors.END}")
        print("On Ubuntu/Debian: sudo apt-get install python3-tk")
        print("On Fedora/RHEL: sudo dnf install python3-tkinter")
        print("On macOS: brew install python-tk")
        print("On Windows: Usually included with Python")
        return 'cli'
    
    try:
        # Initialize components
        db_manager = EnhancedDatabaseManager()
        network_monitor = EnhancedNetworkMonitor(db_manager)
        network_scanner = AdvancedNetworkScanner(db_manager)
        traffic_generator = AdvancedTrafficGenerator(db_manager)
        telegram_bot = TelegramBot(db_manager)
        
        # Create main window
        root = tk.Tk()
        root.title("Accurate Cyber Defense v2.0 - Integrated Security Platform")
        root.geometry("1400x900")
        
        # Create application
        app = EnhancedCyberSecurityDashboard(
            root, 
            db_manager, 
            network_monitor, 
            network_scanner,
            traffic_generator,
            telegram_bot
        )
        
        # Handle window close
        def on_closing():
            network_monitor.stop_monitoring()
            traffic_generator.stop_traffic()
            telegram_bot.stop_polling()
            root.quit()
            root.destroy()
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        root.mainloop()
        
        return 'menu'
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to start GUI: {str(e)}")
        print(f"{Colors.RED}GUI Error: {e}{Colors.END}")
        return 'cli'

def main():
    """Main entry point"""
    print_banner()
    
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == '--cli':
            mode = 'cli'
        elif sys.argv[1] == '--gui':
            mode = 'gui'
        else:
            print(f"{Colors.RED}Unknown argument: {sys.argv[1]}{Colors.END}")
            print(f"{Colors.YELLOW}Usage: python enhanced_cyber_tool.py [--cli|--gui]{Colors.END}")
            mode = 'menu'
    else:
        # Interactive mode selection
        print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
        print("  1. CLI Mode (Command Line Interface)")
        print("  2. GUI Mode (Graphical User Interface)")
        print("  3. Exit")
        
        while True:
            choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
            if choice == '1':
                mode = 'cli'
                break
            elif choice == '2':
                mode = 'gui'
                break
            elif choice == '3':
                print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                return
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
    
    # Run selected mode
    while True:
        if mode == 'cli':
            mode = cli_mode()
        elif mode == 'gui':
            mode = gui_mode()
        elif mode == 'menu':
            print(f"\n{Colors.CYAN}Select mode:{Colors.END}")
            print("  1. CLI Mode (Command Line Interface)")
            print("  2. GUI Mode (Graphical User Interface)")
            print("  3. Exit")
            
            choice = input(f"\n{Colors.GREEN}Select mode (1-3):{Colors.END} ").strip()
            if choice == '1':
                mode = 'cli'
            elif choice == '2':
                mode = 'gui'
            elif choice == '3':
                print(f"{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
                break
            else:
                print(f"{Colors.RED}Invalid choice. Please enter 1, 2, or 3.{Colors.END}")
        else:
            break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}👋 Thank you for using Accurate Cyber Defense!{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}❌ Application error: {e}{Colors.END}")
        import traceback
        traceback.print_exc()