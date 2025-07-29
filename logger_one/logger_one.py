#!/usr/bin/env python3

import os
import re
import logging
import textwrap
from datetime import datetime, timedelta
from collections import defaultdict

# Validate syslog paths
SYSLOG_PATHS = [
    path for path in [
        "/var/log/messages",
        "/var/log/syslog",
        "/var/log/system.log"
    ] if isinstance(path, str) and path.strip()
]

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class LogEntry:
    def __init__(self, timestamp, service, message):
        self.timestamp = timestamp
        self.service = service
        self.message = message

class RSyslogAnalyzer:
    def __init__(self, truncate_length=80, show_full_lines=False, wrap_lines=False):
        self.tree = defaultdict(lambda: defaultdict(list))
        self.log_file = self._find_log_file()
        self.truncate_length = truncate_length
        self.show_full_lines = show_full_lines
        self.wrap_lines = wrap_lines

    def _find_log_file(self):
        for path in SYSLOG_PATHS:
            if os.path.exists(path) and os.access(path, os.R_OK):
                logging.info(f"Using log file: {path}")
                return path
        logging.error("No standard syslog file found or insufficient permissions.")
        return None

    def load_logs(self):
        if not self.log_file:
            return

        # More flexible patterns to handle various syslog formats
        patterns = [
            r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[\d+\])?:\s(?P<message>.+)$',
            r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s(?P<message>.+)$',
            r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s\[(?P<level>[A-Z]+)\]\s(?P<message>.+)$'
        ]

        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    for pattern in patterns:
                        match = re.match(pattern, line)
                        if match:
                            ts_str = f"{match.group('month')} {match.group('day')} {match.group('time')}"
                            try:
                                # Parse timestamp and set current year
                                ts = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=datetime.now().year)
                                service = match.group('service')
                                message = match.group('message')
                                # Directly build tree to save memory
                                date_key = ts.strftime("%Y-%m-%d")
                                self.tree[date_key][service].append(LogEntry(ts, service, message))
                            except ValueError:
                                continue
                            break
        except FileNotFoundError:
            logging.error(f"Log file not found: {self.log_file}")
        except PermissionError:
            logging.error(f"Permission denied accessing log file: {self.log_file}")
        except IOError as e:
            logging.error(f"Failed to read log file: {e}")

    def build_tree(self):
        # Keep only last 30 days to manage memory
        max_days = 30
        cutoff_date = datetime.now().replace(year=datetime.now().year) - timedelta(days=max_days)
        # Create a new tree with filtered entries
        filtered_tree = defaultdict(lambda: defaultdict(list))
        for date_key, services in self.tree.items():
            try:
                date = datetime.strptime(date_key, "%Y-%m-%d")
                if date >= cutoff_date:
                    filtered_tree[date_key] = services
            except ValueError:
                continue
        self.tree = filtered_tree

    def display_tree(self):
        if not self.tree:
            logging.info("No logs to display.")
            return

        for date, services in sorted(self.tree.items()):
            print(f" {date}")
            for service, logs in sorted(services.items()):
                print(f"├── {service}")
                for log in logs[:5]:  # Show first 5 messages per service
                    timestamp = log.timestamp.strftime('%H:%M:%S')
                    if self.show_full_lines:
                        msg = log.message
                        lines = [msg]
                        truncation = ''
                    elif self.wrap_lines:
                        # Wrap lines to truncate_length, accounting for indentation
                        indent = "│       "
                        first_line_prefix = f"│   └── [{timestamp}] "
                        wrap_width = self.truncate_length - len(first_line_prefix)
                        if wrap_width < 20:  # Ensure reasonable wrap width
                            wrap_width = 20
                        lines = textwrap.wrap(log.message, width=wrap_width)
                        truncation = ''
                    else:
                        msg = log.message[:self.truncate_length]
                        lines = [msg]
                        truncation = '...' if len(log.message) > self.truncate_length else ''
                    
                    # Print first line with timestamp
                    print(f"│   └── [{timestamp}] {lines[0]}{truncation}")
                    # Print subsequent wrapped lines with proper indentation
                    if self.wrap_lines and len(lines) > 1:
                        for line in lines[1:]:
                            print(f"│       {line}")
        print()

if __name__ == "__main__":
    # Initialize with line wrapping enabled
    analyzer = RSyslogAnalyzer(truncate_length=80, show_full_lines=False, wrap_lines=True)
    analyzer.load_logs()
    analyzer.build_tree()
    analyzer.display_tree()
