#!/usr/bin/env python3

import os
import re
import logging
import textwrap
from datetime import datetime, timedelta
from collections import defaultdict
import argparse

# Default syslog paths
DEFAULT_SYSLOG_PATHS = [
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/system.log"
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
    def __init__(self, log_file=None, max_days=30, truncate_length=80, show_full_lines=False, wrap_lines=False, max_lines_per_service=5):
        self.tree = defaultdict(lambda: defaultdict(list))
        self.log_file = log_file or self._find_log_file()
        self.max_days = max_days
        self.truncate_length = truncate_length
        self.show_full_lines = show_full_lines
        self.wrap_lines = wrap_lines
        self.max_lines_per_service = max_lines_per_service

    def _find_log_file(self):
        for path in DEFAULT_SYSLOG_PATHS:
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

        current_year = datetime.now().year
        cutoff_date = datetime.now() - timedelta(days=self.max_days)

        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    for pattern in patterns:
                        match = re.match(pattern, line.strip())
                        if match:
                            ts_str = f"{match.group('month')} {match.group('day')} {match.group('time')}"
                            try:
                                # Parse timestamp with current year
                                ts = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=current_year)
                                # Adjust year if timestamp is in the future (e.g., logs from Dec when it's Jan)
                                if ts > datetime.now():
                                    ts = ts.replace(year=current_year - 1)
                                # Skip if older than cutoff to save memory
                                if ts < cutoff_date:
                                    continue
                                service = match.group('service')
                                message = match.group('message').strip()
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
        # Sort logs within each service by timestamp
        for date_key, services in self.tree.items():
            for service, logs in services.items():
                services[service] = sorted(logs, key=lambda x: x.timestamp)

    def display_tree(self):
        if not self.tree:
            logging.info("No logs to display.")
            return

        for date in sorted(self.tree.keys()):
            print(f" {date}")
            services = self.tree[date]
            for service in sorted(services.keys()):
                print(f"├── {service}")
                logs = services[service]
                for log in logs[:self.max_lines_per_service]:
                    timestamp = log.timestamp.strftime('%H:%M:%S')
                    if self.show_full_lines:
                        msg = log.message
                        lines = [msg]
                        truncation = ''
                    elif self.wrap_lines:
                        indent = "│       "
                        first_line_prefix = f"│   └── [{timestamp}] "
                        wrap_width = self.truncate_length - len(first_line_prefix)
                        if wrap_width < 20:
                            wrap_width = 20
                        lines = textwrap.wrap(log.message, width=wrap_width)
                        truncation = ''
                    else:
                        msg = log.message[:self.truncate_length]
                        lines = [msg]
                        truncation = '...' if len(log.message) > self.truncate_length else ''
                    
                    # Print first line with timestamp
                    print(f"│   └── [{timestamp}] {lines[0]}{truncation}")
                    # Print subsequent wrapped lines
                    if self.wrap_lines and len(lines) > 1:
                        for line in lines[1:]:
                            print(f"│       {line}")
                if len(logs) > self.max_lines_per_service:
                    print(f"│   └── ... ({len(logs) - self.max_lines_per_service} more logs)")
        print()

def parse_arguments():
    parser = argparse.ArgumentParser(description="Analyze and display syslog entries in a tree structure.")
    parser.add_argument('--log-file', type=str, help="Path to the syslog file (overrides default search).")
    parser.add_argument('--max-days', type=int, default=30, help="Maximum days of logs to keep (default: 30).")
    parser.add_argument('--truncate-length', type=int, default=80, help="Length to truncate messages (default: 80).")
    parser.add_argument('--show-full-lines', action='store_true', help="Show full log messages without truncation.")
    parser.add_argument('--wrap-lines', action='store_true', help="Wrap long messages across lines.")
    parser.add_argument('--max-lines-per-service', type=int, default=5, help="Maximum lines to show per service (default: 5).")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    analyzer = RSyslogAnalyzer(
        log_file=args.log_file,
        max_days=args.max_days,
        truncate_length=args.truncate_length,
        show_full_lines=args.show_full_lines,
        wrap_lines=args.wrap_lines,
        max_lines_per_service=args.max_lines_per_service
    )
    analyzer.load_logs()
    analyzer.build_tree()
    analyzer.display_tree()
