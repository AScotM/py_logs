#!/usr/bin/env python3

import os
import re
import logging
from datetime import datetime
from collections import defaultdict

# Change this based on your system (e.g. /var/log/syslog for Debian/Ubuntu)
SYSLOG_PATHS = [
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
    def __init__(self):
        self.entries = []
        self.tree = defaultdict(lambda: defaultdict(list))
        self.log_file = self._find_log_file()

    def _find_log_file(self):
        for path in SYSLOG_PATHS:
            if os.path.exists(path):
                logging.info(f"Using log file: {path}")
                return path
        logging.error("No standard syslog file found.")
        return None

    def load_logs(self):
        if not self.log_file:
            return

        log_pattern = re.compile(
            r'^(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[\d+\])?:\s(?P<message>.+)$'
        )

        try:
            with open(self.log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    match = log_pattern.match(line)
                    if match:
                        ts_str = f"{match.group('month')} {match.group('day')} {match.group('time')}"
                        try:
                            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=datetime.now().year)
                        except ValueError:
                            continue
                        service = match.group('service')
                        message = match.group('message')
                        self.entries.append(LogEntry(ts, service, message))
        except Exception as e:
            logging.error(f"Failed to read log file: {e}")

    def build_tree(self):
        for entry in self.entries:
            date_key = entry.timestamp.strftime("%Y-%m-%d")
            self.tree[date_key][entry.service].append(entry)

    def display_tree(self):
        if not self.tree:
            logging.info("No logs to display.")
            return

        for date, services in self.tree.items():
            print(f"📅 {date}")
            for service, logs in services.items():
                print(f"├── {service}")
                for log in logs[:5]:  # Only show first 5 messages per service
                    print(f"│   └── [{log.timestamp.strftime('%H:%M:%S')}] {log.message[:80]}")
            print()

if __name__ == "__main__":
    analyzer = RSyslogAnalyzer()
    analyzer.load_logs()
    analyzer.build_tree()
    analyzer.display_tree()
