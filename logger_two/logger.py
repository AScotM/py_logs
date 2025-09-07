#!/usr/bin/env python3

import os
import re
import logging
import textwrap
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass
import argparse

try:
    from rich.console import Console
    from rich.text import Text
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

DEFAULT_SYSLOG_PATHS = [
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/system.log"
]

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

@dataclass
class LogEntry:
    timestamp: datetime
    service: str
    message: str

class RSyslogAnalyzer:
    def __init__(self, log_file=None, max_days=30, truncate_length=80,
                 show_full_lines=False, wrap_lines=False,
                 max_lines_per_service=5, color_output=True):
        self.tree = defaultdict(lambda: defaultdict(list))
        self.log_file = log_file or self._find_log_file()
        self.max_days = max_days
        self.truncate_length = truncate_length
        self.show_full_lines = show_full_lines
        self.wrap_lines = wrap_lines
        self.max_lines_per_service = max_lines_per_service
        self.color_output = color_output and RICH_AVAILABLE

        # Precompile regex patterns
        self.patterns = [
            re.compile(
                r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
                r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)"
                r"(?:\[\d+\])?:\s(?P<message>.+)$"
            ),
            re.compile(
                r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s"
                r"(?P<message>.+)$"
            ),
            re.compile(
                r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s"
                r"\[(?P<level>[A-Z]+)\]\s(?P<message>.+)$"
            ),
        ]

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

        now = datetime.now()
        current_year = now.year
        cutoff_date = now - timedelta(days=self.max_days)

        try:
            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    for pattern in self.patterns:
                        match = pattern.match(line)
                        if not match:
                            continue
                        ts_str = f"{match.group('month')} {match.group('day')} {match.group('time')}"
                        try:
                            ts = datetime.strptime(ts_str, "%b %d %H:%M:%S").replace(year=current_year)
                            if ts > now:
                                ts = ts.replace(year=current_year - 1)
                            if ts < cutoff_date:
                                break
                            service = match.group("service")
                            message = match.group("message").strip()
                            date_key = ts.strftime("%Y-%m-%d")
                            self.tree[date_key][service].append(LogEntry(ts, service, message))
                        except ValueError:
                            pass
                        break
        except FileNotFoundError:
            logging.error(f"Log file not found: {self.log_file}")
        except PermissionError:
            logging.error(f"Permission denied accessing log file: {self.log_file}")
        except IOError as e:
            logging.error(f"Failed to read log file: {e}")

    def build_tree(self):
        for date_key, services in self.tree.items():
            for service, logs in services.items():
                services[service] = sorted(logs, key=lambda x: x.timestamp)

    def display_tree(self):
        if not self.tree:
            logging.info("No logs to display.")
            return

        for date in sorted(self.tree.keys()):
            self._print_line(f" {date}", style="bold yellow")
            services = self.tree[date]
            for service in sorted(services.keys()):
                self._print_line(f"├── {service}", style="bold cyan")
                logs = services[service]
                for log in logs[:self.max_lines_per_service]:
                    timestamp = log.timestamp.strftime("%H:%M:%S")
                    if self.show_full_lines:
                        lines = [log.message]
                        truncation = ""
                    elif self.wrap_lines:
                        indent = "│       "
                        first_line_prefix = f"│   └── [{timestamp}] "
                        wrap_width = self.truncate_length - len(first_line_prefix)
                        if wrap_width < 20:
                            wrap_width = 20
                        lines = textwrap.wrap(log.message, width=wrap_width)
                        truncation = ""
                    else:
                        lines = [log.message[:self.truncate_length]]
                        truncation = "..." if len(log.message) > self.truncate_length else ""

                    self._print_line(
                        f"│   └── [{timestamp}] {lines[0]}{truncation}",
                        style="white"
                    )
                    if self.wrap_lines and len(lines) > 1:
                        for line in lines[1:]:
                            self._print_line(f"│       {line}", style="dim")

                if len(logs) > self.max_lines_per_service:
                    self._print_line(
                        f"│   └── ... ({len(logs) - self.max_lines_per_service} more logs)",
                        style="dim"
                    )
        print()

    def _print_line(self, text, style=None):
        if self.color_output and style:
            console.print(Text(text, style=style))
        else:
            print(text)

def parse_arguments():
    parser = argparse.ArgumentParser(description="Analyze and display syslog entries in a tree structure.")
    parser.add_argument("--log-file", type=str, help="Path to the syslog file (overrides default search).")
    parser.add_argument("--max-days", type=int, default=30, help="Maximum days of logs to keep (default: 30).")
    parser.add_argument("--truncate-length", type=int, default=80, help="Length to truncate messages (default: 80).")
    parser.add_argument("--show-full-lines", action="store_true", help="Show full log messages without truncation.")
    parser.add_argument("--wrap-lines", action="store_true", help="Wrap long messages across lines.")
    parser.add_argument("--max-lines-per-service", type=int, default=5, help="Maximum lines to show per service (default: 5).")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output.")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    analyzer = RSyslogAnalyzer(
        log_file=args.log_file,
        max_days=args.max_days,
        truncate_length=args.truncate_length,
        show_full_lines=args.show_full_lines,
        wrap_lines=args.wrap_lines,
        max_lines_per_service=args.max_lines_per_service,
        color_output=not args.no_color
    )
    analyzer.load_logs()
    analyzer.build_tree()
    analyzer.display_tree()
