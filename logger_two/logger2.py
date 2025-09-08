#!/usr/bin/env python3

import os
import re
import logging
import textwrap
from datetime import datetime, timedelta
from collections import defaultdict
from dataclasses import dataclass
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Pattern

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
    "/var/log/system.log",
    "/var/log/auth.log"
]

# Common month abbreviations for pre-check
MONTHS = {'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

@dataclass
class LogEntry:
    timestamp: datetime
    service: str
    message: str
    level: Optional[str] = None
    host: Optional[str] = None

class RSyslogAnalyzer:
    def __init__(self, log_file: Optional[str] = None, max_days: int = 30, 
                 truncate_length: int = 80, show_full_lines: bool = False, 
                 wrap_lines: bool = False, max_lines_per_service: int = 5, 
                 color_output: bool = True, verbose: bool = False):
        self.tree: Dict[str, Dict[str, List[LogEntry]]] = defaultdict(lambda: defaultdict(list))
        self.log_file = log_file or self._find_log_file()
        self.max_days = max_days
        self.truncate_length = truncate_length
        self.show_full_lines = show_full_lines
        self.wrap_lines = wrap_lines
        self.max_lines_per_service = max_lines_per_service
        self.color_output = color_output and RICH_AVAILABLE
        self.verbose = verbose
        self.current_year = datetime.now().year
        self.last_month = None

        # Precompile regex patterns
        self.patterns: List[Pattern] = [
            re.compile(
                r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
                r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)"
                r"(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$"
            ),
            re.compile(
                r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*"
                r"(?P<message>.+)$"
            ),
            re.compile(
                r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
                r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*"
                r"\[(?P<level>[A-Z]+)\]\s*(?P<message>.+)$"
            ),
            re.compile(
                r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
                r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[(?P<pid>\d+)\])?:\s*"
                r"(?P<message>.+)$"
            )
        ]

    def _find_log_file(self) -> Optional[str]:
        """Find the appropriate syslog file from default locations."""
        for path in DEFAULT_SYSLOG_PATHS:
            path_obj = Path(path)
            if path_obj.exists() and os.access(path, os.R_OK):
                logging.info(f"Using log file: {path}")
                return str(path)
        
        # Check for rotated logs
        for path in DEFAULT_SYSLOG_PATHS:
            for rotated in [f"{path}.1", f"{path}.0", f"{path}.gz", f"{path}.1.gz"]:
                if Path(rotated).exists() and os.access(rotated, os.R_OK):
                    logging.info(f"Using rotated log file: {rotated}")
                    return rotated
        
        logging.error("No standard syslog file found or insufficient permissions.")
        return None

    def _adjust_year_based_on_month(self, month: str, current_month: Optional[str]) -> int:
        """Adjust year based on month transitions to handle year boundaries."""
        if current_month is None:
            return self.current_year
        
        month_num = {'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
                     'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12}
        
        current_month_num = month_num.get(current_month, 12)
        new_month_num = month_num.get(month, 1)
        
        # If we're in January and see December logs, it's from previous year
        if current_month_num == 1 and new_month_num == 12:
            return self.current_year - 1
        # If we're in December and see January logs, it's from next year
        elif current_month_num == 12 and new_month_num == 1:
            return self.current_year + 1
        
        return self.current_year

    def _parse_iso_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse ISO 8601 timestamps."""
        try:
            # Try with timezone first, then without
            for fmt in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", 
                       "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]:
                try:
                    return datetime.strptime(ts_str, fmt)
                except ValueError:
                    continue
        except ValueError:
            pass
        return None

    def load_logs(self):
        """Load and parse log files with improved year handling."""
        if not self.log_file:
            return

        now = datetime.now()
        cutoff_date = now - timedelta(days=self.max_days)
        line_count = 0
        parsed_count = 0

        try:
            with open(self.log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    line_count += 1
                    
                    # Quick pre-check to skip non-log lines
                    if not line or len(line) < 20 or line[:3] not in MONTHS:
                        continue
                    
                    entry = self._parse_log_line(line, now, cutoff_date)
                    if entry:
                        parsed_count += 1
                        date_key = entry.timestamp.strftime("%Y-%m-%d")
                        self.tree[date_key][entry.service].append(entry)

            if self.verbose:
                logging.info(f"Processed {line_count} lines, parsed {parsed_count} entries")

        except FileNotFoundError:
            logging.error(f"Log file not found: {self.log_file}")
        except PermissionError:
            logging.error(f"Permission denied accessing log file: {self.log_file}")
        except IOError as e:
            logging.error(f"Failed to read log file: {e}")

    def _parse_log_line(self, line: str, now: datetime, cutoff_date: datetime) -> Optional[LogEntry]:
        """Parse a single log line with improved timestamp handling."""
        for pattern in self.patterns:
            match = pattern.match(line)
            if not match:
                continue
            
            try:
                group_dict = match.groupdict()
                
                # Handle ISO timestamp format
                if 'timestamp' in group_dict and group_dict['timestamp']:
                    ts = self._parse_iso_timestamp(group_dict['timestamp'])
                    if not ts:
                        continue
                else:
                    # Traditional syslog format
                    month = group_dict['month']
                    day = group_dict['day']
                    time_str = group_dict['time']
                    
                    # Adjust year based on month transitions
                    year = self._adjust_year_based_on_month(month, self.last_month)
                    self.last_month = month
                    
                    ts_str = f"{year} {month} {day} {time_str}"
                    ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                    
                    # Handle microseconds if present
                    if '.' in time_str:
                        ts = ts.replace(microsecond=int(time_str.split('.')[1].ljust(6, '0')[:6]))

                # Skip if outside date range
                if ts < cutoff_date or ts > now + timedelta(days=1):  # Allow slight future drift
                    return None

                service = group_dict.get("service", "unknown")
                message = group_dict.get("message", "").strip()
                level = group_dict.get("level")
                host = group_dict.get("host")

                return LogEntry(ts, service, message, level, host)

            except (ValueError, KeyError) as e:
                if self.verbose:
                    logging.debug(f"Failed to parse line: {line} - Error: {e}")
                continue
        
        return None

    def build_tree(self):
        """Sort logs by timestamp for each service."""
        for date_key, services in self.tree.items():
            for service, logs in services.items():
                services[service] = sorted(logs, key=lambda x: x.timestamp)

    def display_tree(self):
        """Display the log tree with formatting options."""
        if not self.tree:
            logging.info("No logs to display.")
            return

        for date in sorted(self.tree.keys()):
            self._print_line(f" {date}", style="bold yellow")
            services = self.tree[date]
            for service in sorted(services.keys()):
                self._print_line(f"├── {service}", style="bold cyan")
                logs = services[service]
                
                for i, log in enumerate(logs[:self.max_lines_per_service]):
                    is_last = i == len(logs[:self.max_lines_per_service]) - 1
                    prefix = "│   └── " if is_last and len(logs) <= self.max_lines_per_service else "│   ├── "
                    
                    timestamp = log.timestamp.strftime("%H:%M:%S")
                    
                    if self.show_full_lines:
                        lines = [log.message]
                        truncation = ""
                    elif self.wrap_lines:
                        indent = "│       "
                        first_line_prefix = f"│   {'    ' if not is_last else '    '}└── " if is_last else f"│   ├── "
                        wrap_width = self.truncate_length - len(first_line_prefix) - len(timestamp) - 3
                        if wrap_width < 20:
                            wrap_width = 20
                        lines = textwrap.wrap(log.message, width=wrap_width)
                        truncation = ""
                    else:
                        lines = [log.message[:self.truncate_length]]
                        truncation = "..." if len(log.message) > self.truncate_length else ""

                    # Add level indicator if available
                    level_indicator = ""
                    if log.level:
                        level_indicator = f"[{log.level}] "
                    
                    self._print_line(
                        f"{prefix}[{timestamp}] {level_indicator}{lines[0]}{truncation}",
                        style=self._get_style_for_level(log.level)
                    )
                    
                    if self.wrap_lines and len(lines) > 1:
                        for line in lines[1:]:
                            connector = "       " if is_last else "│      "
                            self._print_line(f"│   {connector}{line}", style="dim")

                if len(logs) > self.max_lines_per_service:
                    self._print_line(
                        f"│   └── ... ({len(logs) - self.max_lines_per_service} more logs)",
                        style="dim"
                    )
        print()

    def _get_style_for_level(self, level: Optional[str]) -> str:
        """Get color style based on log level."""
        if not level:
            return "white"
        
        level_styles = {
            'ERROR': 'red',
            'ERR': 'red',
            'WARN': 'yellow',
            'WARNING': 'yellow',
            'INFO': 'green',
            'DEBUG': 'blue',
            'CRIT': 'bold red',
            'CRITICAL': 'bold red'
        }
        return level_styles.get(level.upper(), 'white')

    def display_summary(self):
        """Display summary statistics about the parsed logs."""
        if not self.tree:
            print("No logs found.")
            return

        total_entries = sum(len(logs) for services in self.tree.values() 
                           for logs in services.values())
        
        unique_services = set()
        for services in self.tree.values():
            unique_services.update(services.keys())
        
        date_range = sorted(self.tree.keys())
        
        print(f"\nSummary:")
        print(f"  Total entries: {total_entries}")
        print(f"  Unique services: {len(unique_services)}")
        print(f"  Date range: {date_range[0]} to {date_range[-1]}")
        print(f"  Days with logs: {len(self.tree)}")
        
        # Top services by log volume
        service_counts = defaultdict(int)
        for services in self.tree.values():
            for service, logs in services.items():
                service_counts[service] += len(logs)
        
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        print(f"  Top services: {', '.join([f'{s[0]} ({s[1]})' for s in top_services])}")

    def _print_line(self, text: str, style: Optional[str] = None):
        """Print a line with optional styling."""
        if self.color_output and style:
            console.print(Text(text, style=style))
        else:
            print(text)

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Analyze and display syslog entries in a tree structure.",
        epilog="Example: ./syslog_analyzer.py --max-days 7 --wrap-lines --verbose"
    )
    
    parser.add_argument("--log-file", type=str, 
                       help="Path to the syslog file (overrides default search).")
    parser.add_argument("--max-days", type=int, default=30, 
                       help="Maximum days of logs to keep (default: 30).")
    parser.add_argument("--truncate-length", type=int, default=80, 
                       help="Length to truncate messages (default: 80).")
    parser.add_argument("--show-full-lines", action="store_true", 
                       help="Show full log messages without truncation.")
    parser.add_argument("--wrap-lines", action="store_true", 
                       help="Wrap long messages across lines.")
    parser.add_argument("--max-lines-per-service", type=int, default=5, 
                       help="Maximum lines to show per service (default: 5).")
    parser.add_argument("--no-color", action="store_true", 
                       help="Disable colored output.")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose output.")
    parser.add_argument("--summary", "-s", action="store_true", 
                       help="Show summary statistics.")
    parser.add_argument("--version", action="version", 
                       version="RSyslogAnalyzer 1.1.0")
    
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
        color_output=not args.no_color,
        verbose=args.verbose
    )
    
    analyzer.load_logs()
    analyzer.build_tree()
    
    if args.summary:
        analyzer.display_summary()
    else:
        analyzer.display_tree()
