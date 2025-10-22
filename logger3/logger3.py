#!/usr/bin/env python3

import os
import re
import logging
import textwrap
import gzip
import bz2
import lzma
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, List, Dict, Pattern, Tuple, Iterator, Any
import argparse
import json
import csv
from contextlib import contextmanager

try:
    from rich.console import Console
    from rich.text import Text
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.syntax import Syntax
    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False

# Extended default log paths for different systems
DEFAULT_SYSLOG_PATHS = [
    "/var/log/messages",
    "/var/log/syslog", 
    "/var/log/system.log",
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/kern.log",
    "/var/log/dmesg",
    "/var/log/debug"
]

# Common month abbreviations for pre-check
MONTHS = {'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 
          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'}

# Configure logging
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
    pid: Optional[str] = None
    raw_line: str = ""
    
    @property
    def is_error(self) -> bool:
        """Check if this log entry represents an error."""
        error_indicators = ['error', 'failed', 'failure', 'exception', 'critical', 'panic']
        return (self.level and self.level.upper() in ['ERROR', 'CRITICAL', 'FATAL'] or
                any(indicator in self.message.lower() for indicator in error_indicators))

@dataclass
class AnalysisResults:
    total_entries: int = 0
    unique_services: set = field(default_factory=set)
    date_range: Tuple[str, str] = ("", "")
    service_counts: Counter = field(default_factory=Counter)
    error_count: int = 0
    level_distribution: Counter = field(default_factory=Counter)
    hourly_distribution: Counter = field(default_factory=Counter)

class LogParser:
    """Handles log parsing with multiple format support."""
    
    def __init__(self, current_year: int, verbose: bool = False):
        self.current_year = current_year
        self.verbose = verbose
        self.last_month = None
        self._compiled_patterns = self._compile_patterns()
    
    def _compile_patterns(self) -> List[Tuple[Pattern, str]]:
        """Compile regex patterns with their format identifiers."""
        patterns = [
            # Traditional syslog with PID
            (
                re.compile(
                    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                    r"(?P<time>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+"
                    r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)"
                    r"(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.+)$"
                ),
                "traditional"
            ),
            # Traditional syslog without PID
            (
                re.compile(
                    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
                    r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*"
                    r"(?P<message>.+)$"
                ),
                "traditional_simple"
            ),
            # Syslog with explicit level
            (
                re.compile(
                    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
                    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
                    r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+):\s*"
                    r"\[(?P<level>[A-Z]+)\]\s*(?P<message>.+)$"
                ),
                "with_level"
            ),
            # ISO 8601 format
            (
                re.compile(
                    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?(?:\s+[+-]\d{4})?)\s+"
                    r"(?P<host>[\w\-.]+)\s+(?P<service>[\w\-.\/]+)(?:\[(?P<pid>\d+)\])?:\s*"
                    r"(?P<message>.+)$"
                ),
                "iso8601"
            ),
            # Journald format
            (
                re.compile(
                    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\+\d{4})\s+"
                    r"(?P<host>[\w\-.]+)\s+(?P<service>\w+)\[(?P<pid>\d+)\]:\s*"
                    r"(?P<message>.+)$"
                ),
                "journald"
            )
        ]
        return patterns
    
    def _adjust_year_based_on_month(self, month: str) -> int:
        """Adjust year based on month transitions to handle year boundaries."""
        if self.last_month is None:
            self.last_month = month
            return self.current_year
        
        month_num = {
            'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
            'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
        }
        
        current_month_num = month_num.get(self.last_month, 12)
        new_month_num = month_num.get(month, 1)
        
        # Handle year transitions
        if current_month_num == 12 and new_month_num == 1:
            year = self.current_year + 1
        elif current_month_num == 1 and new_month_num == 12:
            year = self.current_year - 1
        else:
            year = self.current_year
        
        self.last_month = month
        return year
    
    def _parse_iso_timestamp(self, ts_str: str) -> Optional[datetime]:
        """Parse ISO 8601 timestamps with various formats."""
        # Normalize the timestamp string
        ts_str = ts_str.replace(' ', 'T')  # Replace space with T for consistency
        
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        return None
    
    def parse_line(self, line: str, now: datetime, cutoff_date: datetime) -> Optional[LogEntry]:
        """Parse a single log line with improved pattern matching."""
        # Quick pre-check to skip non-log lines
        if not self._is_likely_log_line(line):
            return None
        
        for pattern, pattern_type in self._compiled_patterns:
            match = pattern.match(line)
            if not match:
                continue
            
            try:
                group_dict = match.groupdict()
                timestamp = self._extract_timestamp(group_dict, pattern_type)
                
                if not timestamp or timestamp < cutoff_date or timestamp > now + timedelta(days=1):
                    return None
                
                return LogEntry(
                    timestamp=timestamp,
                    service=group_dict.get("service", "unknown").strip(),
                    message=group_dict.get("message", "").strip(),
                    level=group_dict.get("level"),
                    host=group_dict.get("host"),
                    pid=group_dict.get("pid"),
                    raw_line=line
                )
                
            except (ValueError, KeyError) as e:
                if self.verbose:
                    logging.debug(f"Failed to parse line with {pattern_type}: {e}")
                continue
        
        return None
    
    def _is_likely_log_line(self, line: str) -> bool:
        """Quick check if line is likely a valid log entry."""
        if not line or len(line) < 15:
            return False
        
        # Check for traditional syslog format
        if line[:3] in MONTHS:
            return True
        
        # Check for ISO timestamp format
        if re.match(r'^\d{4}-\d{2}-\d{2}', line):
            return True
        
        return False
    
    def _extract_timestamp(self, group_dict: Dict[str, str], pattern_type: str) -> Optional[datetime]:
        """Extract timestamp from parsed groups based on pattern type."""
        if pattern_type == "iso8601" or pattern_type == "journald":
            return self._parse_iso_timestamp(group_dict['timestamp'])
        else:
            # Traditional syslog format
            month = group_dict['month']
            day = group_dict['day']
            time_str = group_dict['time']
            
            year = self._adjust_year_based_on_month(month)
            
            # Handle microseconds if present
            if '.' in time_str:
                time_parts = time_str.split('.')
                base_time = time_parts[0]
                microseconds = int(time_parts[1].ljust(6, '0')[:6])
            else:
                base_time = time_str
                microseconds = 0
            
            ts_str = f"{year} {month} {day} {base_time}"
            try:
                timestamp = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
                return timestamp.replace(microsecond=microseconds)
            except ValueError:
                return None

class RSyslogAnalyzer:
    def __init__(self, log_file: Optional[str] = None, max_days: int = 30, 
                 truncate_length: int = 80, show_full_lines: bool = False, 
                 wrap_lines: bool = False, max_lines_per_service: int = 5, 
                 color_output: bool = True, verbose: bool = False,
                 enable_analysis: bool = False):
        self.tree: Dict[str, Dict[str, List[LogEntry]]] = defaultdict(lambda: defaultdict(list))
        self.log_file = log_file or self._find_log_file()
        self.max_days = max_days
        self.truncate_length = truncate_length
        self.show_full_lines = show_full_lines
        self.wrap_lines = wrap_lines
        self.max_lines_per_service = max_lines_per_service
        self.color_output = color_output and RICH_AVAILABLE
        self.verbose = verbose
        self.enable_analysis = enable_analysis
        self.current_year = datetime.now().year
        
        self.parser = LogParser(self.current_year, verbose)
        self.analysis_results = AnalysisResults()
        
        # Statistics
        self._processed_lines = 0
        self._parsed_entries = 0

    def _find_log_file(self) -> Optional[str]:
        """Find the appropriate syslog file from default locations."""
        candidates = []
        
        # Check primary log files
        for path in DEFAULT_SYSLOG_PATHS:
            path_obj = Path(path)
            if path_obj.exists() and os.access(path, os.R_OK):
                candidates.append((path, path_obj.stat().st_mtime))
        
        # Check for rotated logs
        for path in DEFAULT_SYSLOG_PATHS:
            for ext in ["", ".1", ".0", ".gz", ".bz2", ".xz"]:
                rotated_path = f"{path}{ext}"
                rotated_obj = Path(rotated_path)
                if rotated_obj.exists() and os.access(rotated_path, os.R_OK):
                    candidates.append((rotated_path, rotated_obj.stat().st_mtime))
        
        if not candidates:
            logging.error("No standard syslog file found or insufficient permissions.")
            return None
        
        # Return the most recent log file
        candidates.sort(key=lambda x: x[1], reverse=True)
        selected = candidates[0][0]
        logging.info(f"Using log file: {selected}")
        return selected

    @contextmanager
    def _open_log_file(self, file_path: str):
        """Context manager to handle different log file compression formats."""
        if file_path.endswith('.gz'):
            with gzip.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                yield f
        elif file_path.endswith('.bz2'):
            with bz2.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                yield f
        elif file_path.endswith('.xz'):
            with lzma.open(file_path, 'rt', encoding='utf-8', errors='ignore') as f:
                yield f
        else:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                yield f

    def load_logs(self):
        """Load and parse log files with progress tracking and analysis."""
        if not self.log_file:
            return

        now = datetime.now()
        cutoff_date = now - timedelta(days=self.max_days)
        
        try:
            file_size = os.path.getsize(self.log_file)
            show_progress = self.color_output and file_size > 1024 * 1024  # Show progress for files >1MB
            
            with self._open_log_file(self.log_file) as f:
                if show_progress:
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(),
                        TaskProgressColumn(),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        console=console,
                        transient=True
                    ) as progress:
                        task = progress.add_task("Parsing logs...", total=file_size)
                        self._process_file_with_progress(f, progress, task, now, cutoff_date)
                else:
                    self._process_file(f, now, cutoff_date)

            if self.verbose:
                logging.info(f"Processed {self._processed_lines} lines, parsed {self._parsed_entries} entries "
                           f"({self._parsed_entries/self._processed_lines*100:.1f}% success rate)")

        except FileNotFoundError:
            logging.error(f"Log file not found: {self.log_file}")
        except PermissionError:
            logging.error(f"Permission denied accessing log file: {self.log_file}")
        except IOError as e:
            logging.error(f"Failed to read log file: {e}")

    def _process_file(self, file_obj, now: datetime, cutoff_date: datetime):
        """Process log file without progress tracking."""
        for line in file_obj:
            self._process_line(line.strip(), now, cutoff_date)

    def _process_file_with_progress(self, file_obj, progress, task, now: datetime, cutoff_date: datetime):
        """Process log file with progress tracking."""
        # For compressed files, we can't easily track progress by file position
        # So we'll just show indeterminate progress
        for line in file_obj:
            self._process_line(line.strip(), now, cutoff_date)
            progress.update(task, advance=len(line))

    def _process_line(self, line: str, now: datetime, cutoff_date: datetime):
        """Process a single log line and update statistics."""
        self._processed_lines += 1
        entry = self.parser.parse_line(line, now, cutoff_date)
        
        if entry:
            self._parsed_entries += 1
            date_key = entry.timestamp.strftime("%Y-%m-%d")
            self.tree[date_key][entry.service].append(entry)
            
            # Update analysis results
            if self.enable_analysis:
                self._update_analysis(entry)

    def _update_analysis(self, entry: LogEntry):
        """Update analysis results with new log entry."""
        self.analysis_results.total_entries += 1
        self.analysis_results.unique_services.add(entry.service)
        
        if entry.level:
            self.analysis_results.level_distribution[entry.level.upper()] += 1
        
        if entry.is_error:
            self.analysis_results.error_count += 1
        
        # Update hourly distribution
        hour_key = entry.timestamp.strftime("%H:00")
        self.analysis_results.hourly_distribution[hour_key] += 1
        
        # Update service counts
        self.analysis_results.service_counts[entry.service] += 1

    def build_tree(self):
        """Sort logs by timestamp for each service and finalize analysis."""
        for date_key, services in self.tree.items():
            for service, logs in services.items():
                services[service] = sorted(logs, key=lambda x: x.timestamp)
        
        # Finalize analysis results
        if self.tree and self.enable_analysis:
            dates = sorted(self.tree.keys())
            self.analysis_results.date_range = (dates[0], dates[-1])

    def display_tree(self):
        """Display the log tree with enhanced formatting."""
        if not self.tree:
            self._print_line("No logs to display.", style="yellow")
            return

        if self.color_output:
            console.print(Panel("Syslog Analysis Tree", style="bold blue"))
        else:
            print("Syslog Analysis Tree")
            print("=" * 50)

        for date in sorted(self.tree.keys()):
            self._print_line(f"\n{date}", style="bold yellow")
            services = self.tree[date]
            
            for service in sorted(services.keys()):
                logs = services[service]
                error_count = sum(1 for log in logs if log.is_error)
                
                service_display = service
                if error_count > 0:
                    service_display += f" [errors: {error_count}]"
                
                self._print_line(f"├── {service_display}", style="bold cyan")
                self._display_service_logs(logs)

        print()

    def _display_service_logs(self, logs: List[LogEntry]):
        """Display logs for a specific service."""
        displayed_count = min(len(logs), self.max_lines_per_service)
        
        for i, log in enumerate(logs[:self.max_lines_per_service]):
            is_last = i == displayed_count - 1
            prefix = "│   └── " if is_last else "│   ├── "
            
            self._display_log_entry(log, prefix, is_last)
        
        # Show overflow message if there are more logs
        if len(logs) > self.max_lines_per_service:
            overflow_count = len(logs) - self.max_lines_per_service
            error_count = sum(1 for log in logs[self.max_lines_per_service:] if log.is_error)
            
            overflow_msg = f"... ({overflow_count} more logs"
            if error_count > 0:
                overflow_msg += f", {error_count} errors"
            overflow_msg += ")"
            
            self._print_line(f"│   └── {overflow_msg}", style="dim")

    def _display_log_entry(self, log: LogEntry, prefix: str, is_last: bool):
        """Display a single log entry with formatting."""
        timestamp = log.timestamp.strftime("%H:%M:%S")
        level_indicator = f"[{log.level}] " if log.level else ""
        
        if self.show_full_lines:
            message_lines = [log.message]
            truncation = ""
        elif self.wrap_lines:
            # Calculate wrap width considering the prefix and timestamp
            wrap_width = max(40, self.truncate_length - len(prefix) - len(timestamp) - len(level_indicator) - 3)
            message_lines = textwrap.wrap(log.message, width=wrap_width)
            truncation = ""
        else:
            message_lines = [log.message[:self.truncate_length]]
            truncation = "..." if len(log.message) > self.truncate_length else ""
        
        # First line
        first_line = f"{prefix}[{timestamp}] {level_indicator}{message_lines[0]}{truncation}"
        self._print_line(first_line, style=self._get_style_for_log(log))
        
        # Additional lines for wrapped text
        if self.wrap_lines and len(message_lines) > 1:
            for line in message_lines[1:]:
                connector = "       " if is_last else "│      "
                self._print_line(f"│   {connector}{line}", style="dim")

    def _get_style_for_log(self, log: LogEntry) -> str:
        """Get color style based on log level and content."""
        if log.level:
            level_styles = {
                'ERROR': 'red', 'ERR': 'red', 'FATAL': 'bold red',
                'WARN': 'yellow', 'WARNING': 'yellow',
                'INFO': 'green', 'DEBUG': 'blue',
                'CRIT': 'bold red', 'CRITICAL': 'bold red'
            }
            return level_styles.get(log.level.upper(), 'white')
        
        # Fallback: check message content for error indicators
        error_indicators = ['error', 'failed', 'failure', 'exception', 'critical']
        if any(indicator in log.message.lower() for indicator in error_indicators):
            return 'red'
        
        return 'white'

    def display_summary(self):
        """Display enhanced summary statistics."""
        if not self.tree:
            self._print_line("No logs found.", style="yellow")
            return

        if self.color_output:
            self._display_rich_summary()
        else:
            self._display_text_summary()

    def _display_rich_summary(self):
        """Display summary using rich formatting."""
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")
        
        table.add_row("Total entries", f"{self.analysis_results.total_entries:,}")
        table.add_row("Unique services", str(len(self.analysis_results.unique_services)))
        table.add_row("Date range", f"{self.analysis_results.date_range[0]} to {self.analysis_results.date_range[1]}")
        table.add_row("Days with logs", str(len(self.tree)))
        table.add_row("Error count", f"{self.analysis_results.error_count:,}")
        
        # Top services
        top_services = self.analysis_results.service_counts.most_common(5)
        services_str = ", ".join([f"{s[0]} ({s[1]:,})" for s in top_services])
        table.add_row("Top services", services_str)
        
        console.print(Panel(table, title="Log Analysis Summary", style="bold blue"))
        
        # Level distribution
        if self.analysis_results.level_distribution:
            level_table = Table(show_header=True, header_style="bold green")
            level_table.add_column("Level", style="cyan")
            level_table.add_column("Count", style="white")
            
            for level, count in self.analysis_results.level_distribution.most_common():
                level_table.add_row(level, f"{count:,}")
            
            console.print(Panel(level_table, title="Log Level Distribution", style="green"))

    def _display_text_summary(self):
        """Display summary in plain text format."""
        print(f"\nSummary:")
        print(f"  Total entries: {self.analysis_results.total_entries:,}")
        print(f"  Unique services: {len(self.analysis_results.unique_services)}")
        print(f"  Date range: {self.analysis_results.date_range[0]} to {self.analysis_results.date_range[1]}")
        print(f"  Days with logs: {len(self.tree)}")
        print(f"  Error count: {self.analysis_results.error_count:,}")
        
        # Top services
        top_services = self.analysis_results.service_counts.most_common(5)
        print(f"  Top services: {', '.join([f'{s[0]} ({s[1]:,})' for s in top_services])}")
        
        # Level distribution
        if self.analysis_results.level_distribution:
            print(f"  Level distribution:")
            for level, count in self.analysis_results.level_distribution.most_common():
                print(f"    {level}: {count:,}")

    def export_to_json(self, filename: str):
        """Export analysis results to JSON file."""
        export_data = {
            "metadata": {
                "exported_at": datetime.now().isoformat(),
                "log_file": self.log_file,
                "analysis_period_days": self.max_days
            },
            "summary": {
                "total_entries": self.analysis_results.total_entries,
                "unique_services": list(self.analysis_results.unique_services),
                "date_range": self.analysis_results.date_range,
                "days_with_logs": len(self.tree),
                "error_count": self.analysis_results.error_count
            },
            "service_stats": dict(self.analysis_results.service_counts.most_common()),
            "level_stats": dict(self.analysis_results.level_distribution.most_common()),
            "hourly_distribution": dict(self.analysis_results.hourly_distribution.most_common())
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logging.info(f"Exported analysis to {filename}")

    def find_errors(self, service: Optional[str] = None) -> List[LogEntry]:
        """Find all error log entries, optionally filtered by service."""
        errors = []
        for date_services in self.tree.values():
            for svc, logs in date_services.items():
                if service and svc != service:
                    continue
                errors.extend([log for log in logs if log.is_error])
        
        return sorted(errors, key=lambda x: x.timestamp)

    def _print_line(self, text: str, style: Optional[str] = None):
        """Print a line with optional styling."""
        if self.color_output and style:
            console.print(Text(text, style=style))
        else:
            print(text)

def parse_arguments():
    """Parse command line arguments with enhanced options."""
    parser = argparse.ArgumentParser(
        description="Advanced syslog analyzer with tree structure display and analysis.",
        epilog="""
Examples:
  %(prog)s --max-days 7 --wrap-lines --verbose
  %(prog)s --log-file /var/log/syslog --export results.json
  %(prog)s --find-errors --service sshd
        """
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
    parser.add_argument("--enable-analysis", action="store_true",
                       help="Enable detailed log analysis.")
    parser.add_argument("--export", type=str,
                       help="Export analysis results to JSON file.")
    parser.add_argument("--find-errors", action="store_true",
                       help="Find and display error logs.")
    parser.add_argument("--service", type=str,
                       help="Filter by specific service name.")
    parser.add_argument("--version", action="version", 
                       version="RSyslogAnalyzer 2.0.0")
    
    return parser.parse_args()

def main():
    """Main function with enhanced capabilities."""
    args = parse_arguments()
    
    analyzer = RSyslogAnalyzer(
        log_file=args.log_file,
        max_days=args.max_days,
        truncate_length=args.truncate_length,
        show_full_lines=args.show_full_lines,
        wrap_lines=args.wrap_lines,
        max_lines_per_service=args.max_lines_per_service,
        color_output=not args.no_color,
        verbose=args.verbose,
        enable_analysis=args.enable_analysis or args.summary or args.export
    )
    
    analyzer.load_logs()
    analyzer.build_tree()
    
    # Handle different output modes
    if args.find_errors:
        errors = analyzer.find_errors(args.service)
        if errors:
            print(f"\nFound {len(errors)} error logs:")
            for error in errors[-10:]:  # Show last 10 errors
                print(f"  {error.timestamp} [{error.service}] {error.message[:100]}...")
        else:
            print("No error logs found.")
    
    elif args.summary:
        analyzer.display_summary()
    
    else:
        analyzer.display_tree()
    
    # Export if requested
    if args.export:
        analyzer.export_to_json(args.export)

if __name__ == "__main__":
    main()
