import os
import re
import gzip
import zipfile
import json
import csv
import ipaddress
import logging
from collections import Counter
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Set
from xml.etree import ElementTree as ET

# Import the GeoIP library
try:
    import geoip2.database # type: ignore
except ImportError:
    geoip2 = None


class SecurityLogAnalyzer:
    def __init__(self):
        # Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Initialize counters and tracking sets
        self.ip_request_count: Dict[str, int] = {}
        self.failed_login_attempts: Dict[str, List[datetime]] = {}
        self.suspicious_ips: Set[str] = set()

        # Blacklist of IPs (can be loaded from a file or database)
        self.blacklist: Set[str] = {"192.168.1.100", "203.0.113.10"}  # Example IPs

        # GeoIP database setup (update the path as needed)
        self.geoip_db_path = 'GeoLite2-City.mmdb'  # Download required if used
        self.geoip_reader = geoip2.database.Reader(self.geoip_db_path) if geoip2 else None

        # Thresholds for detection
        self.BRUTE_FORCE_THRESHOLD = 5  # Failed attempts within timeframe
        self.BRUTE_FORCE_TIMEFRAME = timedelta(minutes=5)
        self.DOS_THRESHOLD = 100  # Requests per minute

        # Known patterns
        self.SUSPICIOUS_USER_AGENTS = [
            'sqlmap', 'nikto', 'nmap', 'masscan', 'zgrab',
            'python-requests', 'curl', 'wget'
        ]

        # Compile regex patterns
        self.patterns = {
            'ip': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
            'timestamp': re.compile(r'\[(.*?)\]'),
            'request': re.compile(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH).*?"'),
            'status_code': re.compile(r'\s(\d{3})\s'),
            'user_agent': re.compile(r'"Mozilla.*?"|\w+\/[\d.]+|\w+-\w+\/[\d.]+'),
            'failed_login': re.compile(r'Failed password|Invalid user|Failed login attempt', re.IGNORECASE),
            'sql_injection': re.compile(r'union.*select|\/\*.*\*\/|\b(admin|or|and|where|select)\b.*=', re.IGNORECASE),
            'xss_attempt': re.compile(r'<script>|<img.*onerror=|javascript:', re.IGNORECASE),
            'directory_traversal': re.compile(r'\.\.\/|\.\.\\|~\/|\%2e\%2e\%2f|\%252e\%252e\%252f'),
        }

    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp from log entry."""
        try:
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except ValueError:
            try:
                return datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                self.logger.error(f"Unable to parse timestamp: {timestamp_str}")
                return datetime.now()

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def geoip_lookup(self, ip: str) -> Dict[str, str]:
        """Perform GeoIP lookup for an IP address."""
        if not self.geoip_reader:
            return {}
        try:
            response = self.geoip_reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude
            }
        except Exception:
            return {}

    def detect_brute_force(self, ip: str, timestamp: datetime) -> bool:
        """Detect potential brute force attacks based on failed login attempts."""
        if ip not in self.failed_login_attempts:
            self.failed_login_attempts[ip] = []

        self.failed_login_attempts[ip].append(timestamp)

        self.failed_login_attempts[ip] = [
            t for t in self.failed_login_attempts[ip]
            if timestamp - t <= self.BRUTE_FORCE_TIMEFRAME
        ]

        return len(self.failed_login_attempts[ip]) >= self.BRUTE_FORCE_THRESHOLD

    def detect_dos_attack(self, ip: str, timestamp: datetime) -> bool:
        """Detect potential DoS attacks based on request frequency."""
        if ip not in self.ip_request_count:
            self.ip_request_count[ip] = 0
        self.ip_request_count[ip] += 1

        return self.ip_request_count[ip] >= self.DOS_THRESHOLD

    def extract_file_content(self, log_file: str) -> List[str]:
        """Extract and return lines of content from various log file formats."""
        file_ext = os.path.splitext(log_file)[1].lower()
        lines = []

        try:
            if file_ext == ".gz":
                with gzip.open(log_file, 'rt', encoding='utf-8') as f:
                    lines = f.readlines()
            elif file_ext == ".zip":
                with zipfile.ZipFile(log_file, 'r') as z:
                    for name in z.namelist():
                        with z.open(name) as file:
                            lines.extend(file.read().decode('utf-8').splitlines())
            elif file_ext == ".xml":
                tree = ET.parse(log_file)
                lines = [ET.tostring(elem, encoding='unicode') for elem in tree.iter()]
            elif file_ext in {".json", ".csv", ".log", ".txt"}:
                with open(log_file, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
        except Exception as e:
            self.logger.error(f"Error reading file {log_file}: {e}")
        return lines

    def analyze_log_file(self, log_file: str) -> Dict:
        """Analyze the entire log file."""
        lines = self.extract_file_content(log_file)
        security_events = []
        ip_activity = Counter()
        event_summary = Counter()

        for line in lines:
            result = self.analyze_log_entry(line)
            if result and result['events']:
                security_events.append(result)
                ip_activity[result['ip']] += 1
                event_summary.update(result['events'])

        return {
            'analysis_time': datetime.now().isoformat(),
            'total_security_events': len(security_events),
            'unique_ips_detected': len(ip_activity),
            'suspicious_ips': list(self.suspicious_ips),
            'event_summary': dict(event_summary),
            'top_active_ips': dict(ip_activity.most_common(10)),
            'detailed_events': security_events
        }

    def save_to_csv(self, report: Dict, output_csv: str):
        """Save report to a CSV file."""
        try:
            with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file)
                writer.writerow(['IP Address', 'Event', 'Count'])
                for event, count in report['event_summary'].items():
                    writer.writerow([event, count])
            self.logger.info(f"CSV report saved to {output_csv}")
        except Exception as e:
            self.logger.error(f"Error saving CSV: {e}")


# Add main execution block here
if __name__ == "__main__":
    analyzer = SecurityLogAnalyzer()
    log_file = 'example.log'  # Replace with your file
    report = analyzer.analyze_log_file(log_file)
    analyzer.save_to_csv(report, 'report.csv')
