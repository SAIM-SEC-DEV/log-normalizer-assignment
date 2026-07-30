#!/usr/bin/env python3
import re
import csv
import json
import argparse
import hashlib
import sys
from datetime import datetime, timezone
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
import logging

# Configuration

LOG_FORMATS = [
    {
        'name': 'firewall',
        'regex': r'^\[(?P<timestamp>[^\]]+)\]\s+FIREWALL\s+src=(?P<src_ip>\S+)\s+dst=(?P<dst_ip>\S+)\s+action=(?P<action>\S+)\s+port=(?P<port>\d+)\s+bytes=(?P<bytes>\d+)$',
        'timestamp_format': '%Y-%m-%d %H:%M:%S',
        'field_map': {
            'src_ip': 'source_ip',
            'dst_ip': 'target',
            'action': 'action',
            'port': 'port',
            'bytes': 'bytes'
        },
        'event_type': 'FIREWALL',
        'user_default': 'SYSTEM'
    },
    {
        'name': 'auth',
        'regex': r'^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z),(?P<server>\S+),LOGIN,(?P<user>\S+),(?P<src_ip>\S+),(?P<status>\S+)$',
        'timestamp_format': 'iso',
        'field_map': {
            'src_ip': 'source_ip',
            'server': 'target',
            'user': 'user',
            'status': 'action'
        },
        'event_type': 'AUTH',
        'user_default': None  # user is extracted
    },
    {
        'name': 'dns',
        'regex': r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+named\[\d+\]:\s+query:\s+(?P<domain>\S+)\s+IN\s+\S+\s+from\s+(?P<src_ip>\S+)$',
        'timestamp_format': '%b %d %H:%M:%S',  # year missing, we'll append current year
        'field_map': {
            'src_ip': 'source_ip',
            'domain': 'target',
            'host': 'host'
        },
        'event_type': 'DNS',
        'user_default': 'SYSTEM',
        'action_default': 'QUERY'
    },
    {
        'name': 'file_json',
        'regex': r'^\{"timestamp": "(?P<timestamp>[^"]+)", "event": "FILE_ACCESS", "user": "(?P<user>[^"]+)", "file": "(?P<file_path>[^"]+)", "action": "(?P<action>[^"]+)"\}$',
        'timestamp_format': '%Y-%m-%d %H:%M:%S',
        'field_map': {
            'file_path': 'target',
            'user': 'user',
            'action': 'action'
        },
        'event_type': 'FILE',
        'user_default': None
    }
]

# Helper functions

def parse_timestamp(ts_str: str, fmt: str) -> Optional[str]:
    """Convert timestamp to ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ)."""
    if not ts_str:
        return None
    try:
        if fmt == 'iso':
            # ISO format: 2026-07-20T14:23:45Z
            dt = datetime.strptime(ts_str, '%Y-%m-%dT%H:%M:%SZ')
        elif fmt == '%b %d %H:%M:%S':
            # Syslog style, no year – assume current year
            now = datetime.now()
            year = now.year
            dt = datetime.strptime(f"{year} {ts_str}", '%Y %b %d %H:%M:%S')
            # If the date is in the future (e.g., now is July, but log says Jan), adjust year
            if dt > now:
                dt = dt.replace(year=year - 1)
        else:
            dt = datetime.strptime(ts_str, fmt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception as e:
        logging.warning(f"Timestamp parse failed: '{ts_str}' - {e}")
        return None

def validate_ip(ip: str) -> Tuple[bool, str]:
    """Validate IPv4 and flag private ranges."""
    if not ip:
        return False, "MISSING"
    parts = ip.split('.')
    if len(parts) != 4:
        return False, "INVALID"
    try:
        nums = [int(p) for p in parts]
        if any(n < 0 or n > 255 for n in nums):
            return False, "INVALID"
        if nums[0] == 10:
            return True, "PRIVATE"
        if nums[0] == 192 and nums[1] == 168:
            return True, "PRIVATE"
        if nums[0] == 172 and 16 <= nums[1] <= 31:
            return True, "PRIVATE"
        return True, "VALID"
    except ValueError:
        return False, "INVALID"

def clean_value(val: Any) -> str:
    """Clean and convert to string."""
    if val is None:
        return ''
    if isinstance(val, (int, float)):
        return str(val)
    return str(val).strip()

def normalize_action(action: str) -> str:
    """Normalize action verbs."""
    if not action:
        return 'UNKNOWN'
    action = action.upper().strip()
    mapping = {
        'ALLOW': 'ALLOW',
        'PERMIT': 'ALLOW',
        'DENY': 'DENY',
        'DROP': 'DENY',
        'BLOCK': 'DENY',
        'SUCCESS': 'SUCCESS',
        'SUCCEEDED': 'SUCCESS',
        'FAILURE': 'FAILURE',
        'FAILED': 'FAILURE',
        'QUERY': 'QUERY',
        'RESPONSE': 'RESPONSE',
        'READ': 'READ',
        'WRITE': 'WRITE',
        'MODIFY': 'WRITE',
        'DELETE': 'DELETE'
    }
    return mapping.get(action, action) 

def parse_line(line: str) -> Optional[Dict[str, Any]]:
    line = line.rstrip('\n')
    for fmt in LOG_FORMATS:
        match = re.match(fmt['regex'], line)
        if match:
            groups = match.groupdict()
            # Build base entry
            entry = {
                '_raw': line,
                '_source_type': fmt['name'],
                'event_type': fmt['event_type'],
                'status': 'VALID'  # will update if issues
            }
            # Apply field mapping
            for src_field, dst_field in fmt['field_map'].items():
                if src_field in groups:
                    val = groups[src_field]
                    # Special handling
                    if dst_field == 'source_ip':
                        valid, status = validate_ip(val)
                        entry['source_ip'] = val
                        if not valid:
                            entry['status'] = 'INVALID_IP'
                    elif dst_field == 'bytes':
                        try:
                            entry['bytes'] = int(val)
                            if entry['bytes'] < 0:
                                entry['status'] = 'NEGATIVE_BYTES'
                        except ValueError:
                            entry['bytes'] = 0
                            entry['status'] = 'INVALID_BYTES'
                    elif dst_field == 'action':
                        entry['action'] = normalize_action(val)
                    else:
                        entry[dst_field] = clean_value(val)
            # Timestamp normalization
            if 'timestamp' in groups:
                raw_ts = groups['timestamp']
                norm_ts = parse_timestamp(raw_ts, fmt['timestamp_format'])
                if norm_ts:
                    entry['timestamp'] = norm_ts
                else:
                    entry['timestamp'] = None
                    entry['status'] = 'UNPARSEABLE_TIMESTAMP'
                entry['raw_timestamp'] = raw_ts
            else:
                # Construct timestamp from month/day/time for DNS
                if fmt['name'] == 'dns':
                    month = groups.get('month')
                    day = groups.get('day')
                    time_str = groups.get('time')
                    if month and day and time_str:
                        ts_str = f"{month} {day} {time_str}"
                        norm_ts = parse_timestamp(ts_str, '%b %d %H:%M:%S')
                        if norm_ts:
                            entry['timestamp'] = norm_ts
                        else:
                            entry['timestamp'] = None
                            entry['status'] = 'UNPARSEABLE_TIMESTAMP'
                        entry['raw_timestamp'] = ts_str
            # User
            if 'user' in entry:
                pass  # already set
            elif fmt['user_default'] is not None:
                entry['user'] = fmt['user_default']
            else:
                entry['user'] = 'UNKNOWN'
            if 'action' not in entry:
                entry['action'] = fmt.get('action_default', 'UNKNOWN')
            entry.setdefault('target', '')
            entry.setdefault('bytes', 0)
            # If status is still 'VALID' but missing timestamp, mark as flag
            if entry.get('timestamp') is None:
                entry['status'] = 'NO_TIMESTAMP'
            return entry
    return None

def deduplicate(entries: List[Dict]) -> List[Dict]:
    """Remove duplicates where same timestamp, source_ip, action within 1 second."""
    seen = {}
    deduped = []
    for e in entries:
        # Use only if timestamp exists
        ts = e.get('timestamp')
        if ts is None:
            deduped.append(e)
            continue
        key = (ts, e.get('source_ip', ''), e.get('action', ''))
        if key in seen:
            continue
        seen[key] = True
        deduped.append(e)
    return deduped

# Main script
def main():
    parser = argparse.ArgumentParser(description='Normalize security logs.')
    parser.add_argument('--input', required=True, help='Input log file')
    parser.add_argument('--output-csv', default='sample_clean.csv', help='Output CSV')
    parser.add_argument('--output-json', default='sample_clean.json', help='Output JSON')
    parser.add_argument('--format', choices=['auto', 'firewall', 'auth', 'dns', 'file_json'],
                        default='auto', help='Force parser (default: auto)')
    parser.add_argument('--deduplicate', action='store_true', help='Remove near-duplicates')
    parser.add_argument('--log-errors', default='errors.log', help='Error log file')
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig(filename=args.log_errors, level=logging.WARNING,
                        format='%(asctime)s - %(levelname)s - %(message)s')

    parsed_entries = []
    skipped = 0
    with open(args.input, 'r', encoding='utf-8', errors='ignore') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            entry = parse_line(line)
            if entry is None:
                skipped += 1
                logging.warning(f"Line {line_num}: no pattern matched: {line.strip()}")
            else:
                parsed_entries.append(entry)

    total = len(parsed_entries)
    if args.deduplicate:
        parsed_entries = deduplicate(parsed_entries)
        duplicates_removed = total - len(parsed_entries)
    else:
        duplicates_removed = 0

    # Summary statistics
    print(f"Total lines read: {total + skipped}")
    print(f"Parsed successfully: {len(parsed_entries)}")
    print(f"Skipped (malformed): {skipped}")
    print(f"Duplicates removed: {duplicates_removed}")

    # Write CSV
    if parsed_entries:
        fieldnames = ['timestamp', 'source_ip', 'event_type', 'user', 'action',
                      'target', 'bytes', 'status', 'raw_timestamp', '_source_type', '_raw']
        with open(args.output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for row in parsed_entries:
                for fn in fieldnames:
                    if fn not in row:
                        row[fn] = ''
                writer.writerow(row)

    # Write JSON
    with open(args.output_json, 'w', encoding='utf-8') as f:
        json.dump(parsed_entries, f, indent=2, default=str)

    print(f"Output CSV: {args.output_csv}")
    print(f"Output JSON: {args.output_json}")

if __name__ == '__main__':
    main()