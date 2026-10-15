"""Analyze local JSON Lines authentication events without network access."""

import argparse
from collections import Counter, defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
from pathlib import Path
import sys


class LogError(ValueError):
    """Invalid or unreadable log input."""


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    ip: str
    user: str
    outcome: str
    line: int


@dataclass(frozen=True)
class Finding:
    code: str
    ip: str
    user: str | None
    first_seen: str
    last_seen: str
    failures: int
    message: str


def utc_text(timestamp):
    return timestamp.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def parse_event(value, line):
    """Validate one event and normalize its timestamp and IP address."""
    if not isinstance(value, dict):
        raise LogError(f'Line {line}: event must be a JSON object.')
    for field in ('timestamp', 'ip', 'user', 'outcome'):
        if not isinstance(value.get(field), str) or not value[field].strip():
            raise LogError(f'Line {line}: {field} must be a nonempty string.')
    try:
        raw_timestamp = value['timestamp']
        timestamp = datetime.fromisoformat(raw_timestamp.replace('Z', '+00:00'))
        if 'T' not in raw_timestamp or timestamp.utcoffset() is None:
            raise ValueError('timezone required')
        timestamp = timestamp.astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise LogError(f'Line {line}: timestamp must be ISO 8601 with T and a timezone.') from exc
    try:
        ip = str(ipaddress.ip_address(value['ip']))
    except ValueError as exc:
        raise LogError(f'Line {line}: ip must be a valid IPv4 or IPv6 address.') from exc
    if value['outcome'] not in ('failure', 'success'):
        raise LogError(f'Line {line}: outcome must be failure or success.')
    return Event(timestamp, ip, value['user'], value['outcome'], line)


def load_events(path):
    events = []
    try:
        with Path(path).open(encoding='utf-8') as stream:
            for number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except (ValueError, RecursionError) as exc:
                    raise LogError(f'Line {number}: invalid JSON.') from exc
                events.append(parse_event(value, number))
    except (OSError, UnicodeError) as exc:
        raise LogError(f'Cannot read log file: {exc}') from exc
    if not events:
        raise LogError('Log contains no events.')
    return events


def analyze_events(events, threshold=5, window_minutes=10):
    """Summarize events and detect patterns in inclusive rolling time windows.

    Repeated failures aggregate by IP. A subsequent success is correlated only
    with preceding failures for the same IP AND user since its previous success.
    """
    if isinstance(threshold, bool) or not isinstance(threshold, int) or threshold < 2:
        raise ValueError('threshold must be an integer of at least 2')
    if isinstance(window_minutes, bool) or not isinstance(window_minutes, int) or not 1 <= window_minutes <= 10080:
        raise ValueError('window_minutes must be an integer from 1 to 10080')
    ordered = sorted(events, key=lambda event: (event.timestamp, event.line))
    window = timedelta(minutes=window_minutes)
    ip_failures = defaultdict(deque)
    user_failures = defaultdict(deque)
    alerted_ips = set()
    findings = []
    failures_by_ip = Counter()
    users = set()

    for event in ordered:
        users.add(event.user)
        try:
            cutoff = event.timestamp - window
        except OverflowError:
            cutoff = datetime.min.replace(tzinfo=timezone.utc)
        ip_queue = ip_failures[event.ip]
        key = (event.ip, event.user)
        user_queue = user_failures[key]
        for queue in (ip_queue, user_queue):
            while queue and queue[0] < cutoff:
                queue.popleft()
        if len(ip_queue) < threshold:
            alerted_ips.discard(event.ip)
        if event.outcome == 'failure':
            failures_by_ip[event.ip] += 1
            ip_queue.append(event.timestamp)
            user_queue.append(event.timestamp)
            if len(ip_queue) >= threshold and event.ip not in alerted_ips:
                findings.append(Finding(
                    'REPEATED_FAILURES', event.ip, None, utc_text(ip_queue[0]),
                    utc_text(event.timestamp), len(ip_queue),
                    'Repeated authentication failures from one IP; investigate context.'))
                alerted_ips.add(event.ip)
        elif len(user_queue) >= threshold:
            findings.append(Finding(
                'SUCCESS_AFTER_FAILURES', event.ip, event.user,
                utc_text(user_queue[0]), utc_text(event.timestamp), len(user_queue),
                'Successful authentication after repeated failures for this IP and user; review activity.'))
            user_queue.clear()
        else:
            user_queue.clear()

    totals = Counter(event.outcome for event in ordered)
    return {
        'notice': 'Patterns for investigation only; findings do not prove an attack. No findings does not prove safety.',
        'settings': {'threshold': threshold, 'window_minutes': window_minutes},
        'summary': {
            'events': len(ordered), 'failures': totals['failure'], 'successes': totals['success'],
            'unique_ips': len({event.ip for event in ordered}), 'unique_users': len(users),
            'first_seen': utc_text(ordered[0].timestamp) if ordered else None,
            'last_seen': utc_text(ordered[-1].timestamp) if ordered else None,
            'failures_by_ip': dict(sorted(failures_by_ip.items(), key=lambda item: (-item[1], item[0]))),
        },
        'findings': [asdict(finding) for finding in findings],
    }


def format_report(report):
    summary = report['summary']
    lines = ['SECURITY LOG ANALYZER', '=====================', report['notice'],
             f"Events: {summary['events']} | Failures: {summary['failures']} | Successes: {summary['successes']}",
             f"Unique IPs: {summary['unique_ips']} | Unique users: {summary['unique_users']}",
             f"Period (UTC): {summary['first_seen']} to {summary['last_seen']}",
             f"Window: {report['settings']['window_minutes']} minute(s) | Threshold: {report['settings']['threshold']}",
             'Failures by IP:']
    lines.extend(f'  {ip}: {count}' for ip, count in summary['failures_by_ip'].items())
    if not summary['failures_by_ip']:
        lines.append('  None')
    lines.append(f"Findings: {len(report['findings'])}")
    for finding in report['findings']:
        # JSON quoting keeps usernames containing newlines/control characters on one line.
        user = json.dumps(finding['user'], ensure_ascii=True) if finding['user'] is not None else '(all users)'
        lines.extend(['', f"[{finding['code']}] IP: {finding['ip']} | User: {user}",
                      f"  {finding['first_seen']} to {finding['last_seen']} | Failures: {finding['failures']}",
                      f"  {finding['message']}"])
    if not report['findings']:
        lines.append('No targeted patterns found. Review other evidence as needed.')
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('log', type=Path, help='Local UTF-8 JSON Lines file')
    parser.add_argument('--threshold', type=int, default=5, help='Failures required for a finding (minimum 2; default 5)')
    parser.add_argument('--window-minutes', type=int, default=10, help='Rolling window, 1–10080 minutes (default 10)')
    parser.add_argument('--format', choices=('text', 'json'), default='text')
    parser.add_argument('--fail-on-findings', action='store_true', help='Exit 1 when findings exist')
    args = parser.parse_args(argv)
    try:
        # Validate options even before reading a potentially large file.
        analyze_events([], args.threshold, args.window_minutes)
        report = analyze_events(load_events(args.log), args.threshold, args.window_minutes)
    except (LogError, ValueError) as exc:
        print(f'Error: {exc}', file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=True) if args.format == 'json' else format_report(report))
    return 1 if args.fail_on_findings and report['findings'] else 0


if __name__ == '__main__':
    sys.exit(main())
