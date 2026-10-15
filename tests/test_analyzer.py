from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from analyzer import LogError, analyze_events, format_report, load_events, parse_event

ROOT = Path(__file__).resolve().parent.parent


def event(minute=0, outcome='failure', ip='192.0.2.1', user='alice', line=1):
    return parse_event({'timestamp': f'2026-01-15T10:{minute:02d}:00Z',
                        'ip': ip, 'user': user, 'outcome': outcome}, line)


class AnalysisTests(unittest.TestCase):
    def test_threshold_crossing_not_every_failure(self):
        report = analyze_events([event(i) for i in range(8)])
        self.assertEqual(len(report['findings']), 1)
        self.assertEqual(report['findings'][0]['code'], 'REPEATED_FAILURES')
        self.assertEqual(report['findings'][0]['failures'], 5)
        self.assertEqual(report['summary']['failures_by_ip'], {'192.0.2.1': 8})

    def test_success_correlates_same_user_and_ip(self):
        events = [event(i) for i in range(5)] + [event(5, 'success')]
        report = analyze_events(events)
        self.assertEqual([f['code'] for f in report['findings']], ['REPEATED_FAILURES', 'SUCCESS_AFTER_FAILURES'])
        self.assertEqual(report['findings'][1]['user'], 'alice')
        self.assertEqual(report['summary']['successes'], 1)

    def test_success_does_not_mix_users_or_ips(self):
        events = [event(i) for i in range(5)]
        events += [event(5, 'success', user='bob'), event(6, 'success', ip='192.0.2.2')]
        self.assertEqual(len(analyze_events(events)['findings']), 1)

    def test_failures_across_users_aggregate_by_ip(self):
        events = [event(i, user=f'user{i}') for i in range(5)] + [event(5, 'success')]
        self.assertEqual(len(analyze_events(events)['findings']), 1)

    def test_success_resets_user_history(self):
        events = [event(i) for i in range(5)] + [event(5, 'success'), event(6, 'success')]
        findings = analyze_events(events)['findings']
        self.assertEqual(sum(f['code'] == 'SUCCESS_AFTER_FAILURES' for f in findings), 1)

    def test_success_below_threshold_also_resets(self):
        events = [event(0), event(1, 'success'), event(2), event(3, 'success')]
        findings = analyze_events(events, threshold=2)['findings']
        self.assertEqual([f['code'] for f in findings], ['REPEATED_FAILURES'])

    def test_window_boundary_included(self):
        self.assertEqual(len(analyze_events([event(0), event(10)], threshold=2)['findings']), 1)
        self.assertEqual(analyze_events([event(0), event(11)], threshold=2)['findings'], [])

    def test_stale_failures_do_not_correlate_with_success(self):
        events = [event(i) for i in range(5)] + [event(20, 'success')]
        self.assertEqual(len(analyze_events(events)['findings']), 1)

    def test_new_episode_after_window_expires(self):
        events = [event(0), event(1), event(20), event(21)]
        self.assertEqual(len(analyze_events(events, threshold=2)['findings']), 2)

    def test_unsorted_input_is_sorted_without_mutation(self):
        events = [event(3, 'success'), event(1), event(0)]
        original = list(events)
        self.assertEqual(len(analyze_events(events, threshold=2)['findings']), 2)
        self.assertEqual(events, original)

    def test_equal_timestamp_uses_line_order(self):
        events = [event(0, 'success', line=3), event(0, line=2), event(0, line=1)]
        self.assertEqual(len(analyze_events(events, threshold=2)['findings']), 2)

    def test_timezones_and_ipv6_normalized(self):
        record = {'timestamp': '2026-01-15T12:00:00+02:00', 'ip': '2001:0db8::1', 'user': 'alice', 'outcome': 'success'}
        parsed = parse_event(record, 1)
        self.assertEqual(parsed.ip, '2001:db8::1')
        self.assertEqual(parsed.timestamp, datetime(2026, 1, 15, 10, tzinfo=timezone.utc))

    def test_minimum_datetime(self):
        parsed = parse_event({'timestamp': '0001-01-01T00:00:00Z', 'ip': '192.0.2.1', 'user': 'alice', 'outcome': 'success'}, 1)
        self.assertEqual(analyze_events([parsed])['summary']['events'], 1)

    def test_validation(self):
        valid = {'timestamp': '2026-01-15T10:00:00Z', 'ip': '192.0.2.1', 'user': 'alice', 'outcome': 'failure'}
        invalid = [None, [], {}, dict(valid, timestamp='2026-01-15T10:00:00'), dict(valid, timestamp='yesterday'),
                   dict(valid, timestamp='2026-99-99T00:00:00Z'), dict(valid, ip='host.example'),
                   dict(valid, user=' '), dict(valid, user=123), dict(valid, outcome='unknown')]
        for record in invalid:
            with self.subTest(record=record), self.assertRaises(LogError):
                parse_event(record, 2)

    def test_invalid_settings(self):
        for threshold in (0, 1, True, 2.5):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                analyze_events([], threshold=threshold)
        for minutes in (0, -1, 10081, True, 1.5):
            with self.subTest(minutes=minutes), self.assertRaises(ValueError):
                analyze_events([], window_minutes=minutes)

    def test_text_escapes_user_control_characters(self):
        events = [event(0, user='a\n\x1b'), event(1, user='a\n\x1b'), event(2, 'success', user='a\n\x1b')]
        text = format_report(analyze_events(events, threshold=2))
        self.assertIn('a\\n\\u001b', text)
        self.assertNotIn('\x1b', text)


class CLITests(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        return subprocess.run([sys.executable, str(ROOT / 'analyzer.py'), *map(str, args)],
                              cwd=cwd, capture_output=True, text=True)

    def test_suspicious_example_json(self):
        result = self.run_cli(ROOT / 'examples/suspicious.jsonl', '--format', 'json', '--fail-on-findings')
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(len(report['findings']), 2)
        self.assertEqual(report['summary']['events'], 7)
        self.assertEqual(report['summary']['unique_users'], 2)
        self.assertEqual(report['summary']['unique_ips'], 2)
        self.assertEqual(report['summary']['first_seen'], '2026-01-15T10:00:00Z')

    def test_normal_example(self):
        result = self.run_cli(ROOT / 'examples/normal.jsonl', '--fail-on-findings')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('No targeted patterns', result.stdout)

    def test_findings_default_exit_success(self):
        result = self.run_cli(ROOT / 'examples/suspicious.jsonl')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SUCCESS_AFTER_FAILURES', result.stdout)

    def test_options(self):
        result = self.run_cli(ROOT / 'examples/normal.jsonl', '--threshold', '2', '--window-minutes', '1', '--format', 'json')
        self.assertEqual(json.loads(result.stdout)['settings'], {'threshold': 2, 'window_minutes': 1})
        for args in [('--threshold', '1'), ('--window-minutes', '0'), ('--threshold', 'abc')]:
            self.assertEqual(self.run_cli(ROOT / 'examples/normal.jsonl', *args).returncode, 2)

    def test_errors_are_not_partial_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'bad.jsonl'
            for contents in ('', '\n ', '{', '{}', '[]', '{"user":"x"}\n{}', '\ufffd'):
                path.write_text(contents, encoding='utf-8')
                result = self.run_cli(path)
                self.assertEqual(result.returncode, 2, contents)
                self.assertIn('Error:', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertEqual(result.stdout, '')
            path.write_bytes(b'\xff')
            self.assertEqual(self.run_cli(path).returncode, 2)
            self.assertEqual(self.run_cli(Path(directory) / 'missing.jsonl').returncode, 2)

    def test_blank_lines_and_line_numbers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'log.jsonl'
            record = '{"timestamp":"2026-01-15T10:00:00Z","ip":"192.0.2.1","user":"demo","outcome":"success"}'
            path.write_text('\n' + record + '\n\n', encoding='utf-8')
            self.assertEqual(len(load_events(path)), 1)
            path.write_text('\n' + record + '\n{', encoding='utf-8')
            result = self.run_cli(path)
            self.assertEqual(result.returncode, 2)
            self.assertIn('Line 3', result.stderr)

    def test_other_working_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(self.run_cli(ROOT / 'examples/normal.jsonl', cwd=directory).returncode, 0)

    def test_help_and_required_argument(self):
        self.assertEqual(self.run_cli('--help').returncode, 0)
        self.assertEqual(self.run_cli().returncode, 2)


if __name__ == '__main__':
    unittest.main()
