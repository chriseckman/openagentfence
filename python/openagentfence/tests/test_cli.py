"""Tests for ``python -m openagentfence``.

The CLI is exercised as a real subprocess so the assertions cover what a user
actually sees on stdout/stderr, including the exit status.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
SRC = _HERE.parent / "src"
for _entry in (str(SRC), str(_HERE)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import fixtures  # noqa: E402  (path bootstrap must run first)


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    """Run the module CLI in a subprocess with the in-tree package importable."""
    env = dict(os.environ)
    existing = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(SRC) + (os.pathsep + existing if existing else "")
    return subprocess.run(
        [sys.executable, "-m", "openagentfence", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = Path(self._tmp.name)
        self.trace_path = self.tmp_path / "trace.json"
        fixtures.write_trace(self.trace_path, fixtures.sample_trace())

    def test_version_output(self) -> None:
        result = run_cli("--version")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "openagentfence 0.0.1")

    def test_trace_summary_output(self) -> None:
        result = run_cli(str(self.trace_path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "OpenAgentFence trace",
                "Session: sess-01HZY",
                "Findings: 3",
                "Decisions: 5",
            ],
        )

    def test_summary_does_not_dump_the_trace(self) -> None:
        result = run_cli(str(self.trace_path))
        self.assertNotIn("futureField", result.stdout)
        self.assertNotIn("prompt_injection", result.stdout)

    def test_no_raw_secret_reaches_stdout_or_stderr(self) -> None:
        result = run_cli(str(self.trace_path))
        combined = result.stdout + result.stderr
        for secret in fixtures.ALL_FAKE_SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, combined)

    def test_unknown_session_is_reported(self) -> None:
        path = self.tmp_path / "empty.json"
        fixtures.write_trace(path, {})
        result = run_cli(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Session: unknown", result.stdout)

    def test_malformed_trace_fails_cleanly(self) -> None:
        path = self.tmp_path / "bad.json"
        path.write_text('{"sessionId": ', encoding="utf-8")
        result = run_cli(str(path))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, "")
        self.assertIn("invalid JSON", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_file_fails_cleanly(self) -> None:
        result = run_cli(str(self.tmp_path / "absent.json"))
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

    def test_size_limit_is_enforced_from_the_cli(self) -> None:
        result = run_cli("--max-bytes", "16", str(self.trace_path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("limit", result.stderr)

    def test_invalid_size_limit_is_rejected(self) -> None:
        result = run_cli("--max-bytes", "0", str(self.trace_path))
        self.assertEqual(result.returncode, 2)

    def test_missing_argument_is_a_usage_error(self) -> None:
        result = run_cli()
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage: openagentfence", result.stderr)

    def test_event_only_trace_summary(self) -> None:
        path = self.tmp_path / "events.json"
        fixtures.write_trace(path, fixtures.event_trace())
        result = run_cli(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Session: sess-events", result.stdout)
        self.assertIn("Findings: 2", result.stdout)
        self.assertIn("Decisions: 2", result.stdout)

    def test_cli_makes_no_use_of_json_dump_of_secrets(self) -> None:
        # A trace whose every top-level field is secret-bearing still yields a
        # summary with no values in it.
        path = self.tmp_path / "secrets.json"
        fixtures.write_trace(
            path,
            {
                "sessionId": "sess-secret",
                "authorization": fixtures.FAKE_TOKEN,
                "cookie": fixtures.FAKE_COOKIE,
                "findings": [{"private_key": fixtures.FAKE_PRIVATE_KEY}],
            },
        )
        result = run_cli(str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        combined = result.stdout + result.stderr
        for secret in fixtures.ALL_FAKE_SECRETS:
            self.assertNotIn(secret, combined)
        self.assertIn("Findings: 1", result.stdout)


class CliJsonFixtureTests(unittest.TestCase):
    def test_fixture_files_contain_no_real_credentials(self) -> None:
        # Guard against a future edit dropping a live value into the fixtures.
        rendered = json.dumps(
            [fixtures.sample_trace(), fixtures.event_trace()], sort_keys=True
        )
        for secret in fixtures.ALL_FAKE_SECRETS:
            self.assertIn("synthetic", secret)
        self.assertIn("synthetic", rendered)


if __name__ == "__main__":
    unittest.main()
