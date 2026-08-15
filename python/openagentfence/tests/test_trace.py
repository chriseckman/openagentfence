"""Tests for the trace reader."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent
SRC = _HERE.parent / "src"
# Importable whether discovery starts at the tests directory or at the package
# root, and without requiring an editable install.
for _entry in (str(SRC), str(_HERE)):
    if _entry not in sys.path:
        sys.path.insert(0, _entry)

import fixtures  # noqa: E402  (path bootstrap must run first)
import openagentfence  # noqa: E402
from openagentfence import (  # noqa: E402
    REDACTED,
    Trace,
    TraceError,
    TraceFormatError,
    TraceSizeError,
    TraceSourceError,
    is_sensitive_key,
    redact,
)


class TempTraceCase(unittest.TestCase):
    """Base case providing a temporary directory."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp_path = Path(self._tmp.name)

    def write(self, name: str, content: str) -> Path:
        path = self.tmp_path / name
        path.write_text(content, encoding="utf-8")
        return path

    def write_json(self, name: str, document: object) -> Path:
        return self.write(name, json.dumps(document))


class PackageTests(unittest.TestCase):
    def test_package_imports(self) -> None:
        self.assertTrue(hasattr(openagentfence, "Trace"))
        self.assertIs(openagentfence.Trace, Trace)

    def test_version_is_reported(self) -> None:
        self.assertEqual(openagentfence.__version__, "0.0.1")

    def test_exception_hierarchy(self) -> None:
        for error in (TraceFormatError, TraceSizeError, TraceSourceError):
            self.assertTrue(issubclass(error, TraceError))


class LoadTests(TempTraceCase):
    def test_loads_valid_trace(self) -> None:
        path = self.write_json("trace.json", fixtures.sample_trace())
        trace = Trace.load(path)

        self.assertEqual(trace.session_id, "sess-01HZY")
        self.assertEqual(trace.trace_version, "0.1.0")
        self.assertEqual(trace.finding_count, 3)
        self.assertEqual(trace.decision_count, 5)
        self.assertEqual(trace.source, str(path))

    def test_loads_from_json_string(self) -> None:
        trace = Trace.from_json(json.dumps({"sessionId": "s"}))
        self.assertEqual(trace.session_id, "s")
        self.assertIsNone(trace.source)

    def test_tolerates_utf8_bom(self) -> None:
        path = self.tmp_path / "bom.json"
        path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"sessionId": "s"}).encode())
        self.assertEqual(Trace.load(path).session_id, "s")

    def test_missing_session_id_is_none(self) -> None:
        self.assertIsNone(Trace.from_json("{}").session_id)

    def test_session_id_from_nested_session_object(self) -> None:
        trace = Trace.from_json(json.dumps(fixtures.event_trace()))
        self.assertEqual(trace.session_id, "sess-events")

    def test_rejects_malformed_json(self) -> None:
        path = self.write("bad.json", '{"sessionId": ')
        with self.assertRaises(TraceFormatError):
            Trace.load(path)

    def test_malformed_json_error_does_not_carry_the_document(self) -> None:
        # json.JSONDecodeError keeps the whole document on `.doc`; the reader
        # must not chain it, or protected content rides along on the exception.
        path = self.write("bad.json", '{"password": "' + fixtures.FAKE_PASSWORD + '"')
        with self.assertRaises(TraceFormatError) as caught:
            Trace.load(path)
        self.assertIsNone(caught.exception.__cause__)
        self.assertNotIn(fixtures.FAKE_PASSWORD, str(caught.exception))

    def test_rejects_non_object_roots(self) -> None:
        for name, payload in (
            ("array.json", "[1, 2, 3]"),
            ("string.json", '"just a string"'),
            ("number.json", "42"),
            ("null.json", "null"),
            ("bool.json", "true"),
        ):
            with self.subTest(payload=name):
                path = self.write(name, payload)
                with self.assertRaises(TraceFormatError):
                    Trace.load(path)

    def test_rejects_duplicate_object_keys(self) -> None:
        path = self.write("dup.json", '{"sessionId": "a", "sessionId": "b"}')
        with self.assertRaises(TraceFormatError):
            Trace.load(path)

    def test_rejects_non_standard_json_constants(self) -> None:
        for name, payload in (
            ("nan.json", '{"value": NaN}'),
            ("inf.json", '{"value": Infinity}'),
        ):
            with self.subTest(payload=name):
                path = self.write(name, payload)
                with self.assertRaises(TraceFormatError):
                    Trace.load(path)

    def test_rejects_undecodable_bytes(self) -> None:
        path = self.tmp_path / "binary.json"
        path.write_bytes(b"\xff\xfe\x00{")
        with self.assertRaises(TraceFormatError):
            Trace.load(path)

    def test_rejects_missing_file(self) -> None:
        with self.assertRaises(TraceSourceError):
            Trace.load(self.tmp_path / "nope.json")

    def test_rejects_directory(self) -> None:
        with self.assertRaises(TraceSourceError):
            Trace.load(self.tmp_path)


class SizeLimitTests(TempTraceCase):
    def test_rejects_input_over_the_limit(self) -> None:
        document = {"sessionId": "s", "padding": "x" * 4096}
        path = self.write_json("big.json", document)
        with self.assertRaises(TraceSizeError):
            Trace.load(path, max_bytes=1024)

    def test_accepts_input_under_the_limit(self) -> None:
        path = self.write_json("small.json", {"sessionId": "s"})
        self.assertEqual(Trace.load(path, max_bytes=1024).session_id, "s")

    def test_limit_is_inclusive_at_the_boundary(self) -> None:
        path = self.write_json("exact.json", {"a": "b"})
        size = path.stat().st_size
        self.assertEqual(Trace.load(path, max_bytes=size).get("a"), "b")
        with self.assertRaises(TraceSizeError):
            Trace.load(path, max_bytes=size - 1)

    def test_non_positive_limit_is_rejected(self) -> None:
        path = self.write_json("trace.json", {"a": "b"})
        for limit in (0, -1):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                Trace.load(path, max_bytes=limit)


class CollectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = Trace(fixtures.sample_trace())
        self.events = Trace(fixtures.event_trace())

    def test_findings_from_top_level_array(self) -> None:
        findings = self.trace.findings
        self.assertEqual(len(findings), 3)
        self.assertEqual(findings[0]["id"], "f-1")
        self.assertEqual(self.trace.finding_count, 3)

    def test_decisions_from_top_level_array(self) -> None:
        decisions = self.trace.decisions
        self.assertEqual(len(decisions), 5)
        self.assertEqual(decisions[1]["verdict"], "DENY")
        self.assertEqual(self.trace.decision_count, 5)

    def test_findings_derived_from_events(self) -> None:
        self.assertEqual(self.events.finding_count, 2)
        self.assertEqual([f["id"] for f in self.events.findings], ["f-1", "f-2"])

    def test_decisions_derived_from_events(self) -> None:
        self.assertEqual(self.events.decision_count, 2)
        self.assertEqual([d["id"] for d in self.events.decisions], ["d-1", "d-2"])

    def test_non_object_events_are_ignored_not_fatal(self) -> None:
        self.assertEqual(self.events.event_count, 7)
        self.assertEqual(self.events.finding_count, 2)

    def test_missing_collections_are_empty(self) -> None:
        trace = Trace({"sessionId": "s"})
        self.assertEqual(trace.findings, ())
        self.assertEqual(trace.decisions, ())
        self.assertEqual(trace.finding_count, 0)
        self.assertEqual(trace.decision_count, 0)

    def test_wrong_typed_collections_do_not_crash(self) -> None:
        trace = Trace({"findings": {"not": "a list"}, "decisions": "nope"})
        self.assertEqual(trace.findings, ())
        self.assertEqual(trace.decisions, ())


class ForwardCompatibilityTests(unittest.TestCase):
    def test_unknown_fields_are_preserved(self) -> None:
        trace = Trace(fixtures.sample_trace())
        self.assertEqual(trace.raw["futureField"], {"unknownNested": [1, 2, 3]})
        self.assertEqual(trace.get("futureField"), {"unknownNested": [1, 2, 3]})
        self.assertIn("futureField", trace.redacted())

    def test_unknown_fields_survive_a_json_round_trip(self) -> None:
        original = {"sessionId": "s", "brandNew": {"deep": ["a", 1, None, True]}}
        trace = Trace.from_json(json.dumps(original))
        self.assertEqual(dict(trace.raw), original)

    def test_raw_view_is_read_only(self) -> None:
        trace = Trace({"a": "b"})
        with self.assertRaises(TypeError):
            trace.raw["a"] = "c"  # type: ignore[index]

    def test_unknown_event_kinds_are_kept_but_unclassified(self) -> None:
        trace = Trace({"events": [{"kind": "some_future_event"}]})
        self.assertEqual(trace.event_count, 1)
        self.assertEqual(trace.finding_count, 0)
        self.assertEqual(trace.decision_count, 0)


class RedactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.trace = Trace(fixtures.sample_trace())

    def test_sensitive_key_detection(self) -> None:
        for key in (
            "password",
            "passwd",
            "secret",
            "token",
            "api_key",
            "apikey",
            "authorization",
            "cookie",
            "session_cookie",
            "private_key",
            "credential",
            "X-Api-Key",
            "accessToken",
            "clientSecret",
            "CREDENTIALS",
        ):
            with self.subTest(key=key):
                self.assertTrue(is_sensitive_key(key))

        for key in ("sessionId", "verdict", "severity", "url", "reasons"):
            with self.subTest(key=key):
                self.assertFalse(is_sensitive_key(key))

    def test_matching_is_deliberately_conservative(self) -> None:
        # Substring matching over-redacts rather than under-redacts. Keys such
        # as these carry no secret, but masking them is the safe direction.
        for key in ("notASecret", "tokenCount", "cookieBannerDismissed"):
            with self.subTest(key=key):
                self.assertTrue(is_sensitive_key(key))

    def test_redacted_document_masks_sensitive_values(self) -> None:
        redacted = self.trace.redacted()
        vault = redacted["vault"]
        for key in ("password", "api_key", "X-Api-Key", "session_cookie", "private_key"):
            self.assertEqual(vault[key], REDACTED)
        self.assertEqual(vault["adapter"], "in-memory")

    def test_redaction_reaches_nested_findings(self) -> None:
        findings = self.trace.findings
        self.assertEqual(findings[1]["context"]["authorization"], REDACTED)

    def test_no_fake_secret_survives_in_default_views(self) -> None:
        rendered = json.dumps(
            {
                "redacted": self.trace.redacted(),
                "findings": self.trace.findings,
                "decisions": self.trace.decisions,
                "events": self.trace.events,
                "summary": self.trace.summary(),
                "repr": repr(self.trace),
            }
        )
        for secret in fixtures.ALL_FAKE_SECRETS:
            with self.subTest(secret=secret):
                self.assertNotIn(secret, rendered)

    def test_raw_access_is_explicit_and_unredacted(self) -> None:
        self.assertEqual(self.trace.raw["vault"]["password"], fixtures.FAKE_PASSWORD)
        self.assertEqual(
            self.trace.raw_findings[1]["context"]["authorization"], fixtures.FAKE_TOKEN
        )

    def test_get_masks_a_sensitive_top_level_key(self) -> None:
        trace = Trace({"authorization": fixtures.FAKE_TOKEN})
        self.assertEqual(trace.get("authorization"), REDACTED)
        self.assertIsNone(trace.get("absent"))
        self.assertEqual(trace.get("absent", "fallback"), "fallback")

    def test_secret_handles_are_preserved_never_resolved(self) -> None:
        # Handles are inert references (ADR-0005); this package must pass them
        # through untouched and must never try to resolve one.
        self.assertIn(fixtures.SECRET_HANDLE, self.trace.redacted()["vault"]["handles"])

    def test_redaction_does_not_mutate_the_source_document(self) -> None:
        document = fixtures.sample_trace()
        trace = Trace(document)
        trace.redacted()
        self.assertEqual(document["vault"]["password"], fixtures.FAKE_PASSWORD)

    def test_redaction_is_depth_limited(self) -> None:
        deep: object = "leaf"
        for _ in range(50):
            deep = {"next": deep}
        result = redact(deep, max_depth=5)
        rendered = json.dumps(result)
        self.assertIn("[depth-limited]", rendered)
        self.assertNotIn("leaf", rendered)

    def test_redaction_handles_scalars_and_sequences(self) -> None:
        self.assertEqual(redact("plain"), "plain")
        self.assertEqual(redact([{"token": "x"}]), [{"token": REDACTED}])
        self.assertEqual(redact(None), None)

    def test_negative_depth_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            redact({}, max_depth=-1)


class SummaryTests(unittest.TestCase):
    def test_summary_shape(self) -> None:
        summary = Trace(fixtures.sample_trace()).summary()
        self.assertEqual(
            summary.splitlines(),
            [
                "OpenAgentFence trace",
                "Session: sess-01HZY",
                "Findings: 3",
                "Decisions: 5",
            ],
        )

    def test_summary_reports_unknown_session(self) -> None:
        self.assertIn("Session: unknown", Trace({}).summary())

    def test_summary_sanitizes_hostile_session_ids(self) -> None:
        hostile = "\x1b[31mred\nFindings: 999"
        summary = Trace({"sessionId": hostile}).summary()
        self.assertEqual(len(summary.splitlines()), 4)
        self.assertNotIn("\x1b", summary)
        self.assertIn("Findings: 0", summary)

    def test_summary_truncates_long_session_ids(self) -> None:
        summary = Trace({"sessionId": "s" * 500}).summary()
        session_line = summary.splitlines()[1]
        self.assertLess(len(session_line), 200)
        self.assertTrue(session_line.endswith("..."))


if __name__ == "__main__":
    unittest.main()
