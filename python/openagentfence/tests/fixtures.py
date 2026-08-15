"""Synthetic trace fixtures.

Every credential-shaped string here is fake and generated for tests. Real
OpenAgentFence traces never carry raw secret values at all: secrets appear as
opaque handles such as ``<SECRET:demo_login:ab12cd>``. The fixtures below
include a few raw-looking values anyway, because the point of the redaction
tests is to prove that this reader masks them if a malformed or hand-edited
trace ever contains one.
"""

from __future__ import annotations

import json
from typing import Any

# Synthetic, non-functional values used only to assert that redaction fires.
FAKE_TOKEN = "synthetic-token-not-a-real-credential"
FAKE_PASSWORD = "synthetic-password-not-a-real-credential"
FAKE_COOKIE = "synthetic-session-cookie-not-a-real-credential"
FAKE_PRIVATE_KEY = "synthetic-private-key-not-a-real-credential"
FAKE_API_KEY = "synthetic-api-key-not-a-real-credential"

# The handle form the TypeScript runtime actually writes (ADR-0005).
SECRET_HANDLE = "<SECRET:demo_login:ab12cd>"

ALL_FAKE_SECRETS = (
    FAKE_TOKEN,
    FAKE_PASSWORD,
    FAKE_COOKIE,
    FAKE_PRIVATE_KEY,
    FAKE_API_KEY,
)


def sample_trace() -> dict[str, Any]:
    """A trace with top-level findings/decisions and unknown forward fields."""
    return {
        "traceVersion": "0.1.0",
        "sessionId": "sess-01HZY",
        "startedAt": "2026-08-15T09:00:00Z",
        # A field this reader knows nothing about; it must survive round-trip.
        "futureField": {"unknownNested": [1, 2, 3]},
        "findings": [
            {
                "id": "f-1",
                "kind": "prompt_injection",
                "severity": "high",
                "evidence": {"excerpt": "ignore previous instructions"},
            },
            {
                "id": "f-2",
                "kind": "secret_egress",
                "severity": "critical",
                "context": {"authorization": FAKE_TOKEN},
            },
            {"id": "f-3", "kind": "origin_policy", "severity": "low"},
        ],
        "decisions": [
            {"id": "d-1", "verdict": "ALLOW", "reasons": []},
            {"id": "d-2", "verdict": "DENY", "reasons": ["ORIGIN_NOT_ALLOWED"]},
            {"id": "d-3", "verdict": "REQUIRE_APPROVAL", "reasons": ["HIGH_RISK"]},
            {"id": "d-4", "verdict": "DENY", "reasons": ["SECRET_SINK_UNBOUND"]},
            {"id": "d-5", "verdict": "ALLOW", "reasons": []},
        ],
        "vault": {
            "handles": [SECRET_HANDLE],
            "password": FAKE_PASSWORD,
            "api_key": FAKE_API_KEY,
            "X-Api-Key": FAKE_API_KEY,
            "session_cookie": FAKE_COOKIE,
            "private_key": FAKE_PRIVATE_KEY,
            "adapter": "in-memory",
        },
    }


def event_trace() -> dict[str, Any]:
    """A trace that carries only an event log, with no top-level collections."""
    return {
        "traceVersion": "0.1.0",
        "session": {"id": "sess-events"},
        "events": [
            {"kind": "session_start", "at": 0},
            {"kind": "finding", "id": "f-1", "severity": "medium"},
            {"kind": "finding", "id": "f-2", "severity": "high"},
            {"kind": "policy_decision", "id": "d-1", "verdict": "DENY"},
            {"kind": "policyDecision", "id": "d-2", "verdict": "ALLOW"},
            {"kind": "session_end", "at": 12},
            "a non-object event that must not crash the reader",
        ],
    }


def write_trace(path, document: Any) -> None:
    """Write ``document`` to ``path`` as UTF-8 JSON."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(document, handle)
