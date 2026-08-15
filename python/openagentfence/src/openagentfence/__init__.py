"""Python interoperability utilities for OpenAgentFence.

OpenAgentFence itself is TypeScript/Node.js. This package does not implement the
security runtime, its scanners, or its policy engine; it reads the artifacts that
runtime produces so Python tooling can work with them.

    >>> from openagentfence import Trace
    >>> trace = Trace.load("trace.json")           # doctest: +SKIP
    >>> trace.session_id                            # doctest: +SKIP
    'sess-01'

Early development: the API is unstable before 1.0.
"""

from __future__ import annotations

from .trace import (
    DEFAULT_MAX_BYTES,
    DEPTH_LIMITED,
    MAX_REDACTION_DEPTH,
    REDACTED,
    SENSITIVE_KEY_FRAGMENTS,
    Trace,
    TraceError,
    TraceFormatError,
    TraceSizeError,
    TraceSourceError,
    is_sensitive_key,
    redact,
)

__version__ = "0.0.1"

__all__ = [
    "DEFAULT_MAX_BYTES",
    "DEPTH_LIMITED",
    "MAX_REDACTION_DEPTH",
    "REDACTED",
    "SENSITIVE_KEY_FRAGMENTS",
    "Trace",
    "TraceError",
    "TraceFormatError",
    "TraceSizeError",
    "TraceSourceError",
    "__version__",
    "is_sensitive_key",
    "redact",
]
