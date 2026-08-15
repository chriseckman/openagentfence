"""Tolerant reader for OpenAgentFence security traces.

OpenAgentFence writes a redacted, append-only JSON security trace per session.
The trace format is versioned and still evolving in the TypeScript core, so this
reader is deliberately *tolerant*: it requires only that the document root is a
JSON object, preserves every field it does not understand, and exposes the
handful of fields that are stable enough to be useful.

Security posture (this module is used on untrusted input):

- Trace content is data, never code. Parsing uses :mod:`json` only; there is no
  ``eval``, no pickle, no dynamic import, and no object hooks that construct
  arbitrary Python types.
- Input is bounded: :meth:`Trace.load` refuses files larger than ``max_bytes``
  and recursion during redaction is depth-limited.
- No network access and no URL resolution ever happens here. URLs inside a trace
  are treated as opaque strings.
- Secret *handles* (``<SECRET:name:shortid>``) are never resolved; resolving them
  is an executor-side concern of the TypeScript runtime and is out of scope for
  this package.
- Values under obviously secret-bearing keys are redacted from every default
  accessor. The unmodified document remains reachable through :attr:`Trace.raw`
  for callers that explicitly ask for it.
"""

from __future__ import annotations

import json
import os
import stat as stat_module
from collections.abc import Mapping
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

__all__ = [
    "DEFAULT_MAX_BYTES",
    "MAX_REDACTION_DEPTH",
    "REDACTED",
    "SENSITIVE_KEY_FRAGMENTS",
    "Trace",
    "TraceError",
    "TraceFormatError",
    "TraceSizeError",
    "TraceSourceError",
    "is_sensitive_key",
    "redact",
]

#: Default ceiling for a trace file read from disk (8 MiB).
DEFAULT_MAX_BYTES: Final[int] = 8 * 1024 * 1024

#: Maximum structural depth walked while redacting.
MAX_REDACTION_DEPTH: Final[int] = 64

#: Placeholder substituted for a value stored under a sensitive key.
REDACTED: Final[str] = "[redacted]"

#: Placeholder substituted for structure nested deeper than the redaction limit.
DEPTH_LIMITED: Final[str] = "[depth-limited]"

#: Normalized key fragments treated as secret-bearing. Matching is conservative:
#: a key is sensitive when its normalized form *contains* one of these.
SENSITIVE_KEY_FRAGMENTS: Final[frozenset[str]] = frozenset(
    {
        "apikey",
        "authorization",
        "cookie",
        "credential",
        "passwd",
        "password",
        "privatekey",
        "secret",
        "token",
    }
)

_SESSION_ID_KEYS: Final[tuple[str, ...]] = ("sessionId", "session_id", "id")
_TRACE_VERSION_KEYS: Final[tuple[str, ...]] = (
    "traceVersion",
    "trace_version",
    "schemaVersion",
    "schema_version",
    "version",
)
_FINDING_KEYS: Final[tuple[str, ...]] = ("findings",)
_DECISION_KEYS: Final[tuple[str, ...]] = (
    "decisions",
    "policyDecisions",
    "policy_decisions",
)
_EVENT_KEYS: Final[tuple[str, ...]] = ("events",)
_EVENT_KIND_KEYS: Final[tuple[str, ...]] = ("kind", "type", "eventType", "event_type")

_DISPLAY_LIMIT: Final[int] = 128

#: UTF-8 byte-order mark, tolerated at the start of a trace document.
_BOM: Final[str] = chr(0xFEFF)


class TraceError(Exception):
    """Base class for every error raised by this module."""


class TraceFormatError(TraceError):
    """The input was not a well-formed JSON object trace."""


class TraceSizeError(TraceError):
    """The input exceeded the configured maximum size."""


class TraceSourceError(TraceError):
    """The input path could not be used as a trace source."""


def _normalize_key(key: str) -> str:
    """Fold a key to lowercase alphanumerics so ``X-Api-Key`` matches ``apikey``."""
    return "".join(character for character in key.lower() if character.isalnum())


def is_sensitive_key(key: str) -> bool:
    """Return ``True`` when ``key`` looks like it carries a secret value."""
    normalized = _normalize_key(key)
    return any(fragment in normalized for fragment in SENSITIVE_KEY_FRAGMENTS)


def redact(value: Any, *, max_depth: int = MAX_REDACTION_DEPTH) -> Any:
    """Return a copy of ``value`` with secret-bearing entries replaced.

    Redaction is key-based and conservative: any mapping key whose normalized
    form contains a fragment from :data:`SENSITIVE_KEY_FRAGMENTS` has its value
    replaced with :data:`REDACTED`, however deeply nested. Structure below
    ``max_depth`` is replaced with :data:`DEPTH_LIMITED` so a hostile trace
    cannot drive unbounded recursion.
    """
    if max_depth < 0:
        raise ValueError("max_depth must not be negative")
    return _redact(value, max_depth)


def _redact(value: Any, depth: int) -> Any:
    if depth <= 0:
        return DEPTH_LIMITED
    if isinstance(value, Mapping):
        return {
            str(key): (
                REDACTED if is_sensitive_key(str(key)) else _redact(item, depth - 1)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_redact(item, depth - 1) for item in value]
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Object hook that refuses duplicate keys instead of silently keeping one.

    A trace whose objects repeat a key is ambiguous, and two readers can
    disagree about which value wins. For security-relevant data that ambiguity
    is a defect, so it is rejected rather than resolved.
    """
    document: dict[str, Any] = {}
    for key, value in pairs:
        if key in document:
            raise ValueError(f"duplicate object key: {key!r}")
        document[key] = value
    return document


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-standard JSON constant: {name}")


def _describe(source: str | None) -> str:
    return source if source else "<trace>"


def _sanitize_display(value: str, limit: int = _DISPLAY_LIMIT) -> str:
    """Make an untrusted string safe to write to a terminal.

    Control characters (including ANSI escape introducers and newlines) are
    replaced so trace content cannot forge output lines or drive a terminal, and
    the result is truncated to a bounded length.
    """
    cleaned = "".join(
        character if character.isprintable() else "?" for character in value
    )
    if len(cleaned) > limit:
        return cleaned[:limit] + "..."
    return cleaned


class Trace:
    """A parsed OpenAgentFence security trace.

    The document is held as plain JSON data. Accessors return redacted copies by
    default; :attr:`raw` exposes the unmodified document for callers that
    explicitly need it.
    """

    __slots__ = ("_document", "_source")

    def __init__(self, document: Mapping[str, Any], *, source: str | None = None):
        if not isinstance(document, Mapping):
            raise TraceFormatError(
                f"{_describe(source)}: trace root must be a JSON object, "
                f"got {type(document).__name__}"
            )
        self._document: dict[str, Any] = {str(key): value for key, value in document.items()}
        self._source = source

    # -- constructors ----------------------------------------------------

    @classmethod
    def load(
        cls,
        path: str | os.PathLike[str],
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        encoding: str = "utf-8",
    ) -> Trace:
        """Load a trace from a JSON file on disk.

        Raises :class:`TraceSourceError` if the path is not a readable regular
        file, :class:`TraceSizeError` if it exceeds ``max_bytes``, and
        :class:`TraceFormatError` if the contents are not a JSON object.
        """
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")

        file_path = Path(os.fspath(path))
        source = str(file_path)

        try:
            file_stat = file_path.stat()
        except OSError as error:
            raise TraceSourceError(f"{source}: cannot read trace: {error.strerror or error}") from None

        if not stat_module.S_ISREG(file_stat.st_mode):
            raise TraceSourceError(f"{source}: not a regular file")
        if file_stat.st_size > max_bytes:
            raise TraceSizeError(
                f"{source}: trace is {file_stat.st_size} bytes, "
                f"which exceeds the {max_bytes} byte limit"
            )

        try:
            with file_path.open("rb") as handle:
                # Read one byte past the limit so a file that grew between the
                # stat and the read is still rejected.
                payload = handle.read(max_bytes + 1)
        except OSError as error:
            raise TraceSourceError(f"{source}: cannot read trace: {error.strerror or error}") from None

        if len(payload) > max_bytes:
            raise TraceSizeError(
                f"{source}: trace exceeds the {max_bytes} byte limit"
            )

        try:
            text = payload.decode(encoding)
        except (UnicodeDecodeError, LookupError) as error:
            raise TraceFormatError(f"{source}: cannot decode as {encoding}: {error}") from None

        return cls.from_json(text, source=source)

    @classmethod
    def from_json(cls, text: str, *, source: str | None = None) -> Trace:
        """Parse a trace from a JSON string."""
        try:
            document = json.loads(
                text.removeprefix(_BOM),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (ValueError, RecursionError) as error:
            # Deliberately not chained: json.JSONDecodeError carries the whole
            # document on its ``doc`` attribute, and a trace may contain
            # protected content that should not ride along on an exception.
            raise TraceFormatError(f"{_describe(source)}: invalid JSON: {error}") from None
        # A non-object root is rejected by the constructor.
        return cls(document, source=source)

    # -- identity --------------------------------------------------------

    @property
    def source(self) -> str | None:
        """Where this trace was loaded from, when known."""
        return self._source

    @property
    def raw(self) -> Mapping[str, Any]:
        """The unmodified parsed document, including unknown fields.

        This is the explicit, unredacted view. Anything derived from it may
        contain values that the redacted accessors would have masked.
        """
        return MappingProxyType(self._document)

    @property
    def session_id(self) -> str | None:
        """The session identifier, if the trace carries one."""
        for key in _SESSION_ID_KEYS:
            value = self._document.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)
        session = self._document.get("session")
        if isinstance(session, Mapping):
            for key in _SESSION_ID_KEYS:
                value = session.get(key)
                if isinstance(value, str) and value:
                    return value
        return None

    @property
    def trace_version(self) -> str | None:
        """The declared trace/schema version, if present."""
        for key in _TRACE_VERSION_KEYS:
            value = self._document.get(key)
            if isinstance(value, str) and value:
                return value
            if isinstance(value, int) and not isinstance(value, bool):
                return str(value)
        return None

    # -- collections -----------------------------------------------------

    @property
    def raw_events(self) -> tuple[Any, ...]:
        """Trace events exactly as recorded (unredacted)."""
        return self._raw_collection(_EVENT_KEYS, None)

    @property
    def raw_findings(self) -> tuple[Any, ...]:
        """Findings exactly as recorded (unredacted)."""
        return self._raw_collection(_FINDING_KEYS, "finding")

    @property
    def raw_decisions(self) -> tuple[Any, ...]:
        """Policy decisions exactly as recorded (unredacted)."""
        return self._raw_collection(_DECISION_KEYS, "decision")

    @property
    def events(self) -> tuple[Any, ...]:
        """Redacted trace events."""
        return tuple(redact(event) for event in self.raw_events)

    @property
    def findings(self) -> tuple[Any, ...]:
        """Redacted findings.

        Taken from a top-level ``findings`` array when present, otherwise
        derived from event records whose kind names a finding.
        """
        return tuple(redact(finding) for finding in self.raw_findings)

    @property
    def decisions(self) -> tuple[Any, ...]:
        """Redacted policy decisions, derived the same way as :attr:`findings`."""
        return tuple(redact(decision) for decision in self.raw_decisions)

    @property
    def event_count(self) -> int:
        """Number of trace events."""
        return len(self.raw_events)

    @property
    def finding_count(self) -> int:
        """Number of findings."""
        return len(self.raw_findings)

    @property
    def decision_count(self) -> int:
        """Number of policy decisions."""
        return len(self.raw_decisions)

    def _raw_collection(
        self, keys: tuple[str, ...], event_kind: str | None
    ) -> tuple[Any, ...]:
        for key in keys:
            value = self._document.get(key)
            if isinstance(value, list):
                return tuple(value)
        if event_kind is None:
            return ()
        return tuple(
            event
            for event in self._raw_collection(_EVENT_KEYS, None)
            if _event_kind_matches(event, event_kind)
        )

    # -- access ----------------------------------------------------------

    def get(self, key: str, default: Any = None) -> Any:
        """Return a redacted top-level field, or ``default`` when absent."""
        if key not in self._document:
            return default
        if is_sensitive_key(key):
            return REDACTED
        return redact(self._document[key])

    def redacted(self) -> dict[str, Any]:
        """Return a redacted copy of the whole document."""
        result = redact(self._document)
        assert isinstance(result, dict)  # a Mapping always redacts to a dict
        return result

    def summary(self) -> str:
        """Return the short, sanitized summary used by the CLI."""
        session = self.session_id
        return "\n".join(
            (
                "OpenAgentFence trace",
                f"Session: {_sanitize_display(session) if session else 'unknown'}",
                f"Findings: {self.finding_count}",
                f"Decisions: {self.decision_count}",
            )
        )

    def __repr__(self) -> str:
        return (
            f"<Trace source={self._source!r} "
            f"findings={self.finding_count} decisions={self.decision_count}>"
        )


def _event_kind_matches(event: Any, fragment: str) -> bool:
    if not isinstance(event, Mapping):
        return False
    for key in _EVENT_KIND_KEYS:
        value = event.get(key)
        if isinstance(value, str) and fragment in _normalize_key(value):
            return True
    return False
