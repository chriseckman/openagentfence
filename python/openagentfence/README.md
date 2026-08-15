# openagentfence (Python)

Python interoperability utilities for [OpenAgentFence](https://github.com/chriseckman/openagentfence).

> **Early development.** OpenAgentFence is pre-release and this package is
> version `0.0.1`. The API is experimental and may change without notice before
> `1.0`. Do not treat it as production-ready.

## What this package is — and is not

OpenAgentFence is security middleware for AI browser agents. Its primary
implementation is **TypeScript/Node.js**, and that is where the security runtime
lives: the scanners, the policy engine, the action guard, secret handling, and
the framework adapters.

This Python distribution is **not** a Python port of that runtime. It does not
detect prompt injection, evaluate policy, mediate browser actions, or resolve
secrets. It is a small, dependency-free reader for the **artifacts** the
TypeScript runtime produces, so Python tooling — notebooks, CI checks, analysis
scripts — can work with them without shelling out to Node.

Version `0.0.1` covers one artifact: the JSON **security trace**.

## Install

```bash
pip install openagentfence
```

Requires Python 3.10 or newer. It has no runtime dependencies.

## Load a trace

```python
from openagentfence import Trace

trace = Trace.load("trace.json")

print(trace.session_id)      # 'sess-01HZY' or None
print(trace.trace_version)   # '0.1.0' or None
print(trace.finding_count)   # 3
print(trace.decision_count)  # 5

for finding in trace.findings:
    print(finding)
```

The reader is deliberately tolerant. The trace schema is still being settled in
the TypeScript core, so this package requires only that the document root is a
JSON object and preserves every field it does not recognise:

```python
trace.raw["someFieldAddedNextRelease"]   # unknown fields survive intact
```

`findings` and `decisions` come from top-level arrays when present, and are
otherwise derived from event records whose kind names a finding or a decision.

### Redaction

Accessors return **redacted** data by default. Any value stored under an
obviously secret-bearing key — `password`, `secret`, `token`, `api_key`,
`authorization`, `cookie`, `private_key`, `credential`, and similar — is
replaced with `[redacted]`, however deeply nested:

```python
trace.findings          # redacted
trace.decisions         # redacted
trace.redacted()        # redacted copy of the whole document
trace.get("headers")    # redacted

trace.raw               # the unmodified document, when you explicitly need it
trace.raw_findings      # unredacted
```

Matching is conservative and key-based: it prefers to mask a harmless field over
leaking a sensitive one.

OpenAgentFence traces should not contain raw secrets in the first place — the
runtime writes opaque handles such as `<SECRET:demo_login:ab12cd>`. This package
passes handles through untouched and **never** attempts to resolve one;
resolution is an executor-side concern of the TypeScript runtime.

## Command line

```bash
python -m openagentfence trace.json
```

```text
OpenAgentFence trace
Session: sess-01HZY
Findings: 3
Decisions: 5
```

The CLI prints only this sanitized summary; it never dumps the trace document.

```bash
python -m openagentfence --version
python -m openagentfence --max-bytes 1048576 trace.json
```

## Handling untrusted traces

A security trace can describe hostile web content, so it is treated as untrusted
input:

- Parsing is `json` only — no `eval`, no pickle, no dynamic imports, and no
  hooks that construct arbitrary Python objects.
- Input is bounded. `Trace.load` refuses files over 8 MiB by default
  (`max_bytes` is configurable), and redaction is depth-limited.
- Duplicate object keys and non-standard JSON constants (`NaN`, `Infinity`) are
  rejected rather than silently resolved.
- No network access and no URL resolution ever happen while loading a trace.
- Parse errors do not carry the document, and the session identifier is
  sanitized before display so trace content cannot forge terminal output.

## Project

- Repository: <https://github.com/chriseckman/openagentfence>
- Security policy: <https://github.com/chriseckman/openagentfence/security/policy>

## License

Apache-2.0. Copyright 2026 Christopher Eckman.
