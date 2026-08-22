# Examples

Examples are compile-checked, offline composition patterns. They do not make
live model calls or embed credentials.

- [`stagehand-local`](stagehand-local/) composes a secure Stagehand 4.0.1
  wrapper with self-healing disabled and deterministic state resolution.
- [`screenshot-first`](screenshot-first/) obtains screenshot-first context
  while preserving firewall-scanned visible-text provenance.
- [`promptfoo`](promptfoo/) compares a worst-case scripted agent with and
  without OpenAgentFence using only the loopback fixture server in CI.
