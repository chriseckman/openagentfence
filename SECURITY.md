# Security Policy

OpenAgentFence is security infrastructure for AI browser agents. Its own
security is treated as critical: it sits on a privileged execution path
between untrusted web content and authenticated browser capabilities. Thank
you for helping keep it trustworthy.

## Supported versions

OpenAgentFence is **pre-release**. No packages have been published and there
are no supported release lines yet.

Until stable releases exist:

- Security fixes land on the default branch (`main`).
- Once `0.x` packages are published, the **latest published minor version**
  is the supported line; fixes are released as patch versions on it. Older
  minors will not receive backports during `0.x` unless announced otherwise.
- From `1.0` onward, a supported-versions table will be maintained here.

## Reporting a vulnerability

**Please do not open a public GitHub issue for an exploitable vulnerability.**

Report privately using **GitHub Private Vulnerability Reporting** for this
repository:

`https://github.com/chriseckman/openagentfence/security/advisories/new`

If private reporting is not yet enabled on the repository when you look, do
not disclose details in a public issue. Open a public issue that says only
"security contact requested" without technical details, and a maintainer
will establish a private channel. (A dedicated contact address is not yet
published; this file will be updated when one is.)

Please include, where possible:

- The affected package/component and commit or version.
- A description of the impact (which invariant in
  [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) is violated, if you can tell).
- A minimal reproduction: an attack page/fixture, policy file, and the
  sequence of agent actions. Redact any real secrets.
- Whether the issue is already public.

## What should be reported

Anything that lets a browser agent escape the capability envelope that
OpenAgentFence is configured to enforce, or that leaks protected data. For
example:

- Prompt-injection bypasses that defeat sanitization or restricted mode in a
  way that leads to an unauthorized action or disclosure.
- Action Guard bypasses (an action executes without authorization, a wrapper
  authorizes one structured action but executes another, or a claimed
  state-bound adapter executes after relevant state changed).
- Secret disclosure: raw secret values reaching model context, traces,
  findings, events, approval requests, logs, or an unapproved sink.
- Guard-provider credential disclosure outside application setup or the
  selected provider adapter, including credentials entering policy, `core`,
  classification content, structured errors, events, or traces.
- Secret-handle resolution flaws (resolving for an unbound origin/field,
  authorizing a new sink in `RESTRICTED`, resolving any handle in
  `READ_ONLY`/`QUARANTINED`, or handle guessing).
- Taint/provenance bypass (untrusted data laundered into trusted provenance).
- Memory-guard bypass (web-derived memory accepted on read as trusted or as
  instructions, or without schema/hash verification and provenance retention).
- Origin-policy bypass (allowlist/same-site/redirect-hop evasion, scheme
  confusion, domain confusion the policy should catch).
- SSRF / private-network access (loopback, RFC1918, link-local, cloud
  metadata, configured internal ranges).
- Upload/download policy bypass.
- Egress/DLP bypass with sensitive or tainted data.
- Network Mutation Guard bypass on a surface the active adapter reports as
  enforced, including page-script, form, redirect, WebSocket, service-worker,
  or WebMCP effects being misattributed to an authorized action.
- Classifier, guard-model, critic, or ensemble output granting capability,
  resolving a secret, modifying policy, answering an approval, or lowering a
  deterministic critical block; malformed probabilistic output being trusted
  without strict schema validation.
- Unsafe parser or decoder behavior (unbounded decoding, resource
  exhaustion, prototype pollution, deserialization to executable objects).
- Dependency or supply-chain vulnerabilities in a security-critical path.
- Security-trace leaks (secrets or unredacted protected content in traces or
  receipts) or trace/receipt integrity flaws.
- Plugin isolation failures (a scanner plugin obtaining context beyond its
  manifest permissions, raw secrets, or the ability to widen capability).
- Stagehand or Playwright adapter bypasses (an execution path that reaches
  the browser without passing the wrapper/authorization).
- Approval-flow flaws (page content triggering or satisfying an approval; a
  missing handler resolving to allow).
- Budget/fail-closed flaws (scanner exhaustion or budget exhaustion silently
  disabling protection).
- Any other way for an agent to escape the intended capability envelope.

Detection-quality issues (a heuristic or model missing a specific injection
that deterministic controls still contained) are welcome as **regular
issues** with a fixture, unless they combine with a bypass of a deterministic
control.

## Security model and boundaries

OpenAgentFence is **in-process middleware**, not an operating-system sandbox,
a network appliance, or a browser-security replacement. Please read
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) before reporting. In
particular, the following are **outside the intended trust boundary** and
are not vulnerabilities in OpenAgentFence:

- A malicious or negligent host application that deliberately bypasses the
  middleware (calls the framework directly, disables policy, misuses the
  documented `unsafe` escape hatch).
- A fully compromised host process, operating system, or kernel.
- A compromised browser binary or a browser engine vulnerability.
- Malicious privileged browser extensions outside OpenAgentFence's control.
- A compromised primary-agent model provider steering the agent *within*
  the configured envelope.
- Physical attackers.

Conversely, "the guard model was fooled" is expected; what matters is
whether deterministic controls still held. A report showing that a fooled
agent could exceed the envelope is exactly what we want to hear about.

## Good-faith research

We welcome good-faith security research on OpenAgentFence. When you:

- act in good faith to avoid privacy violations, data destruction, and
  service disruption (test against your own environments and the project's
  fixtures, not third parties' systems),
- give us a reasonable opportunity to fix the issue before public
  disclosure, and
- do not exploit an issue beyond what is needed to demonstrate it,

the maintainers will treat your research as authorized, will not pursue or
support legal action against you for it, and will work with you to
understand and resolve the issue. This is a statement of the project's
intent; it cannot bind third parties (for example the operators of sites you
might test against) and is not legal advice.

## Coordinated disclosure

- We ask reporters to keep details private until a fix is released and
  users have had a reasonable window to update.
- We will credit reporters in the advisory and release notes unless they
  prefer otherwise.
- If we cannot reproduce or do not agree an issue is in scope, we will say
  so and explain why; reporters are free to disclose after a reasonable
  coordination period.
- **Response targets:** we aim to acknowledge a report within **5 business
  days** and to provide a status update (validated / not reproducible /
  out of scope, with an initial severity) within **14 days** of receipt.
  There is no fixed remediation SLA before 1.0; critical issues affecting
  default configuration are prioritized ahead of all other work.

## Security response lifecycle

```text
report
  -> acknowledgement (we confirm receipt and open a private advisory)
  -> validation (reproduce with a fixture; identify affected invariant/boundary)
  -> severity assessment (impact on the capability envelope, secrets, data;
     exploitability; whether default configuration is affected)
  -> remediation (fix on a private branch; review by a maintainer)
  -> regression test (the reproduction becomes a permanent security-corpus
     fixture or invariant test; CI gate must fail before the fix and pass after)
  -> coordinated disclosure (advisory published; patch release; changelog;
     credit)
```

Every fixed vulnerability results in a regression fixture. This is a hard
rule of the project (see [CONTRIBUTING.md](CONTRIBUTING.md) and
[AGENTS.md](AGENTS.md)).

## Project security practices

Planned and tracked in [docs/IMPLEMENTATION_PLAN.md](docs/IMPLEMENTATION_PLAN.md):
dependency pinning and lockfiles, automated dependency updates, CodeQL and
dependency review on every pull request, secret scanning, fuzzing of
decoders and parsers, strict schema validation at trust boundaries, no
arbitrary deserialization, no remote code execution in scanner plugins,
SHA-pinned CI actions with least-privilege tokens, npm trusted publishing
with provenance, SBOM per release, and signed tags. Until these are in place
the repository should be treated as pre-release software.
