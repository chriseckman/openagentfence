# Policy reference

`openagentfence.yml` is a closed, versioned authorization document. The
runtime parser accepts YAML or JSON up to 1 MiB, 16 levels, and 1,000 nodes;
it rejects unknown keys, aliases, tags, merge keys, unsafe keys, environment
substitution, provider settings, and credentials. The machine-readable schema
is [`openagentfence-policy.schema.json`](../packages/policy/schemas/openagentfence-policy.schema.json).

All policy controls can only narrow the trusted task contract. They cannot add
a capability, bind a secret sink, change provenance, make a semantic result
authoritative, or promote an adapter capability gap to enforcement. P1 policy
profiles are not shipped in v0.1.

## Root keys

| Key | Default / bounds | Runtime effect and security impact |
| --- | --- | --- |
| `version` | Required; exactly `1` | Selects the only accepted policy format. |
| `defaults.unknown_action` | Omitted means secure core default; supplied value must be `block` | Blocks unrecognized actions with `unknown_action`; cannot be weakened. |
| `defaults.scanner_failure.low_risk` | `block` when omitted; `warn` or `block` when supplied | Chooses WARN or BLOCK only for low-risk scanner failure evidence. |
| `defaults.scanner_failure.high_risk` | Omitted means secure core default; supplied value must be `block` | Blocks high-risk scanner failure evidence; cannot be weakened. |
| `navigation.mode` | Omitted leaves the trusted task envelope in charge; `same-origin`, `same-site`, `allowlist`, or `none` | Further narrows `NAVIGATE`. `allowlist` is represented by trusted task-contract origins, not a page value. |
| `navigation.block_private_networks` | Omitted/`false` does not grant; `true` narrows | Adds a policy block for private destinations. Core private-network controls still win even when it is omitted. |
| `navigation.max_redirect_hops` | `5`; integer `0..5` | May only lower the guarded redirect limit. Redirect follow-up enforcement remains adapter-dependent. |
| `navigation.internal_network_ranges` | Empty; at most 64 CIDRs of at most 128 characters | Adds application-selected internal ranges to deny before a supported routed request continues. |
| `actions.<upload\|delete\|purchase\|message\|execute_script\|download\|authenticate\|publish\|change_setting>` | Omitted leaves the envelope in charge; `deny`, `approval`, or `allow` | `deny` blocks; `approval` requires the existing approval boundary; `allow` cannot widen the envelope or re-enable `EXECUTE_SCRIPT`. |
| `secrets.resolution` | Omitted secure behavior; supplied value must be `executor_only` | Documents and validates the invariant; secret values still resolve only in a one-shot exact executor sink. |
| `secrets.restricted_mode` | `keep_approved_sinks`; or `deny_all` | Controls whether an exact sink established while NORMAL can be reused in RESTRICTED. READ_ONLY and QUARANTINED still deny. |
| `injection.high_confidence` | Omitted; `restricted_mode` or `block` | Interprets trusted high injection scanner evidence as RESTRICT or BLOCK. Semantic evidence cannot produce this authority. |
| `injection.critical` | Omitted; `quarantine` or `block` | The current pure policy engine emits BLOCK for critical injection evidence. Risk-state quarantine is owned by the session risk engine, not this key. |
| `budgets.max_actions`, `max_duration_ms`, `max_navigations` | Omitted; non-negative number when supplied | Bounds firewall-owned runtime counters. Once exceeded, the selected disposition applies. |
| `budgets.on_exceeded` | `block` when omitted; `block` or `restricted_mode` | Chooses BLOCK or RESTRICT after a configured budget is exceeded. |
| `scanners.<id>.patterns` | Empty; at most 32 bounded fixed-prefix patterns | Data-only input for `secretPatternsFromPolicy()`. The application must explicitly pass its result to `defaultScanners({ secretPatterns })`; facade composition does not load patterns automatically. |
| `scanners.<id>.rules.<rule>.threshold` / `.mode` / `.origins` | Omitted; threshold `0..1`, mode `warn\|block` | Available only through `resolveScannerThreshold()` with firewall-owned scanner/rule/origin metadata. It is not automatic scanner reconfiguration. |
| `scanners.<id>.enabled` | Omitted; boolean accepted | Reserved configuration metadata in v0.1. The default catalog ignores it, so it never disables a deterministic scanner. |
| `suppressions[]` | Empty; requires `rule`, `scope`, `justification`, optional ISO-like `expires` | `resolveScannerSuppression()` reports an eligible deterministic scanner suppression from trusted evidence. Final reason-code controls cannot be suppressed; applications must integrate the returned record deliberately. It does not suppress core capability, network, secret, or ActionIntent controls. |
| `risk.restricted_at`, `risk.quarantine_at` | Omitted; non-negative number accepted | Reserved v0.1 metadata. Session risk thresholds are firewall-owned and this key does not currently alter them. |

## Secure-default template

The CLI’s `openagentfence init` writes the explicit P0 template. It contains
only operative secure defaults and no provider or credential fields:

```yaml
version: 1
defaults:
  unknown_action: block
  scanner_failure:
    low_risk: block
    high_risk: block
navigation:
  mode: same-site
  block_private_networks: true
  max_redirect_hops: 5
actions:
  upload: approval
  delete: approval
  purchase: approval
  message: approval
  execute_script: deny
  download: approval
  authenticate: approval
  publish: approval
  change_setting: approval
secrets:
  resolution: executor_only
  restricted_mode: keep_approved_sinks
```

Use `openagentfence policy validate openagentfence.yml` before application
startup. Provider construction remains application-owned under ADR-0009.

## Suppressions and reasons

Suppressions must be specific, justified, and bounded to a deterministic
scanner rule and trusted origin. They are never a bypass for a final control.
For all stable decision reasons and explanations, see
[reason codes](reason-codes.md).
