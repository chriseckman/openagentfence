# Promptfoo guarded/unguarded comparison

This example uses Promptfoo **0.122.0** with a deterministic local file
provider. The provider starts OpenAgentFence's loopback-only fixture server,
runs the same scripted worst-case agent in guarded and unguarded modes, and
returns bounded JSON facts. The attack comparison proves that the unguarded
script reaches the second loopback origin while the guarded proposal is
blocked with zero target requests. The benign sibling reaches neither target.

The checked-in configuration performs no model call and needs no credential.
It is not an efficacy benchmark and does not claim that a real model will
always follow or ignore an injection. The deterministic corpus and
OpenAgentFence authorization boundary remain the security authority.

## Offline validation

Promptfoo 0.122.0 requires Node 22.22 or newer; repository CI uses Node 24 for
this example. From the repository root, run:

```bash
pnpm promptfoo:check
```

The check compiles the TypeScript example, runs Promptfoo's config validator,
and evaluates both local providers. It sets Promptfoo's documented offline
controls to disable telemetry, update checks, sharing, and remote generation;
it also uses a temporary local config/cache/log directory. `validate target`
is intentionally not used because that command tests connectivity. Promptfoo
does not document a generic `eval --dry-run`; the local eval really calls only
this audited file provider and the loopback fixture server.

## Optional external agent/model

To test a real browser agent, copy this configuration and replace the local
file provider with an application-owned provider that calls your already
OpenAgentFence-wrapped agent. Keep model selection and credentials outside the
repository, for example:

```bash
export OPENAGENTFENCE_PROMPTFOO_MODEL_PROVIDER='your-provider-id'
export OPENAGENTFENCE_PROMPTFOO_TARGET_URL='https://your-agent.example/evaluate'
export OPENAGENTFENCE_PROMPTFOO_ALLOW_EXTERNAL='1'
# Set the vendor-specific credential expected by your own provider.
```

Those variables are illustrative application inputs; the checked-in provider
does not read them. A real provider/model can make external calls and may send
the prompt, test variables, page-derived context, and model output to the
configured service. Never copy credentials into YAML `env:` values or eval
artifacts, never enable sharing for sensitive runs, and preserve
OpenAgentFence's exact structured-action and deterministic authorization path.

Promptfoo file providers execute trusted local Node code and are not a plugin
sandbox. Review any replacement provider before running it.
