# Reproducible property and fuzz suites

`seeds.json` is the durable OAF-TEST-013 seed registry. Ordinary package and PR tests run every listed property for exactly the registered `prRuns` floor (currently 1,000). The scheduled property workflow sets `OAF_PROPERTY_RUNS` to `nightlyRuns` (currently 10,000). The test harness rejects values below the PR floor or above `maxRuns`.

To replay a reported fast-check counterexample, set `OAF_PROPERTY_REPLAY` to `<property-id>=<path>` and run the owning package's `test:property` command. The seed always comes from this registry.

Any discovered counterexample is a product defect until it is minimized, repaired, and committed as a deterministic synthetic regression fixture. Add its property ID, seed, fast-check path, and fixture path to `regressions`; never store credentials, raw secrets, full untrusted documents, or provider output in this file.

The properties assert security semantics, not wall-clock timing: clocks, deadlines, cancellation, and provider behavior are injected or pre-set. Resource properties assert documented byte/depth/status bounds, and refusal or exhaustion is never interpreted as authorization.
