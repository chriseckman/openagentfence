# Stagehand local composition

The application constructs Stagehand 4.0.1 with `selfHeal: false`, supplies a
deterministic `StagehandStateResolver`, and exposes only the returned secure
wrapper to agent code. Model/provider configuration remains application-owned
and may make external calls; this example itself performs none.

See [`index.ts`](index.ts) for the compile-checked composition helper.
