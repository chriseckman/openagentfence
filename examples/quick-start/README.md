# Secure quick start

`createQuickStart(adapter)` composes a supplied `BrowserAdapter`, an explicit
validated secure policy, and `defaultScanners()`. It is compiled and executed
against an in-memory adapter fixture in the repository test suite. The function
does not navigate, start a browser, read environment variables, resolve a
credential, or call a provider.

Applications choose and construct their own adapter. To use an optional guard
provider, construct it separately and pass it to `OpenAgentFence`; provider
credentials and endpoints do not belong in `openagentfence.yml`.
