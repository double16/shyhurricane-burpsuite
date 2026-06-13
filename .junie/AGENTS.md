## Critical rules the agent must follow before doing anything
- Read `README.md` before acting.
- Update `CHANGELOG.md` for user-facing changes.

## Testing and contribution
- Always write unit tests and check that they pass for new business logic.
- Always run unit tests to verify changes.
- Test both positive and negative scenarios.
- Do not rename files without a valid technical reason.

## Explicit prohibitions what agents must NOT do
- Do not bump major versions of core dependencies without a dedicated PR and discussion.

## Java best practices
- Prefer immutability: use `final` for fields/variables where possible; avoid mutable static state.
- Use meaningful names and small methods; keep classes focused on a single responsibility.
- Null-safety: fail fast with `Objects.requireNonNull` or use `Optional` for truly optional returns; validate public method inputs.
- Concurrency:
  - Avoid shared mutable state; use thread-safe collections and `ConcurrentHashMap` when needed.
  - Guard background threads/services with proper lifecycle management and interruption handling.
- Exceptions:
  - Use checked exceptions for recoverable conditions and unchecked for programmer errors.
  - Do not swallow exceptions; add context and rethrow or handle. Avoid logging and rethrowing without need (double logging).
- Logging:
  - Use a consistent logging facade (e.g., SLF4J) and appropriate levels (`trace`/`debug`/`info`/`warn`/`error`).
  - Never log secrets, API keys, tokens, or PII; redact sensitive data.
- I/O and resources: use try-with-resources; close streams/sockets; set timeouts for network calls.
- Collections: prefer interfaces (`List`, `Map`) in APIs; avoid returning internal mutable collections (return unmodifiable views or copies).
- Equality and hashing: when overriding `equals`, always override `hashCode`; keep them consistent and immutable.
- Testing: write unit tests for business logic; include positive and negative cases; avoid time/date flakiness (use fixed clocks).
- Performance: measure before optimizing; avoid premature micro-optimizations; consider algorithmic complexity.
- Security: validate and sanitize external inputs; use safe defaults; avoid reflection unsafe operations; keep dependencies updated.


## Burp Suite Extensions — best practices
- API usage and lifecycle
  - Implement `burp.IBurpExtender` once; set a clear name via `callbacks.setExtensionName("ShyHurricane Forwarder")`.
  - Obtain `IExtensionHelpers` from `callbacks.getHelpers()` and prefer helpers for all parsing/encoding (e.g., `analyzeRequest`, `analyzeResponse`, `bytesToString`, `stringToBytes`).
  - Register only the listeners you need (`IHttpListener`, `IProxyListener`, `IScannerCheck`, `IContextMenuFactory`, `ITab`, etc.).
  - Handle unloads: implement `IExtensionStateListener` and release resources in `extensionUnloaded()` (stop executors, close sockets, unregister listeners, flush buffers).

- Threading, UI, and performance
  - Do not block Burp UI threads or listener callbacks; offload heavy/IO work to bounded executors with backpressure and timeouts.
  - Update Swing UI only on the EDT using `SwingUtilities.invokeLater` (or `invokeAndWait` when required).
  - Keep hot-path code allocation-light; avoid copying large request/response bodies unnecessarily. Use streams/byte arrays and process incrementally where possible.
  - Batch outbound network calls (e.g., when forwarding many items) to avoid degrading Burp performance.

- Memory and data handling
  - Treat HTTP messages as bytes-first; do not assume UTF-8 unless `Content-Type` indicates a charset. Use helpers to decode headers and bodies.
  - Avoid retaining `IHttpRequestResponse` objects and raw bodies long-term; store only derived, minimal data (IDs, offsets, hashes) when feasible.
  - Never mutate shared arrays returned by APIs without copying; prefer defensive copies for data you persist.

- Configuration, settings, and UX
  - Persist user settings via `callbacks.saveExtensionSetting` / `loadExtensionSetting`; validate inputs and provide sensible defaults.
  - Do not store secrets in plaintext; never log tokens, credentials, or PII. Redact sensitive headers/fields in logs and UI.
  - Expose a concise `ITab` for configuration/status with clear enable/disable controls and a debug logging toggle.
  - Provide clear error messages and recovery hints in the UI and Extender output.

- Robustness and error handling
  - Fail safe: on network errors or downstream outages, back off (with jitter), queue within bounds, and drop oldest items rather than freezing the UI.
  - Catch and log exceptions in background tasks with enough context; prefer structured messages. Do not double-log and avoid stack traces at `info` level.
  - Validate and sanitize any external inputs used to build HTTP requests or file paths.

- Compatibility and boundaries
  - Use only public `burp.*` interfaces; avoid reflection or reliance on undocumented/internal classes.
  - Test on recent Burp Suite Community and Professional editions. Avoid version-specific assumptions; guard optional APIs via feature detection.
  - Keep Java compatibility aligned with Burp’s supported runtime; avoid conflicting dependency versions and shade/relocate if necessary to prevent classpath clashes.

- Testing and observability
  - Unit test parsing and transformation logic with `IExtensionHelpers` utilities (positive and negative cases).
  - Add integration tests around message forwarding using recorded fixtures where feasible; avoid network flakiness with mocks or local test servers.
  - Include lightweight metrics/counters (e.g., forwarded count, last error time) surfaced in the UI for troubleshooting.

