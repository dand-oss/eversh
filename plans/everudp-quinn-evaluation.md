# Bounded Quinn evaluation

Status: authorized evaluation; no engine selected or production change approved.
Tracking: eversh-5fc.78.

The user explicitly authorized a bounded Quinn performance comparison after the
NoQ single-path screen at `e2498d89770715ebcdb700d8c72d86feebc85f58` failed to
establish a usable improvement. This is a narrow exception to the NoQ selection
in `design.md` and `reference.md`: Quinn may be evaluated for performance, not
only for migration or pinning failure. Historical contracts and receipts remain
unchanged. NoQ remains the production default; everssh is not being ported.

## Scope and stopping rules

1. Pin a reviewed Quinn source/version and dependency closure. Inspect API,
   licensing, MSRV, TLS and migration differences before adapting code. Record
   unsupported security or recovery behavior as a failed feasibility condition,
   not an invitation to remove the requirement.
2. Keep the candidate isolated from production defaults. Reuse the production
   everudp application protocol, queues, gateway, client and PTY path. A native
   echo or transport-only floor is not evidence for product parity.
3. Before timing, pass the relevant admission, byte-identity, reconnect,
   migration and resource checks on the candidate. Preserve TLS 1.3, SSH-derived
   SPKI trust, client-key binding, bounded one-use invitations, Retry/address
   validation, stream limits and terminal failure classification.
4. Keep reliable ordered terminal streams, input/resize/signal ordering,
   acknowledgement boundaries, bounded replay and backpressure, observer
   isolation, PTY-lifetime reconnect and gateway-crash ambiguity handling.
   No datagrams, prediction, relay, TCP terminal payload or reduced encryption.
5. Freeze a bounded paired schedule, exact source/build identities, profiles,
   seeds and controls before measurement. Use the same compiled PTY fixture and
   full-transcript oracle, public send-to-accepted-output timing, CPU placement,
   0%/5% symmetric-loss cells, and both pinned zmosh controls. Record every
   scheduled block and failure. Do not rerun an unchanged candidate to select a
   favorable result. No simultaneous builds or helper agents during timing.
6. A screening result cannot authorize adoption. Release still requires the
   original exact-SHA gates: p50 ratio point estimate <= 1.00, p50 upper-95
   ratio <= 1.10, and p95 upper-95 ratio <= 1.00 against both controls in both
   cells, with 1,200 observations per implementation per cell and the frozen
   block-stratified analysis. Reliability, security, dependency, resource,
   compatibility and independent-review gates also remain required.

The evaluation does not authorize a parallel production engine, a default
transport change, release, merge, push, tag or fleet deployment. A positive
result must include a reviewed selection decision and integration plan; a
negative result is retained without changing the acceptance thresholds.
