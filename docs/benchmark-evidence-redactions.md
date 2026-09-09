# Benchmark bootstrap credential redactions

The current evidence tree redacts 72 `ZMX_CONNECT` records across nine archives.
These records contained ephemeral zmosh QUIC benchmark authentication keys.
They were not intended for archival. The launcher fix at `4918777` keeps raw
bootstrap output private and exports only protocol, port, and `[REDACTED]`.

Each affected archive contains `redactions.json` with the exact changed paths
and original/redacted SHA-256 hashes. Original checksum receipts are retained
with suffix `.pre-redaction`; current `SHA256SUMS` receipts cover the redacted
tree and those original receipts. Original receipts are historical records and
are not expected to validate the redacted files directly.

Before redaction all nine archive receipts passed. Verification afterwards
compared every original top-level receipt entry: only the declared connection
log fields and regenerated checksum receipts changed. Timing results, source
identities, executable hashes, measurements, and analyses remain byte-identical.
Resealing is not a new performance qualification or an alteration of results.

This is forward cleanup, not history rewriting. Earlier local Git commits still
contain the original records. No claim is made that history has been purged or
that each historical credential's expiry has been independently verified.
Publishing this history should wait for an explicit history-cleanup decision.
No push, force-push, release, or fleet operation is part of this cleanup.

Tracked in `eversh-5fc.43`.
