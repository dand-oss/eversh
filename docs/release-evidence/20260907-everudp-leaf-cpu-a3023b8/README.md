# Leaf CPU attribution — diagnostic only

Bead: eversh-5fc.20. No qualification or architecture-integration approval.
Measured binaries are the plain a3023b8 floor and frozen zmosh UDP from the
common-control build documented in build-provenance.json. The harness checkout
was 65e6f60. This collection changes no runtime code.

Two completed 1,000-trial-per-candidate blocks used 0% loss, 100 ms gaps,
seeds 89801 and 89802, and reversed candidate order. Their original manifests,
transcripts, resource files, network counters and seals are retained untouched.
The block PASS values describe harness/transcript success, NOT performance
qualification. Profiling perturbs execution; do not use these latency samples
for acceptance or mix them with unprofiled qualification samples.

## Sampling method

Private Debian perf 7.1.13 executable SHA256:
83e79d866c65499c16302d8e27900955868609908be2bbe0d1afed02f082decb.
No system package installation. Each attachment selected only processes whose
/proc/PID/exe device and inode matched the uniquely copied benchmark binary;
the selected PIDs and inode identities are in the scope JSON files.

Each capture used cpu-clock:u,cpu-clock:k at 4999 Hz for 30 seconds, with
--no-inherit --no-buildid-cache and explicit -p PIDs. No system-wide recording,
stack dumps, callgraphs, command-line collection, payloads or authentication
values were requested. A bounded timeout sent SIGINT; exit 124 is expected.
The floor was sampled in floor-first, zmosh in zmosh-first. Both captures have
zero lost samples. Raw perf files and rendered reports are included.

Reports were rendered with perf report --stdio --stdio-color never,
--sort comm,pid,dso,symbol --percent-limit 1 and DEBUGINFOD_URLS empty.
Percentages are leaf CPU samples, not inclusive call costs or wall-clock delay.
The reports omit individual symbols below 1%; raw captures retain them.

## Results and limits

| Capture | Scoped processes | User samples | Kernel samples |
| --- | ---: | ---: | ---: |
| Floor | 2 | 677 | 404 |
| zmosh UDP | 3 | 151 | 340 |

Floor poll_transmit accounts for about 8% of userspace samples across its two
processes, populate_packet about 4%. No allocator leaf dominates. zmosh samples
include its gateway, daemon and client; its largest user leaves include syscall
wrappers, gateway/daemon loops and packet send/crypto. Kernel samples in both
include socket syscalls, routing, epoll/poll and scheduling.

These are separate short sampling windows, not role-matched CPU benchmarks or
per-request distributions. Different process counts, inlining, host activity,
capture perturbation and sparse samples preclude a causal speedup estimate.
In particular, multiplying a CPU percentage by median latency is invalid.

Combined with the prior sealed causal measurements (server queue-to-driver
median approximately 3.5 microseconds), this evidence does not establish that
removing one task handoff can supply the missing floor margin. It identifies
protocol polling/packet construction and socket work for a bounded experiment,
not a reason to replace QUIC or bypass its security/congestion/timer handling.
The unsafe endpoint flush previously removed remains excluded. Architecture
selection and production acceptance remain UNKNOWN, not PASS.
