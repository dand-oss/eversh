# jq -s -f summarize-cpu.jq derived-traces/*.json
def median:
  sort | length as $n |
  if $n == 0 then error("empty population")
  elif $n % 2 == 1 then .[($n / 2 | floor)]
  else (.[($n / 2 - 1)] + .[($n / 2)]) / 2 end;
if length != 4 or any(.[]; .status != "DIAGNOSTIC") then
  error("requires four validated diagnostic reports")
else . end |
{
  status: "DIAGNOSTIC",
  qualification_pass: false,
  semantics: "Pooled whole-trace call populations, including warmup/control and recorder overhead. CPU and wall sampled separately. No per-trial attribution, percentile subtraction/summing, or calibration correction.",
  populations: ([.[] |
    ("protocol_poll_intervals", "sender_poll_intervals") as $kind |
    ("client", "server") as $role |
    .[$kind][$role].intervals[] |
    if .thread_cpu_duration_ns == null then error("missing CPU interval") else . end |
    {kind:$kind,role:$role,outcome,wall_ns:.duration_ns,cpu_ns:.thread_cpu_duration_ns}
  ] | group_by([.kind,.role,.outcome]) | map({
    kind:.[0].kind, role:.[0].role, outcome:.[0].outcome,
    count:length, wall_median_ns:(map(.wall_ns)|median),
    cpu_median_ns:(map(.cpu_ns)|median)
  }))
}
