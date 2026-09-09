# Inputs: validated path-analysis.json as $p, result.json as $r (slurpfile).
# Intervals are boundary differences, not exclusive CPU/network costs.
def med:
  sort | length as $n |
  if $n == 0 then null
  elif $n % 2 == 0 then (.[($n/2)-1] + .[$n/2])/2
  else .[($n/2|floor)] end;
[$p[0].rows[] |
  $r[0].public_boundaries[.trial] as $b |
  {trial, latency:($b.accepted_ns-$b.send_ns),
   prequeue:(.input.queued_ns-$b.send_ns),
   input_write:(.input.written_ns[0]-.input.queued_ns),
   input_handoff:.stream_handoff_ns,
   pty_accept:(.input.accepted_ns-.input.prepared_ns[0]),
   pty_echo:(.output.gateway_queued_ns-.input.accepted_ns),
   output_return:(.output.staged_ns-.output.gateway_queued_ns),
   local_sink:($b.accepted_ns-.output.staged_ns)}] as $rows |
{status:"DIAGNOSTIC", qualification:false,
 bins_median_us:[range(0;10) as $n |
   $r[0].samples_us[$n*20:($n+1)*20] | med],
 groups:([{name:"all",rows:$rows},
          {name:"over_2ms",rows:[$rows[]|select(.latency>2000000)]},
          {name:"at_most_2ms",rows:[$rows[]|select(.latency<=2000000)]}] |
   map({name,n:(.rows|length),median_ns:(.rows as $rs |
     reduce ["latency","prequeue","input_write","input_handoff",
             "pty_accept","pty_echo","output_return","local_sink"][] as $k
       ({}; .[$k]=([$rs[]|.[$k]]|med)))})),
 rows:$rows}
