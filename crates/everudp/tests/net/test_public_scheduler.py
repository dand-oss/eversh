import unittest
from analyze_public_scheduler import correlate, timelines


def wake(ns, pid=7, kind='sched_wakeup'):
    return f'0.{ns:09d}: sched:{kind}: comm=x pid={pid} prio=120 target_cpu=000'


def switch(ns, old, new, state='S'):
    return f'0.{ns:09d}: sched:sched_switch: prev_comm=x prev_pid={old} prev_prio=120 prev_state={state} ==> next_comm=x next_pid={new} next_prio=120'


class SchedulerTests(unittest.TestCase):
    def test_waking_is_not_runnable_and_preemption_is(self):
        text = '\n'.join([wake(1, kind='sched_waking'), wake(10), switch(30, 0, 7),
                          switch(40, 7, 0, 'R+'), switch(60, 0, 7), switch(80, 7, 0)])
        tracks = timelines(text, {'client': 7})
        self.assertEqual(tracks['client']['waits'], [(10, 30), (40, 60)])
        rows = correlate([{'trial': 0, 'send_ns': 20, 'accepted_ns': 70}], tracks)
        self.assertEqual(rows[0]['runnable_wait_ns'], {'client': 30})

    def test_coverage_excludes_partial_trials(self):
        tracks = timelines('\n'.join([wake(10), switch(20, 0, 7), switch(30, 7, 0)]), {'client': 7})
        rows = correlate([{'trial': 0, 'send_ns': 1, 'accepted_ns': 25},
                          {'trial': 1, 'send_ns': 15, 'accepted_ns': 35}], tracks)
        self.assertTrue(all('excluded' in row for row in rows))

    def test_repeated_wake_preserves_first_runnable_timestamp(self):
        tracks = timelines('\n'.join([wake(10), wake(15), switch(20, 0, 7)]), {'client': 7})
        self.assertEqual(tracks['client']['waits'], [(10, 20)])

    def test_cross_target_switch_is_accounted_separately(self):
        tracks = timelines('\n'.join([wake(1), wake(2, 8), switch(5, 0, 7),
                                      switch(10, 7, 8, 'R'), switch(20, 8, 7), switch(30, 7, 0)]),
                           {'client': 7, 'gateway': 8})
        self.assertEqual(tracks['client']['waits'], [(1, 5), (10, 20)])
        self.assertEqual(tracks['gateway']['waits'], [(2, 10)])

    def test_incomplete_or_unscoped_or_regressed_trace_fails(self):
        for text in [wake(1, 99), '\n'.join([wake(20), wake(10)]),
                     '\n'.join([switch(10, 0, 7), switch(20, 0, 7)]), 'bad event']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                timelines(text, {'client': 7})


if __name__ == '__main__':
    unittest.main()
