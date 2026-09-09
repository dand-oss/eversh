import itertools
import unittest
from pgo_compare import schedule


class ComparisonScheduleTests(unittest.TestCase):
    def test_complete_frozen_schedule(self):
        jobs = schedule()
        self.assertEqual(len(jobs), 12)
        orders = {','.join(p) for p in itertools.permutations(('everudp', 'zmosh-udp', 'zmosh-quic'))}
        for loss, base in ((0, 920000), (5, 930000)):
            cell = [j for j in jobs if j[0] == loss]
            self.assertEqual({j[1] for j in cell}, set(range(base + 1, base + 7)))
            self.assertEqual({j[2] for j in cell}, orders)


if __name__ == '__main__':
    unittest.main()
