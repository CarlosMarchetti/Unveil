import unittest

import unicorn

from unveil.native.api_models import LocalHeap, UnsupportedAPI


class LocalHeapTests(unittest.TestCase):
    def test_zeroed_memory_alignment_isolation_and_cumulative_budget(self):
        machine = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        heap = LocalHeap(machine, budget=8192)
        first = heap.alloc(0x40, 17)
        second = heap.alloc(0, 4096)
        self.assertEqual(first % 16, 0)
        self.assertNotEqual(first, second)
        self.assertEqual(bytes(machine.mem_read(first, 17)), bytes(17))
        machine.mem_write(first, b'payload')
        self.assertEqual(bytes(machine.mem_read(second, 7)), bytes(7))
        with self.assertRaises(UnsupportedAPI):
            heap.alloc(0, 1)
        self.assertEqual(heap.calls, 2)
        self.assertEqual(heap.allocated, 8192)
