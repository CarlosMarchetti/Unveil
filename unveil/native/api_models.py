"""Bounded Win32 API models operating exclusively on emulator memory."""


class UnsupportedAPI(ValueError):
    """The call requires semantics outside the modeled subset."""


class LocalHeap:
    def __init__(self, machine, *, budget=64 * 1024 * 1024):
        self.machine = machine
        self.budget = budget
        self.next_address = 0x720000000000
        self.allocated = 0
        self.calls = 0

    def alloc(self, flags: int, size: int) -> int:
        # Movable handles, zero-sized blocks and legacy flags need separate models.
        if flags not in (0, 0x40) or size <= 0:
            raise UnsupportedAPI('LocalAlloc supports positive-sized LMEM_FIXED/LPTR only')
        length = (size + 4095) & ~4095
        if length > self.budget - self.allocated:
            raise UnsupportedAPI('LocalAlloc exceeds emulator heap budget')
        address = self.next_address
        self.machine.mem_map(address, length)
        # Unicorn pages start zeroed. For LMEM_FIXED contents are unspecified;
        # zero is one allowed initial state, not a recovered Windows heap state.
        self.next_address += length
        self.allocated += length
        self.calls += 1
        return address
