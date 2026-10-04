"""Bounded recognition of constant inline XOR stack strings; no target execution."""
import time

import pefile


def recover(data: bytes, max_instructions=200000, timeout=10):
    import capstone as cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

    pe = pefile.PE(data=data, fast_load=True)
    if pe.FILE_HEADER.Machine not in (0x14c, 0x8664):
        pe.close()
        return [], {'status': 'unsupported-architecture', 'limitations': ['Native patterns currently support x86/x64 only.']}
    decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else cs.CS_MODE_32)
    decoder.detail = True
    decoder.skipdata = True
    results, seen = [], set()
    deadline = time.monotonic() + timeout
    count, truncated = 0, False
    base = pe.OPTIONAL_HEADER.ImageBase

    def emit(memory, changed, start_rva):
        for frame in ('rsp', 'rbp', 'esp', 'ebp'):
            offsets = sorted(offset for key, offset in memory if key == frame)
            if not offsets:
                continue
            groups, group = [], []
            for offset in offsets:
                if group and offset != group[-1] + 1:
                    groups.append(group)
                    group = []
                group.append(offset)
            groups.append(group)
            for offsets in groups:
                raw = bytes(memory[frame, offset] for offset in offsets)
                cursor = 0
                for segment in raw.split(b'\0')[:-1]:
                    touched = any((frame, offset) in changed for offset in offsets[cursor:cursor + len(segment)])
                    cursor += len(segment) + 1
                    if not touched or len(segment) < 4:
                        continue
                    try:
                        text = segment.decode('utf-8')
                    except UnicodeError:
                        continue
                    if not all(c.isprintable() or c in '\t\r\n' for c in text):
                        continue
                    identity = (start_rva, text)
                    if identity in seen:
                        continue
                    seen.add(identity)
                    results.append(dict(plaintext=text, pattern='inline-constant-xor-stack',
                                        rva=start_rva, confidence='candidate',
                                        evidence='Constant stack writes and explicit XOR; terminated printable UTF-8'))

    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        memory, changed, registers = {}, set(), {}
        start_rva = section.VirtualAddress
        for insn in decoder.disasm(section.get_data(), base + section.VirtualAddress):
            count += 1
            if count > max_instructions or time.monotonic() >= deadline or len(results) >= 10000:
                truncated = True
                break
            if insn.id == 0:
                emit(memory, changed, start_rva)
                memory, changed, registers = {}, set(), {}
                continue
            ops = insn.operands
            barrier = any(insn.group(g) for g in (cs.CS_GRP_JUMP, cs.CS_GRP_CALL, cs.CS_GRP_RET, cs.CS_GRP_INT))
            handled = False
            if len(ops) == 2 and insn.mnemonic in ('mov', 'movabs', 'xor'):
                left, right = ops
                value = right.imm if right.type == X86_OP_IMM else registers.get(right.reg) if right.type == X86_OP_REG else None
                if left.type == X86_OP_REG and value is not None:
                    old = registers.get(left.reg)
                    if insn.mnemonic != 'xor' or old is not None:
                        registers.clear()  # Avoid stale values in overlapping x86 register aliases.
                        registers[left.reg] = (value if insn.mnemonic != 'xor' else old ^ value) & ((1 << (left.size * 8)) - 1)
                        handled = True
                elif left.type == X86_OP_MEM and value is not None and not left.mem.index:
                    frame = insn.reg_name(left.mem.base)
                    if frame in ('rsp', 'rbp', 'esp', 'ebp') and left.size in (1, 2, 4, 8):
                        keys = [(frame, left.mem.disp + i) for i in range(left.size)]
                        if insn.mnemonic != 'xor' or all(key in memory for key in keys):
                            if not memory:
                                start_rva = insn.address - base
                            encoded = (value & ((1 << (left.size * 8)) - 1)).to_bytes(left.size, 'little')
                            for key, byte in zip(keys, encoded):
                                memory[key] = memory[key] ^ byte if insn.mnemonic == 'xor' else byte
                                if insn.mnemonic == 'xor':
                                    changed.add(key)
                                else:
                                    changed.discard(key)
                            handled = True
            _, written = insn.regs_access()
            stack_changed = any(insn.reg_name(reg) in ('rsp', 'rbp', 'esp', 'ebp') for reg in written)
            memory_written = any(op.type == X86_OP_MEM and op.access & cs.CS_AC_WRITE for op in ops)
            if barrier or stack_changed or (memory_written and not handled):
                emit(memory, changed, start_rva)
                memory, changed, registers = {}, set(), {}
            elif not handled:
                if written:
                    registers.clear()
            if len(memory) > 4096:
                emit(memory, changed, start_rva)
                memory, changed, registers = {}, set(), {}
        emit(memory, changed, start_rva)
        if truncated:
            break
    pe.close()
    return results, dict(status='budget-exhausted' if truncated else 'completed', instructions=count,
                         limits=dict(instructions=max_instructions, seconds=timeout),
                         limitations=['Linear decoding is heuristic; candidates require code-context validation.',
                                      'Only constant inline XOR on stack buffers is recognized; arbitrary decryptors are unresolved.'])
