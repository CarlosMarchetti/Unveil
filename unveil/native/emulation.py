"""Experimental x64 CPU probe, with no host API or syscall forwarding.

This is not a Windows emulator. Captures are raw mapped images, not rebuilt PEs.
"""
from pathlib import Path
import struct
import time


MAX_INSTRUCTIONS = 10_000_000
MAX_TIMEOUT_SECONDS = 60


def needs_instruction_decode(code: bytes) -> bool:
    """Filter for the opcode families containing the probe's forbidden operations.

    Unicorn supplies an instruction boundary. Skip legacy/REX prefixes, then
    decode all two-byte opcodes and all primary INT/I/O/HLT families with Capstone.
    """
    for opcode in code:
        if opcode in (0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x3e, 0x26, 0x64, 0x65, 0x66, 0x67) or 0x40 <= opcode <= 0x4f:
            continue
        return opcode == 0x0f or opcode in (0xcc, 0xcd, 0xf1, 0xf4) or 0x6c <= opcode <= 0x6f or 0xe4 <= opcode <= 0xe7 or 0xec <= opcode <= 0xef
    return True


def initialize_tls(machine, pe, base, size, environment=None):
    """Model one module's static AMD64 TLS; callback execution is unsupported."""
    from unicorn.x86_const import UC_X86_REG_GS_BASE

    if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= 9:
        return dict(status='absent')
    directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[9]
    if not directory.VirtualAddress:
        if directory.Size:
            raise ValueError('TLS directory size without address')
        return dict(status='absent')

    def image_range(address, length):
        if length < 0 or not base <= address <= base + size - length:
            raise ValueError('TLS address outside mapped image')

    address = base + directory.VirtualAddress
    if directory.Size < 40:
        raise ValueError('Truncated AMD64 TLS directory')
    image_range(address, directory.Size)
    start, end, index, callbacks, zero_fill, characteristics = struct.unpack(
        '<QQQQII', bytes(machine.mem_read(address, 40)))
    if end < start or bool(start) != bool(end):
        raise ValueError('Invalid TLS template range')
    length = end - start
    if start:
        image_range(start, length)
    image_range(index, 4)
    if callbacks:
        image_range(callbacks, 8)
        if int.from_bytes(machine.mem_read(callbacks, 8), 'little'):
            return dict(status='blocked', reason='tls_callbacks_not_modeled')
    if length + zero_fill > 1024 * 1024:
        raise ValueError('TLS allocation exceeds 1 MiB')
    if characteristics & ~0x00f00000 or (characteristics >> 20) == 15:
        raise ValueError('Invalid TLS alignment characteristics')
    # Fixed, disjoint probe addresses, above the permitted image range.
    teb, vector, storage = 0x710000000000, 0x710000001000, 0x710000002000
    if environment is None:
        machine.mem_map(teb, 4096)
    machine.mem_map(vector, 4096)
    machine.mem_map(storage, max(4096, (length + zero_fill + 4095) & ~4095))
    if length:
        machine.mem_write(storage, bytes(machine.mem_read(start, length)))
    machine.mem_write(index, bytes(4))
    machine.mem_write(vector, storage.to_bytes(8, 'little'))
    machine.mem_write(teb + 0x30, teb.to_bytes(8, 'little'))
    machine.mem_write(teb + 0x58, vector.to_bytes(8, 'little'))
    if environment is not None:
        environment.configure_tls(vector)
    machine.reg_write(UC_X86_REG_GS_BASE, teb)
    return dict(status='initialized', index=0, templateBytes=length,
                zeroFillBytes=zero_fill, callbacksExecuted=0,
                scope='single-module-static-tls')


def probe(path, capture_path, *, max_instructions=100_000, timeout_seconds=5, model_tsc=False,
          module_dirs=(), main_name=None, windows_version=None, debugged=False):
    import capstone
    import pefile
    import unicorn as uc
    from unicorn.x86_const import (UC_X86_REG_RSP, UC_X86_REG_RIP,
                                   UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RAX,
                                   UC_X86_REG_R8, UC_X86_REG_R9)
    from .api_models import LocalHeap, UnsupportedAPI
    from .module_loader import ModuleLoader, read_guest_string
    from .windows_environment import GuestEnvironment

    if not 1 <= max_instructions <= MAX_INSTRUCTIONS or not 1 <= timeout_seconds <= MAX_TIMEOUT_SECONDS:
        raise ValueError('Emulation limits outside permitted range')
    pe = pefile.PE(str(path), fast_load=True)
    try:
        if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b:
            raise ValueError('Experimental probe supports AMD64 PE32+ only')
        base = pe.OPTIONAL_HEADER.ImageBase
        size = pe.OPTIONAL_HEADER.SizeOfImage
        if not 0 < size <= 128 * 1024 * 1024 or base % 4096 or base + size >= 0x600000000000:
            raise ValueError('Image exceeds probe address or memory budget')
        header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
        raw = Path(path).read_bytes()
        if not 0 < header_size <= min(len(raw), size):
            raise ValueError('Invalid mapped header size')
        machine = uc.Uc(uc.UC_ARCH_X86, uc.UC_MODE_64)
        machine.mem_map(base, (size + 4095) & ~4095)
        machine.mem_write(base, raw[:header_size])
        reserved = []
        occupied = [(0, header_size)]
        for section in pe.sections:
            rva, length = section.VirtualAddress, max(section.Misc_VirtualSize, section.SizeOfRawData)
            if rva + length > size or (length and any(rva < end and start < rva + length for start, end in occupied)):
                raise ValueError('Overlapping/out-of-bounds virtual sections')
            if length:
                occupied.append((rva, rva + length))
            start, physical = section.PointerToRawData, section.SizeOfRawData
            if start + physical > len(raw):
                raise ValueError('Section exceeds file')
            if physical:
                machine.mem_write(base + rva, raw[start:start + physical])
            elif length and section.Characteristics & 0x20000000:
                reserved.append((base + rva, base + rva + length))
        environment = GuestEnvironment(machine, base, windows_version=windows_version, debugged=debugged)
        tls = initialize_tls(machine, pe, base, size, environment)
        if tls['status'] == 'blocked':
            return dict(status='blocked', reason=tls['reason'], instructions=0,
                        captured=False, imageBase=base, imageSize=size, tls=tls)
        # Every import has an addressable probe trampoline. The code hook either
        # models it, resolves guest DLL code or stops before executing its RET.
        pe.parse_data_directories(directories=[1, 13])
        imported = {}
        import_keys, trampoline_pages, startup_modules = {}, set(), set()

        def register_import(dll, symbol):
            label = dll + '!' + (symbol if isinstance(symbol, str) else '#' + str(symbol))
            key = (dll.casefold(), symbol)
            if key in import_keys:
                return import_keys[key]
            if len(imported) >= 65536:
                raise UnsupportedAPI('Probe import budget exceeded')
            address = 0x600000000000 + 16 * len(imported)
            page = address & ~4095
            if page not in trampoline_pages:
                machine.mem_map(page, 4096)
                trampoline_pages.add(page)
            machine.mem_write(address, b'\xc3')
            imported[address] = label
            import_keys[key] = address
            return address

        for attribute in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            for descriptor in getattr(pe, attribute, []):
                dll = descriptor.dll.decode('ascii')
                if attribute == 'DIRECTORY_ENTRY_IMPORT':
                    startup_modules.add(dll)
                for symbol in descriptor.imports:
                    if not base <= symbol.address <= base + size - 8:
                        raise ValueError('Import slot outside image')
                    address = register_import(dll, symbol.name.decode('ascii') if symbol.name else symbol.ordinal)
                    machine.mem_write(symbol.address, address.to_bytes(8, 'little'))
        loader = ModuleLoader(machine, module_dirs, main_name or Path(path).name, base, size,
                              register_import, startup_modules=startup_modules,
                              main_pe=pe if module_dirs else None,
                              on_module_loaded=environment.add_module)
        environment.add_module(loader.main)
        heap = LocalHeap(machine)
        stack_base, stack_size = 0x700000000000, 2 * 1024 * 1024
        machine.mem_map(stack_base, stack_size)
        machine.reg_write(UC_X86_REG_RSP, stack_base + stack_size - 0x108)
        environment.configure_stack(stack_base, stack_size)
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        state = dict(status='blocked', reason='instruction_or_time_budget', instructions=0,
                     captured=False, imageBase=base, imageSize=size, lastAddress=None, tls=tls)
        tsc_reads = 0
        dirty_pages = set()
        instruction_cache = {}
        cached_pages = set()
        started = time.monotonic()
        forbidden = {'syscall', 'sysenter', 'sysexit', 'sysret', 'int', 'int1', 'int3',
                     'in', 'out', 'insb', 'insd', 'insw', 'outsb', 'outsd', 'outsw',
                     'rdtsc', 'rdtscp', 'rdrand', 'rdseed', 'cpuid', 'hlt'}

        def stop(reason, **details):
            state.update(reason=reason, **details)
            machine.emu_stop()

        def on_write(mu, access, address, length, value, user):
            if any(page in cached_pages for page in range(address // 4096, (address + length - 1) // 4096 + 1)):
                # CPU and modeled API writes can change code, including across pages.
                instruction_cache.clear()
                cached_pages.clear()
            if base <= address < base + size:
                dirty_pages.update(range(address // 4096, (min(address + length, base + size) - 1) // 4096 + 1))

        def on_environment_read(mu, access, address, length, value, user):
            structure = environment.check_read(address, length)
            if structure is not None:
                stop('unmodeled_environment_field', structure=structure,
                     accessAddress=address, accessLength=length)

        def api_context(mu, label):
            args = [mu.reg_read(register) for register in (UC_X86_REG_RCX, UC_X86_REG_RDX,
                                                         UC_X86_REG_R8, UC_X86_REG_R9)]
            context = dict(apiArguments=args)
            if label.lower().endswith(('!getmodulehandlea', '!loadlibrarya')) and args[0]:
                # Decode only emulator memory, bounded to a Windows module basename.
                value = bytearray()
                try:
                    for offset in range(260):
                        byte = mu.mem_read(args[0] + offset, 1)[0]
                        if byte == 0:
                            context['requestedModule'] = value.decode('ascii', 'replace')
                            break
                        value.append(byte)
                except uc.UcError:
                    context['moduleNameUnreadable'] = True
            return context

        def on_invalid(mu, access, address, length, value, user):
            stop('unmodeled_import' if address in imported else 'unmapped_memory',
                 accessAddress=address, importName=imported.get(address), accessType=access,
                 **(api_context(mu, imported[address]) if address in imported else {}))
            return False

        def model_api(mu, label):
            dll, name = label.split('!', 1)
            argument = mu.reg_read(UC_X86_REG_RCX)
            second = mu.reg_read(UC_X86_REG_RDX)
            if dll.casefold() == 'ntdll.dll' and name in ('NtQueryInformationProcess', 'ZwQueryInformationProcess'):
                rsp = mu.reg_read(UC_X86_REG_RSP)
                if not stack_base <= rsp <= stack_base + stack_size - 0x30:
                    raise UnsupportedAPI('Process query arguments lie outside the guest stack')
                return_length = int.from_bytes(mu.mem_read(rsp + 0x28, 8), 'little')
                result, writes = environment.query_process(argument, second & 0xffffffff,
                                      mu.reg_read(UC_X86_REG_R8), mu.reg_read(UC_X86_REG_R9) & 0xffffffff,
                                      return_length)
                for write_address, write_size in writes:
                    on_write(mu, None, write_address, write_size, 0, None)
            elif dll.casefold() == 'ntdll.dll' and name in ('NtSetInformationThread', 'ZwSetInformationThread'):
                result = environment.set_thread_information(argument, second & 0xffffffff,
                                      mu.reg_read(UC_X86_REG_R8), mu.reg_read(UC_X86_REG_R9) & 0xffffffff)
            elif dll.casefold() not in ('kernel32.dll', 'kernelbase.dll'):
                return False
            elif name == 'LocalAlloc':
                result = heap.alloc(argument & 0xffffffff, second)
            elif name == 'IsDebuggerPresent':
                result = environment.is_debugger_present()
            elif name == 'GetCurrentProcess':
                result = 0xffffffffffffffff
            elif name == 'GetCurrentThread':
                result = 0xfffffffffffffffe
            elif name == 'CheckRemoteDebuggerPresent':
                if argument != 0xffffffffffffffff or not second:
                    raise UnsupportedAPI('Debugger query supports only the guest current-process pseudo-handle and a valid output pointer')
                mu.mem_write(second, struct.pack('<I', environment.is_debugger_present()))
                on_write(mu, None, second, 4, environment.is_debugger_present(), None)
                result = 1
            elif name in ('GetModuleHandleA', 'GetModuleHandleW') and module_dirs:
                text = read_guest_string(mu, argument, wide=name.endswith('W')) if argument else None
                result = loader.get_handle(text)
            elif name in ('LoadLibraryA', 'LoadLibraryW') and module_dirs:
                text = read_guest_string(mu, argument, wide=name.endswith('W'))
                result = loader.load(text).base
            elif name == 'GetProcAddress' and module_dirs:
                symbol = second if second <= 0xffff else read_guest_string(mu, second, limit=4096)
                result = loader.resolve(argument, symbol)
            else:
                return False
            rsp = mu.reg_read(UC_X86_REG_RSP)
            if not stack_base <= rsp <= stack_base + stack_size - 8:
                raise UnsupportedAPI('Modeled API return address lies outside the guest stack')
            return_address = int.from_bytes(mu.mem_read(rsp, 8), 'little')
            mu.reg_write(UC_X86_REG_RAX, result)
            mu.reg_write(UC_X86_REG_RSP, rsp + 8)
            mu.reg_write(UC_X86_REG_RIP, return_address)
            return True

        def on_code(mu, address, length, user):
            nonlocal tsc_reads
            state['instructions'] += 1
            state['lastAddress'] = address
            if time.monotonic() - started >= timeout_seconds:
                stop('time_budget')
                return
            if not 1 <= length <= 15:
                stop('invalid_instruction_size', instructionSize=length)
                return
            label = imported.get(address) or loader.export_labels.get(address)
            if label:
                try:
                    if model_api(mu, label):
                        return
                    if address in imported:
                        if not module_dirs:
                            stop('unmodeled_import', importName=label, accessAddress=address,
                                 **api_context(mu, label))
                            return
                        dll, symbol = label.split('!', 1)
                        symbol = int(symbol[1:]) if symbol.startswith('#') else symbol
                        dependency = loader.load(dll)
                        destination = loader.resolve(dependency.base, symbol)
                        if not destination:
                            raise UnsupportedAPI('Imported symbol is absent from the loaded module')
                        mu.reg_write(UC_X86_REG_RIP, destination)
                        return
                except (UnsupportedAPI, OSError, uc.UcError) as error:
                    stop('unsupported_api_arguments' if isinstance(error, UnsupportedAPI) else 'module_loader_error',
                         importName=label,
                         detail=str(error), **api_context(mu, label))
                    return
            if not base <= address < base + size:
                module = loader.containing(address)
                if module is None:
                    stop('execution_outside_image')
                    return
                if module.tls_rva or module.entry_point:
                    stop('module_initialization_not_modeled', moduleName=module.name,
                         tlsRva=module.tls_rva, entryPointRva=module.entry_point)
                    return
                if not any(start <= address - module.base < end for start, end in module.executable_ranges):
                    stop('execution_in_module_data', moduleName=module.name)
                    return
            if (address // 4096 in dirty_pages and any(start <= address < end for start, end in reserved)
                    and any(mu.mem_read(address, min(length, base + size - address)))):
                stop('candidate_transition', status='candidate', transitionRva=address - base)
                return
            key = (address, length)
            if key not in instruction_cache:
                code = bytes(mu.mem_read(address, length))
                mnemonic = ''
                if needs_instruction_decode(code):
                    instruction = next(decoder.disasm_lite(code, address, count=1), None)
                    mnemonic = instruction[2] if instruction else None
                if len(instruction_cache) >= 65536:
                    instruction_cache.clear()
                    cached_pages.clear()
                instruction_cache[key] = mnemonic
                cached_pages.update(range(address // 4096, (address + length - 1) // 4096 + 1))
            mnemonic = instruction_cache[key]
            if mnemonic is None:
                stop('undecodable_instruction')
            elif mnemonic == 'rdtsc' and model_tsc:
                ticks = state['instructions'] * 100
                mu.reg_write(UC_X86_REG_RAX, ticks & 0xffffffff)
                mu.reg_write(UC_X86_REG_RDX, ticks >> 32)
                mu.reg_write(UC_X86_REG_RIP, address + length)
                tsc_reads += 1
            elif mnemonic in forbidden:
                stop('unmodeled_instruction', mnemonic=mnemonic)

        machine.hook_add(uc.UC_HOOK_MEM_WRITE, on_write)
        machine.hook_add(uc.UC_HOOK_MEM_READ, on_environment_read,
                         begin=environment.TEB, end=environment.TEB + 4095)
        machine.hook_add(uc.UC_HOOK_MEM_READ, on_environment_read,
                         begin=environment.PEB, end=environment.PEB + environment.REGION_SIZE - 1)
        machine.hook_add(uc.UC_HOOK_MEM_INVALID, on_invalid)
        machine.hook_add(uc.UC_HOOK_CODE, on_code)
        entry = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if not header_size <= entry < size:
            raise ValueError('Entry point outside image sections')
        try:
            machine.emu_start(base + entry, base + size, timeout=timeout_seconds * 1_000_000,
                              count=max_instructions)
        except uc.UcError as error:
            state['emulatorError'] = str(error)
            if state['reason'] == 'instruction_or_time_budget':
                state['reason'] = 'emulator_error'
        state['lastAddress'] = machine.reg_read(UC_X86_REG_RIP)
        state['writtenImagePages'] = len(dirty_pages)
        state['apiModels'] = dict(localAllocCalls=heap.calls, heapBytesAllocated=heap.allocated)
        state['moduleLoader'] = loader.report()
        state['windowsEnvironment'] = environment.report()
        state['timingModel'] = dict(enabled=bool(model_tsc), rdtscReads=tsc_reads,
                                   ticksPerInstruction=100 if model_tsc else None,
                                   realTiming=False)
        if state['status'] == 'candidate':
            Path(capture_path).write_bytes(bytes(machine.mem_read(base, size)))
            state['captured'] = True
        state['limitations'] = [
            'Static TLS, selected TEB/PEB fields, LDR lists, fixed LocalAlloc and module APIs are modeled; unknown environment fields, exceptions and threads remain unsupported.',
            'PEB version fields come from an explicit emulation profile, not the captured process; unconfigured version reads stop the probe.',
            'DLLs are mapped only in guest memory; imports resolve lazily. DLL entry points and TLS initialization are not run; their unmodeled code execution is blocked.',
            'LocalAlloc has a 64 MiB page-rounded budget; unspecified LMEM_FIXED memory starts zeroed, one possible initial state.',
            'Opt-in RDTSC uses instruction-count times 100; timing-dependent paths are hypothetical, not equivalent to a real Windows execution.',
            'Image pages are mapped RWX for observation; this is not Windows loader behavior.',
            'Registers start from the emulator defaults; no real process state is supplied.',
            'A transition into written memory is not proof of the original entry point or complete unpacking.',
            'Imported pointers contain probe sentinels and must not be treated as a recovered IAT.',
            'No executable reconstruction or devirtualization is performed.']
        return state
    finally:
        pe.close()
