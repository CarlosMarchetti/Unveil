"""Explainable protection triage; never infer a version from section names."""


def detect_vmprotect(metadata, entry_bytes=b''):
    sections = metadata['sections']
    names = {s['name'] for s in sections}
    if any(d['index'] == 14 and d['address'] for d in metadata['dataDirectories']):
        return None  # This detector targets native PE, not managed protectors.
    evidence = []
    score = 0
    if '.vmp0' in names and '.vmp1' in names:
        evidence.append(dict(signal='section_names', detail='Both .vmp0 and .vmp1 are present'))
        score += 40
    reserved = [s for s in sections if s['size'] == 0 and s['virtualSize'] > 0]
    packed = [s for s in sections if s['size'] >= 4096 and s['entropy'] >= 7.6 and 'X' in s['permissions']]
    if len(reserved) >= 3:
        evidence.append(dict(signal='unbacked_sections', detail=f'{len(reserved)} sections have virtual size but no file bytes'))
        score += 15
    if packed:
        evidence.append(dict(signal='high_entropy_code', detail='High-entropy executable sections: ' + ', '.join(s['name'] for s in packed)))
        score += 15
    stub = len(entry_bytes) >= 10 and entry_bytes[0] == 0x68 and entry_bytes[5] in (0xe8, 0xe9)
    if stub:
        evidence.append(dict(signal='entry_stub', detail='Entry begins with PUSH imm32 followed by CALL/JMP rel32'))
        score += 15
    functions = {symbol['name'] for dll in metadata['imports'] for symbol in dll['symbols']}
    if {'LoadLibraryA', 'GetProcAddress'} <= functions:
        evidence.append(dict(signal='dynamic_imports', detail='LoadLibraryA and GetProcAddress imports are present'))
        score += 5
    # Generic packing characteristics are insufficient to name VMProtect.
    if not ({'.vmp0', '.vmp1'} <= names) or score < 55:
        return None
    return dict(name='VMProtect', status='suspected', confidence=min(score, 90),
                version=None, versionBasis='No version signature has been independently evaluated',
                evidence=evidence, packingLikely=bool(reserved and packed),
                virtualization='not_proven',
                limitations=['Names and byte patterns can be forged; confidence is a heuristic score.',
                             'The DiE import-position hash algorithm is not implemented.',
                             'Packing and entry stubs do not establish which functions are virtualized.'])


def unpack_plan(metadata, vmpdump_configured=False):
    protection = metadata.get('protection')
    return dict(
        detected=protection['name'] if protection else None,
        selection='unicorn-probe' if protection and metadata['architecture'] == 'AMD64' else None,
        capabilities=dict(detection=True, boundedEmulation=metadata['architecture'] == 'AMD64',
                          memorySnapshot=True,
                          liveDump='explicit_windows_opt_in',
                          importReconstruction=bool(vmpdump_configured and metadata['architecture'] == 'AMD64'),
                          runnablePeReconstruction=False, devirtualization=False),
        steps=[
            dict(id='detect', status='completed' if protection else 'unknown'),
            dict(id='live-dump', status='requires_explicit_opt_in', backend='windows-live-dump',
                 purpose='Read the matching main module with --dump; --launch additionally executes the input EXE'),
            dict(id='emulate', status='requires_explicit_opt_in', backend='unicorn-probe',
                 purpose='Experimental bounded execution of CPU instructions; no Windows API forwarding'),
            dict(id='capture', status='conditional',
                 purpose='Capture mapped image at first execution of a written, formerly unbacked executable region'),
            dict(id='reconstruct-imports',
                 status='requires_explicit_opt_in' if vmpdump_configured else 'requires_configuration',
                 backend='vmpdump' if vmpdump_configured else None,
                 purpose='Scan a live, already-unpacked process for VMProtect import stubs and rebuild an IAT',
                 requires=['Target process running under Windows and past its OEP',
                          'Externally verified VMPDump.exe binary, supplied by the user',
                          '--pid and --module identifying the live target'],
                 limitations=['Requires an already-running process; this backend does not launch the target.',
                             'Import recovery is not equivalent to devirtualization of the recovered functions.',
                             'Linear scanning of mutated code can miss some stub calls; see upstream issues.']),
            dict(id='devirtualize', status='not_implemented',
                 purpose='Requires function-level semantic recovery and equivalence validation')],
        limitations=['A capture event is a candidate transition, not proof of an original entry point.',
                     'No automatic VMProtect removal is claimed.'])
