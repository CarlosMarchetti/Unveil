"""Shared input archive budgets, checked before decompressing any entry."""


def validate_archive(jar, *, max_entries=100_000,
                     max_entry_bytes=256 * 1024 * 1024,
                     max_total_bytes=512 * 1024 * 1024):
    """Return entries after validating declared sizes and ambiguous names.

    Includes resources: name recovery reads some resources after indexing.
    These are decompressed-byte budgets, not a bound on parser/VM memory.
    """
    infos = jar.infolist()
    if len(infos) > max_entries:
        raise ValueError('ZIP entry count exceeds safety limit')
    names = set()
    total = 0
    for info in infos:
        if info.filename in names:
            raise ValueError('Duplicate ZIP entries are ambiguous; refusing archive')
        names.add(info.filename)
        if info.flag_bits & 1:
            raise ValueError('Encrypted ZIP entries are not supported')
        if info.file_size > max_entry_bytes:
            raise ValueError('ZIP entry exceeds decompressed size safety limit')
        total += info.file_size
        if total > max_total_bytes:
            raise ValueError('ZIP total decompressed size exceeds safety limit')
    return infos
