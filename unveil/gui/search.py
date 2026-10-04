"""Bounded binary search with explicit physical-file versus mapped-image addressing."""
from dataclasses import dataclass
from pathlib import Path
import re

import pefile

from .model import read_bounded


@dataclass(frozen=True)
class Hit:
    offset: int
    rva: int | None
    encoding: str
    text: str
    byte_length: int


class BinaryView:
    def __init__(self, path: Path, mapped: bool = False):
        self.path = path.resolve()
        self.data = read_bounded(self.path)
        self.mapped = mapped
        with pefile.PE(data=self.data, fast_load=True) as pe:
            self.image_size = pe.OPTIONAL_HEADER.SizeOfImage
            self.header_size = pe.OPTIONAL_HEADER.SizeOfHeaders
            self.sections = tuple((s.VirtualAddress, s.PointerToRawData, s.SizeOfRawData)
                                  for s in pe.sections)
        if mapped and len(self.data) != self.image_size:
            raise ValueError('Imagem mapeada precisa conter exatamente SizeOfImage bytes.')

    def offset_to_rva(self, offset: int) -> int | None:
        if not 0 <= offset < len(self.data):
            return None
        if self.mapped or offset < self.header_size:
            return offset if offset < self.image_size else None
        for rva, start, length in self.sections:
            if start <= offset < start + length:
                result = rva + offset - start
                return result if result < self.image_size else None
        return None

    def read_rva(self, rva: int, length: int) -> bytes:
        if not 1 <= length <= 4096 or rva < 0 or rva + length > self.image_size:
            raise ValueError('Intervalo de assinatura inválido.')
        if self.mapped:
            offset = rva
        elif rva + length <= self.header_size:
            offset = rva
        else:
            offset = next((start + rva - section_rva for section_rva, start, size in self.sections
                           if section_rva <= rva and rva + length <= section_rva + size), None)
            if offset is None:
                raise ValueError('Esse RVA não tem bytes físicos. Carregue uma imagem mapeada (.bin).')
        result = self.data[offset:offset + length]
        if len(result) != length:
            raise ValueError('Arquivo truncado nesse RVA.')
        return result

    def search(self, query: str, mode: str = 'strings', limit: int = 2500) -> list[Hit]:
        if not 1 <= limit <= 5000:
            raise ValueError('Limite de busca inválido.')
        hits = []
        if mode == 'hex':
            from .model import hex_bytes
            needle = hex_bytes(query)
            offset = self.data.find(needle)
            while offset >= 0 and len(hits) < limit:
                hits.append(Hit(offset, self.offset_to_rva(offset), 'hex', needle.hex(' '), len(needle)))
                offset = self.data.find(needle, offset + 1)
            return hits
        if mode != 'strings':
            raise ValueError('Modo de busca inválido.')
        patterns = [('ascii', rb'[\x20-\x7e]{4,}'), ('utf-16le', rb'(?:[\x20-\xff]\0){4,}')]
        for encoding, pattern in patterns:
            for match in re.finditer(pattern, self.data):
                # Filter full strings before truncating the displayed result.
                text = match.group().decode(encoding)
                if query.casefold() not in text.casefold():
                    continue
                hits.append(Hit(match.start(), self.offset_to_rva(match.start()), encoding,
                                text[:512], len(match.group())))
                if len(hits) >= limit:
                    return sorted(hits, key=lambda h: h.offset)
        return sorted(hits, key=lambda h: h.offset)

    def text_patch(self, hit: Hit, replacement: str) -> tuple[str, str]:
        if hit.encoding not in ('ascii', 'utf-16le') or hit.rva is None or hit.byte_length > 4094:
            raise ValueError('Selecione uma string curta com RVA válido.')
        terminator = b'\0\0' if hit.encoding == 'utf-16le' else b'\0'
        original = self.data[hit.offset:hit.offset + hit.byte_length + len(terminator)]
        if not original.endswith(terminator):
            raise ValueError('A string não tem terminador nulo; defina os bytes manualmente.')
        if '\0' in replacement:
            raise ValueError('O texto não pode conter um caractere nulo.')
        encoded = replacement.encode(hit.encoding) + terminator
        if len(encoded) > len(original):
            raise ValueError('Texto maior que o espaço original. Esta edição exige alocação/redirecionamento, não uma troca direta.')
        return original.hex(), encoded.ljust(len(original), b'\0').hex()
