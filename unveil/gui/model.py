"""Portable project format and validation for AMD64 memory patches."""
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import re

import pefile

MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_PATCH_BYTES = 4096


def hex_bytes(value: str) -> bytes:
    if not isinstance(value, str):
        raise ValueError('Os bytes precisam ser texto hexadecimal.')
    compact = re.sub(r'\s+', '', value)
    if not compact or len(compact) % 2 or not re.fullmatch(r'[0-9a-fA-F]+', compact):
        raise ValueError('Use pares hexadecimais, por exemplo: 31 C0 C3.')
    if len(compact) > MAX_PATCH_BYTES * 2:
        raise ValueError('Cada assinatura ou alteração tem limite de 4096 bytes.')
    return bytes.fromhex(compact)


def parse_rva(value: str) -> int:
    try:
        result = int(value.strip(), 16)
    except (ValueError, AttributeError) as exc:
        raise ValueError('RVA inválido. Informe hexadecimal, como 0x404f70.') from exc
    if not 0 <= result <= 0xffffffff:
        raise ValueError('O RVA precisa estar entre 0 e 0xffffffff.')
    return result


def read_bounded(path: Path) -> bytes:
    with path.open('rb') as stream:
        data = stream.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        raise ValueError('O limite de arquivo é 128 MiB.')
    return data


@dataclass(frozen=True)
class Patch:
    name: str
    rva: int
    expected_hex: str
    replacement_hex: str

    def validated(self, image_size: int) -> 'Patch':
        if not isinstance(self.name, str) or not self.name.strip() or len(self.name) > 120:
            raise ValueError('Dê ao patch um nome de até 120 caracteres.')
        if type(self.rva) is not int or not 0 <= self.rva < image_size:
            raise ValueError(f'RVA fora do módulo: {self.name}.')
        expected, replacement = hex_bytes(self.expected_hex), hex_bytes(self.replacement_hex)
        if len(replacement) > len(expected):
            raise ValueError('A assinatura esperada precisa cobrir todos os bytes substituídos.')
        if self.rva + len(expected) > image_size:
            raise ValueError(f'Assinatura ultrapassa o fim do módulo: {self.name}.')
        return Patch(self.name.strip(), self.rva, expected.hex(), replacement.hex())

    def runtime(self) -> dict:
        return dict(name=self.name, rva=self.rva, expectedHex=self.expected_hex,
                    patchHex=self.replacement_hex)


@dataclass(frozen=True)
class Project:
    source: str
    sha256: str
    image_size: int
    title: str = 'Application'
    patches: tuple[Patch, ...] = ()
    capture: bool = True
    memory_mb: int = 4096

    @classmethod
    def open_sample(cls, source: str) -> 'Project':
        path = Path(source).resolve(strict=True)
        data = read_bounded(path)
        with pefile.PE(data=data, fast_load=True) as pe:
            if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b:
                raise ValueError('O editor de patches suporta EXE PE AMD64 (64 bits).')
            if pe.FILE_HEADER.Characteristics & 0x2000:
                raise ValueError('Selecione um EXE; o launcher não inicia DLLs.')
            size = pe.OPTIONAL_HEADER.SizeOfImage
        if not 0 < size <= MAX_FILE_BYTES:
            raise ValueError('SizeOfImage inválido ou maior que 128 MiB.')
        return cls(str(path), hashlib.sha256(data).hexdigest(), size, title=path.stem)

    def validated(self) -> 'Project':
        if not isinstance(self.source, str) or not self.source:
            raise ValueError('A amostra não foi selecionada.')
        if not isinstance(self.sha256, str) or not re.fullmatch('[0-9a-f]{64}', self.sha256):
            raise ValueError('SHA-256 inválido no projeto.')
        if type(self.image_size) is not int or not 0 < self.image_size <= MAX_FILE_BYTES:
            raise ValueError('Tamanho de imagem inválido.')
        if not isinstance(self.title, str) or not self.title.strip() or len(self.title) > 256 or '\0' in self.title:
            raise ValueError('Informe o título exato da janela que deve aparecer antes do patch.')
        if type(self.capture) is not bool or type(self.memory_mb) is not int or not 2048 <= self.memory_mb <= 8192:
            raise ValueError('Configuração de captura ou RAM inválida.')
        if len(self.patches) > 128:
            raise ValueError('O projeto suporta até 128 patches.')
        patches = tuple(p.validated(self.image_size) for p in self.patches)
        seen = set()
        intervals = []
        for patch in patches:
            if patch.name in seen:
                raise ValueError(f'Nome duplicado: {patch.name}.')
            seen.add(patch.name)
            intervals.append((patch.rva, patch.rva + len(bytes.fromhex(patch.expected_hex)), patch.name))
        intervals.sort()
        for left, right in zip(intervals, intervals[1:]):
            if left[1] > right[0]:
                raise ValueError(f'Assinaturas sobrepostas: {left[2]} / {right[2]}.')
        return Project(self.source, self.sha256, self.image_size, self.title.strip(), patches,
                       self.capture, self.memory_mb)

    def save(self, path: Path) -> None:
        if path.resolve() == Path(self.source).resolve():
            raise ValueError('O projeto não pode sobrescrever a amostra.')
        path.write_text(json.dumps(dict(version=1, **asdict(self.validated())), indent=2,
                                   ensure_ascii=False), encoding='utf-8')

    @classmethod
    def load(cls, path: Path) -> 'Project':
        if path.stat().st_size > 2 * 1024 * 1024:
            raise ValueError('Projeto JSON maior que 2 MiB.')
        value = json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(value, dict) or type(value.get('version')) is not int or value['version'] != 1:
            raise ValueError('Versão de projeto não suportada.')
        required = {'source', 'sha256', 'image_size', 'title', 'patches', 'capture', 'memory_mb'}
        if set(value) != required | {'version'} or not isinstance(value['patches'], list):
            raise ValueError('Campos inválidos no projeto.')
        patches = []
        for item in value['patches']:
            if not isinstance(item, dict) or set(item) != {'name', 'rva', 'expected_hex', 'replacement_hex'}:
                raise ValueError('Definição de patch inválida.')
            patches.append(Patch(**item))
        return cls(**{k: value[k] for k in required if k != 'patches'}, patches=tuple(patches)).validated()


def import_patches(path: Path, image_size: int) -> tuple[Patch, ...]:
    if path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError('Lista de patches maior que 2 MiB.')
    values = json.loads(path.read_text(encoding='utf-8-sig'))
    if not isinstance(values, list) or len(values) > 128:
        raise ValueError('Esperada uma lista JSON de até 128 patches.')
    patches = []
    for item in values:
        if not isinstance(item, dict) or not {'name', 'rva', 'expectedHex', 'patchHex'} <= set(item):
            raise ValueError('Cada patch precisa de name, rva, expectedHex e patchHex.')
        patches.append(Patch(item['name'], item['rva'], item['expectedHex'], item['patchHex']).validated(image_size))
    return tuple(patches)
