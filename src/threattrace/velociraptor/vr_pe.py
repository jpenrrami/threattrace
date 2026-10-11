from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

MAX_EXPORTS_TO_PARSE = 4096


@dataclass(frozen=True)
class PEExport:
    name: str | None
    ordinal: int

    @property
    def rundll32_entrypoint(self) -> str:
        return self.name or f"#{self.ordinal}"


@dataclass(frozen=True)
class PEDllExecution:
    loader: str
    entrypoint: str
    exports: tuple[PEExport, ...]


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _cstring(data: bytes, offset: int) -> str:
    end = data.find(b"\x00", offset)
    if end < 0:
        end = min(len(data), offset + 256)
    return data[offset:end].decode("ascii", errors="ignore")


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int | None:
    for va, virtual_size, raw_ptr, raw_size in sections:
        size = max(virtual_size, raw_size)
        if va <= rva < va + size:
            return raw_ptr + (rva - va)
    return None


def _bounded_count(value: int) -> int:
    if value < 0:
        return 0
    return min(value, MAX_EXPORTS_TO_PARSE)


def read_pe_exports(path: Path) -> tuple[PEExport, ...]:
    """Return PE export table entries, or an empty tuple for invalid/unreadable files."""
    try:
        data = path.read_bytes()
    except OSError:
        return ()
    if len(data) < 0x100 or data[:2] != b"MZ":
        return ()
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 0x108 >= len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        return ()
    file_header = pe_offset + 4
    section_count = _u16(data, file_header + 2)
    optional_size = _u16(data, file_header + 16)
    optional = file_header + 20
    magic = _u16(data, optional)
    data_dir = optional + (112 if magic == 0x20B else 96)
    if data_dir + 8 > len(data):
        return ()
    export_rva = _u32(data, data_dir)
    if not export_rva:
        return ()
    section_table = optional + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for idx in range(section_count):
        off = section_table + idx * 40
        if off + 40 > len(data):
            break
        virtual_size = _u32(data, off + 8)
        virtual_address = _u32(data, off + 12)
        raw_size = _u32(data, off + 16)
        raw_ptr = _u32(data, off + 20)
        sections.append((virtual_address, virtual_size, raw_ptr, raw_size))
    export_off = _rva_to_offset(export_rva, sections)
    if export_off is None or export_off + 40 > len(data):
        return ()
    ordinal_base = _u32(data, export_off + 16)
    function_count = _u32(data, export_off + 20)
    name_count = _u32(data, export_off + 24)
    names_rva = _u32(data, export_off + 32)
    ordinals_rva = _u32(data, export_off + 36)
    names_off = _rva_to_offset(names_rva, sections)
    ordinals_off = _rva_to_offset(ordinals_rva, sections)
    names_by_ordinal: dict[int, str] = {}
    if names_off is not None and ordinals_off is not None:
        for idx in range(_bounded_count(name_count)):
            name_rva_off = names_off + idx * 4
            ord_off = ordinals_off + idx * 2
            if name_rva_off + 4 > len(data) or ord_off + 2 > len(data):
                break
            name_off = _rva_to_offset(_u32(data, name_rva_off), sections)
            if name_off is None or name_off >= len(data):
                continue
            ordinal = ordinal_base + _u16(data, ord_off)
            name = _cstring(data, name_off)
            if name:
                names_by_ordinal[ordinal] = name
    exports: list[PEExport] = []
    for index in range(_bounded_count(function_count)):
        ordinal = ordinal_base + index
        exports.append(PEExport(name=names_by_ordinal.get(ordinal), ordinal=ordinal))
    return tuple(exports)


def choose_dll_execution(path: Path) -> PEDllExecution:
    """Choose a conservative Windows DLL loader and entrypoint from PE exports."""
    exports = read_pe_exports(path)
    by_name = {str(item.name).lower(): item for item in exports if item.name}
    if "dllregisterserver" in by_name:
        return PEDllExecution(loader="regsvr32", entrypoint="DllRegisterServer", exports=exports)
    for preferred in ("startw", "start", "run", "entrypoint", "control_rundll"):
        if preferred in by_name:
            exp = by_name[preferred]
            return PEDllExecution(loader="rundll32", entrypoint=exp.rundll32_entrypoint, exports=exports)
    if exports:
        return PEDllExecution(loader="rundll32", entrypoint=exports[0].rundll32_entrypoint, exports=exports)
    return PEDllExecution(loader="rundll32", entrypoint="#1", exports=())
