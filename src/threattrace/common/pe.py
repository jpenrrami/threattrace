from __future__ import annotations

import struct
from pathlib import Path

_PE_MACHINE_ARCH = {0x014C: "x86", 0x8664: "x64"}


def detect_pe_architecture(path: Path) -> str:
    """Return x86/x64 for a valid PE file, otherwise unknown."""
    try:
        with path.open("rb") as handle:
            if handle.read(2) != b"MZ":
                return "unknown"
            handle.seek(0x3C)
            raw_offset = handle.read(4)
            if len(raw_offset) != 4:
                return "unknown"
            handle.seek(struct.unpack("<I", raw_offset)[0])
            if handle.read(4) != b"PE\x00\x00":
                return "unknown"
            raw_machine = handle.read(2)
            if len(raw_machine) != 2:
                return "unknown"
            return _PE_MACHINE_ARCH.get(struct.unpack("<H", raw_machine)[0], "unknown")
    except OSError:
        return "unknown"
