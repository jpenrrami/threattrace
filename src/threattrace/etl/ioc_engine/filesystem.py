from __future__ import annotations

from typing import Any

from threattrace.common.collections import dedupe_strings_lower_sorted as _dedupe

RANSOM_EXTENSIONS = [
    ".locked",
    ".lock",
    ".crypted",
    ".crypt",
    ".enc",
    ".encrypted",
    ".cry",
    ".wallet",
    ".wncry",
    ".zepto",
    ".cerber",
    ".ryk",
    ".ryuk",
]


RANSOM_NOTE_PATTERNS = [
    "readme",
    "decrypt",
    "recover",
    "restore",
    "how_to",
    "ransom",
    "payment",
    "bitcoin",
]

SUSPICIOUS_WRITABLE_DIR_FRAGMENTS = [
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\programdata\\",
    "\\users\\public\\",
    "\\desktop\\",
    "\\documents\\",
    "\\downloads\\",
    "\\startup\\",
    "\\windows\\temp\\",
    "\\vr-malware-test\\",
]

SUSPICIOUS_FILE_EXTENSIONS = [
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta", ".lnk",
    ".locked", ".lock", ".crypted", ".crypt", ".enc", ".encrypted", ".tmp", ".dat", ".bin",
]


SHADOW_COPY_PATTERNS = [
    "vssadmin delete",
    "wmic shadowcopy delete",
    "wbadmin delete",
    "bcdedit",
]

BACKUP_TAMPERING_PATTERNS = [
    "wbadmin delete catalog",
    "wbadmin delete backup",
    "bcdedit /set",
]

def extract_filesystem_iocs(report: dict[str, Any]) -> dict[str, Any]:
    """
    Extract filesystem-related IoCs from CAPE report.

    Coverage:
    - Dropped files
    - File reads/writes/deletes
    - Ransomware extensions
    - Ransom notes
    - Shadow copy deletion
    - Backup tampering
    """

    summary = report.get("behavior", {}).get("summary", {}) or {}
    processes = report.get("behavior", {}).get("processes", []) or []

    dropped_files: list[str] = []
    suspicious_files: list[str] = []
    ransomware_files: list[str] = []
    ransom_notes: list[str] = []
    shadow_copy_commands: list[str] = []
    backup_tampering_commands: list[str] = []

    # Aggregate filesystem activity
    for field in ("files", "read_files", "write_files", "delete_files"):
        dropped_files.extend(summary.get(field, []) or [])

    # Analyze files
    for file_path in dropped_files:
        lower_path = file_path.lower()

        # Ransomware extension detection
        if any(lower_path.endswith(ext) for ext in RANSOM_EXTENSIONS):
            ransomware_files.append(file_path)

        # Ransom note detection
        if any(pattern in lower_path for pattern in RANSOM_NOTE_PATTERNS):
            ransom_notes.append(file_path)

        if (
            any(fragment in lower_path for fragment in SUSPICIOUS_WRITABLE_DIR_FRAGMENTS)
            and (
                any(lower_path.endswith(ext) for ext in SUSPICIOUS_FILE_EXTENSIONS)
                or any(pattern in lower_path for pattern in RANSOM_NOTE_PATTERNS)
            )
        ):
            suspicious_files.append(file_path)

    # Process command line analysis
    for proc in processes:
        cmd = proc.get("command_line", "")
        if not cmd:
            continue

        lower_cmd = cmd.lower()

        if any(pattern in lower_cmd for pattern in SHADOW_COPY_PATTERNS):
            shadow_copy_commands.append(cmd)

        if any(pattern in lower_cmd for pattern in BACKUP_TAMPERING_PATTERNS):
            backup_tampering_commands.append(cmd)

    # Behavioral indicators
    attack_patterns = {
        "shadow_copy_deletion": bool(shadow_copy_commands),
        "backup_tampering": bool(backup_tampering_commands),
        "ransom_note_creation": bool(ransom_notes),
        "mass_file_modification": len(dropped_files) > 50,
        "ransomware_extension_activity": bool(ransomware_files),
    }

    ransomware_indicators: list[str] = []

    if attack_patterns["shadow_copy_deletion"]:
        ransomware_indicators.append("shadow_copy_deletion")

    if attack_patterns["backup_tampering"]:
        ransomware_indicators.append("backup_tampering")

    if attack_patterns["ransom_note_creation"]:
        ransomware_indicators.append("ransom_note_creation")

    if attack_patterns["ransomware_extension_activity"]:
        ransomware_indicators.append("encrypted_file_extensions")

    if attack_patterns["mass_file_modification"]:
        ransomware_indicators.append("mass_file_modification")

    dropped_d = _dedupe(dropped_files)
    suspicious_d = _dedupe(suspicious_files)
    ransomware_d = _dedupe(ransomware_files)
    ransom_notes_d = _dedupe(ransom_notes)
    shadow_d = _dedupe(shadow_copy_commands)
    backup_d = _dedupe(backup_tampering_commands)
    indicators_d = _dedupe(ransomware_indicators)

    return {
        "dropped_files": dropped_d,
        "suspicious_files": suspicious_d,
        "ransomware_files": ransomware_d,
        "ransom_notes": ransom_notes_d,
        "shadow_copy_commands": shadow_d,
        "backup_tampering_commands": backup_d,
        "attack_patterns": attack_patterns,
        "ransomware_indicators": indicators_d,
        "counts": {
            "dropped_files": len(dropped_d),
            "suspicious_files": len(suspicious_d),
            "ransomware_files": len(ransomware_d),
            "ransom_notes": len(ransom_notes_d),
            "shadow_copy_commands": len(shadow_d),
            "backup_tampering_commands": len(backup_d),
        },
    }
