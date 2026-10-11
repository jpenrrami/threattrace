from __future__ import annotations

import re
from typing import Any

from threattrace.common.collections import dedupe_strings_lower_sorted as _dedupe

LOL_BINS = [
    "powershell",
    "cmd.exe",
    "rundll32",
    "regsvr32",
    "mshta",
    "wmic",
    "certutil",
    "bitsadmin",
    "cscript",
    "wscript",
    "psexec",
]


CREDENTIAL_PATTERNS = [
    "mimikatz",
    "lsass",
    "sekurlsa",
    "procdump",
    "samdump",
    "ntdsutil",
]


LATERAL_MOVEMENT_PATTERNS = [
    "psexec",
    "wmic",
    "winrm",
    "schtasks",
    "net use",
    "remote desktop",
]


INJECTION_PATTERNS = [
    "createremotethread",
    "writeprocessmemory",
    "setwindowshookex",
    "queueuserapc",
]

PROCESS_HOLLOWING_PATTERNS = [
    "process hollowing",
    "ntunmapviewofsection",
    "resume thread",
]

DEFENDER_TAMPERING_PATTERNS = [
    "windows-defender-remover",
    "defender",
    "disableantispyware",
    "set-mppreference",
    "tamperprotection",
    "windefend",
]

RANSOMWARE_PROCESS_PATTERNS = [
    "vssadmin delete shadows",
    "wbadmin delete",
    "bcdedit /set",
    "cipher /w",
    "wevtutil cl",
]

RANSOM_NOTE_PATTERNS = [
    "readme",
    "decrypt",
    "restore",
    "recover",
    "ransom",
]

def extract_process_iocs(report: dict[str, Any]) -> dict[str, Any]:
    """
    Extract process execution IoCs from CAPE report.

    Coverage:
    - Process tree
    - Command lines
    - LOLBins
    - Credential theft
    - Lateral movement
    - Suspicious binaries
    - Injection heuristics
    """

    behavior = report.get("behavior", {}) or {}
    summary = behavior.get("summary", {}) or {}
    processes = behavior.get("processes", []) or []

    command_lines: list[str] = []
    process_names: list[str] = []
    lolbins: list[str] = []
    credential_access: list[str] = []
    lateral_movement: list[str] = []
    suspicious_processes: list[str] = []
    injection_indicators: list[str] = []

    process_hollowing: list[str] = []
    mutexes: list[str] = []

    defender_tampering: list[str] = []
    ransomware_activity: list[str] = []
    ransom_notes: list[str] = []

    mutexes.extend(summary.get("mutexes", []) or [])

    for proc in processes:
        process_name = proc.get("process_name")
        command_line = proc.get("command_line", "")

        if process_name:
            process_names.append(process_name)

        if command_line:
            command_lines.append(command_line)

        lower_cmd = command_line.lower()

        # LOLBins
        if any(re.search(rf"\b{re.escape(bin_name)}\b", lower_cmd) for bin_name in LOL_BINS):
            lolbins.append(command_line)

        # Credential theft
        if any(pattern in lower_cmd for pattern in CREDENTIAL_PATTERNS):
            credential_access.append(command_line)

        # Lateral movement
        if any(pattern in lower_cmd for pattern in LATERAL_MOVEMENT_PATTERNS):
            lateral_movement.append(command_line)

        # Injection heuristics
        if any(pattern in lower_cmd for pattern in INJECTION_PATTERNS):
            injection_indicators.append(command_line)

        # Process hollowing detection
        if any(pattern in lower_cmd for pattern in PROCESS_HOLLOWING_PATTERNS):
            process_hollowing.append(command_line)

        # Defender / EDR tampering
        if any(pattern in lower_cmd for pattern in DEFENDER_TAMPERING_PATTERNS):
            defender_tampering.append(command_line)

        # Ransomware destructive activity
        if any(pattern in lower_cmd for pattern in RANSOMWARE_PROCESS_PATTERNS):
            ransomware_activity.append(command_line)

        # Ransom note references
        if any(pattern in lower_cmd for pattern in RANSOM_NOTE_PATTERNS):
            ransom_notes.append(command_line)

        # Suspicious paths
        if any(
            re.search(rf"\\\\{re.escape(p.strip(chr(92)))}\\", lower_cmd)
            for p in [
                "\\temp\\",
                "\\appdata\\",
                "\\programdata\\",
                "\\users\\public\\",
            ]
        ):
            suspicious_processes.append(command_line)

    attack_patterns = {
        "lolbins_usage": bool(lolbins),
        "credential_access": bool(credential_access),
        "lateral_movement": bool(lateral_movement),
        "process_injection": bool(injection_indicators),
        "process_hollowing": bool(process_hollowing),
        "defender_tampering": bool(defender_tampering),
        "shadow_copy_deletion": bool(ransomware_activity),
        "crypto_activity": bool(ransomware_activity),
        "ransomware_extension_activity": bool(ransom_notes),
    }

    defense_evasion_indicators: list[str] = []
    if attack_patterns["lolbins_usage"]:
        defense_evasion_indicators.append("lolbins_usage")

    if attack_patterns["defender_tampering"]:
        defense_evasion_indicators.append("defender_tampering")

    credential_access_indicators: list[str] = []
    if attack_patterns["credential_access"]:
        credential_access_indicators.append("credential_access")

    if attack_patterns["process_hollowing"]:
        injection_indicators.append("process_hollowing_detected")

    process_names_d = _dedupe(process_names)
    command_lines_d = _dedupe(command_lines)
    lolbins_d = _dedupe(lolbins)
    credential_d = _dedupe(credential_access)
    lateral_d = _dedupe(lateral_movement)
    suspicious_d = _dedupe(suspicious_processes)
    injection_d = _dedupe(injection_indicators)
    defender_d = _dedupe(defender_tampering)
    ransomware_d = _dedupe(ransomware_activity)
    ransom_notes_d = _dedupe(ransom_notes)
    mutexes_d = _dedupe(mutexes)

    return {
        "process_names": process_names_d,
        "command_lines": command_lines_d,
        "mutexes": mutexes_d,
        "lolbins": lolbins_d,
        "credential_access": credential_d,
        "lateral_movement": lateral_d,
        "suspicious_processes": suspicious_d,
        "injection_indicators": injection_d,
        "defender_tampering": defender_d,
        "ransomware_activity": ransomware_d,
        "ransom_notes": ransom_notes_d,
        "attack_patterns": attack_patterns,
        "defense_evasion_indicators": _dedupe(defense_evasion_indicators),
        "credential_access_indicators": _dedupe(credential_access_indicators),
        "counts": {
            "mutexes": len(mutexes_d),
            "process_names": len(process_names_d),
            "command_lines": len(command_lines_d),
            "lolbins": len(lolbins_d),
            "credential_access": len(credential_d),
            "lateral_movement": len(lateral_d),
            "suspicious_processes": len(suspicious_d),
            "injection_indicators": len(injection_d),
            "defender_tampering": len(defender_d),
            "ransomware_activity": len(ransomware_d),
            "ransom_notes": len(ransom_notes_d),
        },
    }
