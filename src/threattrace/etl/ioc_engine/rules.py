from __future__ import annotations

# =========================
# LOLBins / Living-off-the-land binaries
# =========================
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
    "msbuild",
    "installutil",
]


# =========================
# Registry persistence
# =========================
PERSISTENCE_KEYS = [
    r"software\microsoft\windows\currentversion\run",
    r"software\microsoft\windows\currentversion\runonce",
    r"software\microsoft\windows\currentversion\policies\explorer\run",
    r"software\microsoft\windows nt\currentversion\winlogon",
    r"software\microsoft\windows\currentversion\shellserviceobjectdelayload",
    r"system\currentcontrolset\services",
    r"software\\microsoft\\windows\\currentversion\\runservices",
    r"software\\microsoft\\windows\\currentversion\\runservicesonce",
    r"software\\microsoft\\windows nt\\currentversion\\image file execution options",
    r"software\\microsoft\\windows\\currentversion\\policies\\system",
]


# =========================
# Defender / AV tampering
# =========================
DEFENDER_TAMPERING_KEYS = [
    "disableantispyware",
    "disableantivirus",
    "tamperprotection",
    "real-time protection",
    "windefend",
    "mpcmdrun",
]


# =========================
# WMI persistence (Event Consumers)
# =========================
WMI_PERSISTENCE_KEYS = [
    "__eventfilter",
    "commandlineeventconsumer",
    "filtertoconsumerbinding",
]


# =========================
# Shadow copy / backup destruction
# =========================
SHADOW_COPY_PATTERNS = [
    "vssadmin delete",
    "wmic shadowcopy delete",
    "wbadmin delete",
    "bcdedit",
]


# =========================
# Backup tampering patterns
# =========================
BACKUP_TAMPERING_PATTERNS = [
    "wbadmin delete catalog",
    "wbadmin delete backup",
    "bcdedit /set",
]


# =========================
# Ransomware file extensions
# =========================
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
    ".ryuk",
    ".ryk",
    ".conti",
    ".akira",
    ".blackcat",
    ".alphv",
    ".hive",
    ".royal",
    ".medusa",
    ".clop",
    ".play",
    ".rhysida",
    ".lockbit",
]


# =========================
# Ransom note patterns
# =========================
RANSOM_NOTE_PATTERNS = [
    "readme",
    "decrypt",
    "recover",
    "restore",
    "how_to",
    "ransom",
    "payment",
    "bitcoin",
    "recover_files",
    "restore_files",
    "lockbit",
    "blackcat",
    "alphv",
    "akira",
    "hive",
    "royal",
    "medusa",
    "conti",
]


# =========================
# Family-specific identifiers
# =========================
RANSOMWARE_FAMILY_PATTERNS = {
    "lockbit": ["lockbit", ".lockbit", "lockbit black"],
    "blackcat": ["blackcat", "alphv", ".blackcat", ".alphv"],
    "akira": ["akira", ".akira"],
    "hive": ["hive", ".hive"],
    "royal": ["royal", ".royal"],
    "medusa": ["medusa", "medusalocker", ".medusa"],
    "conti": ["conti", ".conti"],
    "clop": ["clop", ".clop"],
    "play": ["play", ".play"],
    "rhysida": ["rhysida", ".rhysida"],
    "ryuk": ["ryuk", ".ryuk"],
    "wannacry": ["wncry", "wannacry", ".wncry"],
}


# =========================
# Credential theft indicators
# =========================
CREDENTIAL_PATTERNS = [
    "mimikatz",
    "lsass",
    "sekurlsa",
    "procdump",
    "samdump",
    "ntdsutil",
    "comsvcs.dll",
    "vaultcmd",
    "browserpass",
    "cookie",
]


# =========================
# Lateral movement indicators
# =========================
LATERAL_MOVEMENT_PATTERNS = [
    "psexec",
    "wmic",
    "winrm",
    "schtasks",
    "net use",
    "remote desktop",
    "smb",
    "admin$",
    "c$",
    "net view",
]


# =========================
# Process injection
# =========================
INJECTION_PATTERNS = [
    "createremotethread",
    "writeprocessmemory",
    "setwindowshookex",
    "queueuserapc",
]


# =========================
# Process hollowing patterns
# =========================
PROCESS_HOLLOWING_PATTERNS = [
    "process hollowing",
    "ntunmapviewofsection",
    "resume thread",
]


# =========================
# Crypto APIs
# =========================
CRYPTO_APIS = [
    "cryptencrypt",
    "cryptdecrypt",
    "cryptacquirecontext",
    "bcryptencrypt",
    "bcryptdecrypt",
    "bcryptgenrandom",
]


# =========================
# Credential APIs
# =========================
CREDENTIAL_APIS = [
    "credsenumerate",
    "lsaopenpolicy",
    "lsaretrieveprivatedata",
    "samopenuser",
    "logonuser",
    "readprocessmemory",
]


# =========================
# Defense evasion APIs
# =========================
DEFENSE_EVASION_APIS = [
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "zwqueryinformationprocess",
    "virtualprotect",
    "writeprocessmemory",
    "createremotethread",
    "ntsetinformationthread",
    "rtladjustprivilege",
    "setunhandledexceptionfilter",
    "terminateprocess",
]


# =========================
# Persistence APIs
# =========================
PERSISTENCE_APIS = [
    "regsetvalue",
    "createservice",
    "openservice",
    "schtasks",
]


# =========================
# Suspicious TLDs / infrastructure
# =========================
SUSPICIOUS_TLDS = [
    ".biz",
    ".top",
    ".xyz",
    ".ru",
    ".cn",
    ".su",
    ".onion",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
]


# =========================
# Benign domain keywords (for filtering)
# =========================
BENIGN_DOMAIN_KEYWORDS = [
    "google.com",
    "microsoft.com",
    "windows.com",
    "office.com",
    "azure.com",
    "amazonaws.com",
    "cloudfront.net",
    "github.com",
]