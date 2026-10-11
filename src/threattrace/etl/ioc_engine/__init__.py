"""IoC Engine package.

High-level components:
- orchestrator: entrypoint for IoC extraction
- normalizer: normalization utilities for IoCs
- network/filesystem/process/api: extractors
- registry: registry IoC extraction
- rules: detection constants
- scoring: threat scoring
- threat_intel: enrichment helpers

"""

from .normalizer import normalize_iocs
from .orchestrator import extract_iocs

__all__ = [
    "extract_iocs",
    "normalize_iocs",
]
