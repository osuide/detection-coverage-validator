"""Compliance framework mapping data.

Contains authoritative mappings between compliance frameworks and MITRE ATT&CK techniques.

Data sources:
- NIST 800-53 Rev 5: MITRE CTID Mappings Explorer (https://ctid.mitre.org)
- CIS Controls v8: Official CIS Whitepaper (https://www.cisecurity.org)
"""

from pathlib import Path

# Base path for compliance mapping data files
DATA_DIR = Path(__file__).parent

NIST_800_53_FILE = DATA_DIR / "nist_800_53_r5.json"
CIS_CONTROLS_FILE = DATA_DIR / "cis_controls_v8.json"
