#!/usr/bin/env python3
"""Add T1071.001 template registration to template_loader.py"""

import re

template_loader_path = "/Users/austinosuide/coolstuff/a13e/backend/app/data/remediation_templates/template_loader.py"

# Read the file
with open(template_loader_path, 'r') as f:
    content = f.read()

# Add import statement after T1071
import_pattern = r'(from \.t1071_application_layer_protocol import TEMPLATE as T1071\n)'
import_replacement = r'\1from .t1071_001_web_protocols import TEMPLATE as T1071_001\n'

if 't1071_001_web_protocols' not in content:
    content = re.sub(import_pattern, import_replacement, content)
    print("Added import statement")
else:
    print("Import already exists")

# Add registry entry after T1071
registry_pattern = r'("T1071": T1071,\n)'
registry_replacement = r'\1    "T1071.001": T1071_001,\n'

if '"T1071.001"' not in content:
    content = re.sub(registry_pattern, registry_replacement, content)
    print("Added registry entry")
else:
    print("Registry entry already exists")

# Add parent mapping
parent_pattern = r'(PARENT_MAPPINGS = \{[^}]+)'
parent_addition = '    "T1071.001": "T1071",\n'

if '"T1071.001": "T1071"' not in content:
    # Find the PARENT_MAPPINGS section and add before the closing brace
    parent_close_pattern = r'(\n\})\n\ndef get_template'
    if re.search(parent_close_pattern, content):
        content = re.sub(parent_close_pattern, f',\n{parent_addition}\\1\n\ndef get_template', content)
        print("Added parent mapping")
else:
    print("Parent mapping already exists")

# Write back
with open(template_loader_path, 'w') as f:
    f.write(content)

print("Done!")
