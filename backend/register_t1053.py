#!/usr/bin/env python3
"""
Script to add T1053 template to template_loader.py
"""
import time

# Wait for any linter to finish
time.sleep(3)

loader_path = "app/data/remediation_templates/template_loader.py"

# Read the file
with open(loader_path, "r") as f:
    content = f.read()

# Check if already added
if "from .t1053_scheduled_task import TEMPLATE as T1053" in content:
    print("T1053 import already exists")
else:
    # Add import after t1055_process_injection
    content = content.replace(
        "from .t1095_non_app_layer_protocol import TEMPLATE as T1095",
        "from .t1095_non_app_layer_protocol import TEMPLATE as T1095\nfrom .t1053_scheduled_task import TEMPLATE as T1053",
    )
    print("Added T1053 import")

# Check if registry entry already exists
if '"T1053": T1053,' in content:
    print("T1053 registry entry already exists")
else:
    # Add registry entry after T1055 (process injection is similar to scheduled tasks)
    content = content.replace(
        '    "T1055": T1055,', '    "T1055": T1055,\n    "T1053": T1053,'
    )
    print("Added T1053 registry entry")

# Write back
with open(loader_path, "w") as f:
    f.write(content)

print(f"Updated {loader_path}")
