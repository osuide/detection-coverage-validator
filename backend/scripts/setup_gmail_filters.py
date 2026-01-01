#!/usr/bin/env python3
"""
One-time setup script for Gmail filters.

Creates keyword-based filters for automatic ticket categorisation.
Run via ECS Exec.
"""

import sys
import os

# Add the backend app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.google_workspace_service import get_workspace_service


def main():
    print("=" * 60)
    print("A13E Gmail Filter Setup")
    print("=" * 60)

    ws = get_workspace_service()
    print(f"\nAuthenticated as: {ws.delegated_user}")

    # Define keyword-based filters
    filters = [
        {
            "name": "Billing",
            "keywords": "billing OR invoice OR payment OR subscription OR refund",
            "label": "Support/Category/Billing",
        },
        {
            "name": "Bug Report",
            "keywords": "bug OR error OR broken OR crash OR not working",
            "label": "Support/Category/Bug Report",
        },
        {
            "name": "Feature Request",
            "keywords": "feature OR enhancement OR suggestion OR would be nice",
            "label": "Support/Category/Feature Request",
        },
        {
            "name": "Technical",
            "keywords": "API OR integration OR scan OR detection OR AWS OR GCP",
            "label": "Support/Category/Technical",
        },
        {
            "name": "Account",
            "keywords": "account OR password OR login OR access OR permission",
            "label": "Support/Category/Account",
        },
        {
            "name": "Urgent Priority",
            "keywords": "urgent OR emergency OR critical OR ASAP",
            "label": "Support/Priority/Urgent",
        },
    ]

    print("\n" + "-" * 60)
    print("Creating keyword-based filters...")
    print("-" * 60)

    created = 0
    errors = 0

    for f in filters:
        try:
            label_id = ws.get_label_id(f["label"])
            if label_id:
                ws.create_gmail_filter(
                    criteria={"subject": f["keywords"]},
                    action={"addLabelIds": [label_id]},
                )
                print(f"   Created: {f['name']} -> {f['label']}")
                created += 1
            else:
                print(f"   Label not found: {f['label']}")
                errors += 1
        except Exception as e:
            if "Filter already exists" in str(e):
                print(f"   Exists: {f['name']}")
            else:
                print(f"   Error {f['name']}: {e}")
                errors += 1

    # Auto-apply "New" status to incoming support emails
    print("\n" + "-" * 60)
    print("Creating auto-status filter...")
    print("-" * 60)

    try:
        new_label_id = ws.get_label_id("Support/Status/New")
        if new_label_id:
            ws.create_gmail_filter(
                criteria={"to": "support@a13e.com"},
                action={"addLabelIds": [new_label_id]},
            )
            print("   Created: Auto-New Status filter")
            created += 1
    except Exception as e:
        if "Filter already exists" in str(e):
            print("   Exists: Auto-New Status filter")
        else:
            print(f"   Error: {e}")
            errors += 1

    print("\n" + "=" * 60)
    print(f"Setup Complete! Created {created} filters, {errors} errors")
    print("=" * 60)


if __name__ == "__main__":
    main()
