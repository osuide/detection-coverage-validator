#!/usr/bin/env python3
"""
Check for duplicate Google Workspace resources.

Run via ECS Exec to find and clean up duplicate resources from
failed deployment attempts.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.google_workspace_service import get_workspace_service


def main():
    print("=" * 60)
    print("Checking for Duplicate Workspace Resources")
    print("=" * 60)

    ws = get_workspace_service()
    print(f"\nAuthenticated as: {ws.delegated_user}")

    # Check Drive folders
    print("\n" + "-" * 60)
    print("1. Checking Drive folders...")
    print("-" * 60)

    results = (
        ws.drive.files()
        .list(
            q="name = 'A13E Operations' and mimeType = 'application/vnd.google-apps.folder' and trashed = false",
            fields="files(id, name, createdTime, webViewLink)",
        )
        .execute()
    )

    folders = results.get("files", [])
    print(f"Found {len(folders)} 'A13E Operations' folders:")
    for f in folders:
        print(f"  - ID: {f['id']}")
        print(f"    Created: {f.get('createdTime', 'unknown')}")
        print(f"    Link: {f.get('webViewLink', 'N/A')}")

    # Check spreadsheets
    print("\n" + "-" * 60)
    print("2. Checking Support CRM spreadsheets...")
    print("-" * 60)

    results = (
        ws.drive.files()
        .list(
            q="name contains 'Support CRM' and mimeType = 'application/vnd.google-apps.spreadsheet' and trashed = false",
            fields="files(id, name, createdTime, webViewLink)",
        )
        .execute()
    )

    sheets = results.get("files", [])
    print(f"Found {len(sheets)} Support CRM spreadsheets:")
    for s in sheets:
        print(f"  - ID: {s['id']}")
        print(f"    Name: {s['name']}")
        print(f"    Created: {s.get('createdTime', 'unknown')}")
        print(f"    Link: {s.get('webViewLink', 'N/A')}")

    # Check Gmail filters
    print("\n" + "-" * 60)
    print("3. Checking Gmail filters...")
    print("-" * 60)

    filters = ws.list_gmail_filters()
    print(f"Found {len(filters)} Gmail filters:")
    for f in filters:
        criteria = f.get("criteria", {})
        action = f.get("action", {})
        print(f"  - ID: {f.get('id')}")
        print(f"    Criteria: {criteria}")
        print(f"    Action: {action}")

    # Check Gmail labels
    print("\n" + "-" * 60)
    print("4. Checking Support Gmail labels...")
    print("-" * 60)

    labels_result = ws.gmail.users().labels().list(userId="me").execute()
    support_labels = [
        label
        for label in labels_result.get("labels", [])
        if label.get("name", "").startswith("Support/")
    ]
    print(f"Found {len(support_labels)} Support labels:")
    for label in support_labels:
        print(f"  - {label.get('name')} (ID: {label.get('id')})")

    print("\n" + "=" * 60)
    print("Check Complete!")
    print("=" * 60)
    print(
        """
To clean up duplicates:
1. Keep the oldest/most complete resource
2. Manually delete duplicates in Google Drive
3. Delete duplicate filters via: ws.delete_gmail_filter(filter_id)
"""
    )


if __name__ == "__main__":
    main()
