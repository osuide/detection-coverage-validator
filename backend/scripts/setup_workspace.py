#!/usr/bin/env python3
"""
One-time setup script for Google Workspace resources.

Creates:
- support@a13e.com collaborative inbox
- Gmail labels for ticket management
- Support CRM spreadsheet
- Drive folder structure

Run via ECS Exec or locally with service account key.
"""

import sys
import os

# Add the backend app to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.google_workspace_service import get_workspace_service


def main():
    print("=" * 60)
    print("A13E Google Workspace Setup")
    print("=" * 60)

    ws = get_workspace_service()
    print(f"\nAuthenticated as: {ws.delegated_user}")
    print(f"WIF enabled: {ws.use_wif}")

    # =========================================================================
    # 1. Create Support Group
    # =========================================================================
    print("\n" + "-" * 60)
    print("1. Creating support@a13e.com collaborative inbox...")
    print("-" * 60)

    try:
        group = ws.create_google_group(
            email="support@a13e.com",
            name="A13E Support",
            description="Customer support inbox for A13E Detection Coverage Validator",
            collaborative_inbox=True,
        )
        print(f"   Created: {group.get('email', 'support@a13e.com')}")
    except Exception as e:
        print(f"   Error: {e}")

    # =========================================================================
    # 2. Create Gmail Labels
    # =========================================================================
    print("\n" + "-" * 60)
    print("2. Creating Gmail labels for ticket management...")
    print("-" * 60)

    labels = [
        # Categories
        "Support/Category/Billing",
        "Support/Category/Technical",
        "Support/Category/Feature Request",
        "Support/Category/Bug Report",
        "Support/Category/Account",
        "Support/Category/Integration",
        # Priority
        "Support/Priority/Urgent",
        "Support/Priority/High",
        "Support/Priority/Normal",
        "Support/Priority/Low",
        # Status
        "Support/Status/New",
        "Support/Status/In Progress",
        "Support/Status/Waiting on Customer",
        "Support/Status/Escalated",
        "Support/Status/Resolved",
        "Support/Status/Closed",
        # Customer Tier
        "Support/Tier/Free",
        "Support/Tier/Individual",
        "Support/Tier/Pro",
        "Support/Tier/Enterprise",
        # Cloud Provider
        "Support/Cloud/AWS",
        "Support/Cloud/GCP",
        "Support/Cloud/Multi-Cloud",
    ]

    try:
        created = ws.create_gmail_labels(labels)
        print(f"   Created {len(created)} labels")
        for label in labels:
            print(f"   - {label}")
    except Exception as e:
        print(f"   Error: {e}")

    # =========================================================================
    # 3. Create Drive Folder Structure
    # =========================================================================
    print("\n" + "-" * 60)
    print("3. Creating Drive folder structure...")
    print("-" * 60)

    try:
        # Root folder
        root = ws.create_drive_folder("A13E Operations")
        print(f"   Created: A13E Operations ({root['id']})")

        # Support folders
        support = ws.create_drive_folder("Support", parent_id=root["id"])
        print(f"   Created: Support ({support['id']})")

        templates = ws.create_drive_folder("Templates", parent_id=support["id"])
        print(f"   Created: Support/Templates ({templates['id']})")

        runbooks = ws.create_drive_folder("Runbooks", parent_id=support["id"])
        print(f"   Created: Support/Runbooks ({runbooks['id']})")

        escalations = ws.create_drive_folder("Escalations", parent_id=support["id"])
        print(f"   Created: Support/Escalations ({escalations['id']})")

        # Sales folders
        sales = ws.create_drive_folder("Sales", parent_id=root["id"])
        print(f"   Created: Sales ({sales['id']})")

        # Engineering folders
        engineering = ws.create_drive_folder("Engineering", parent_id=root["id"])
        print(f"   Created: Engineering ({engineering['id']})")

        print(f"\n   Root folder URL: {root.get('webViewLink', 'N/A')}")

    except Exception as e:
        print(f"   Error: {e}")
        support = None

    # =========================================================================
    # 4. Create CRM Spreadsheet
    # =========================================================================
    print("\n" + "-" * 60)
    print("4. Creating Support CRM spreadsheet...")
    print("-" * 60)

    try:
        spreadsheet = ws.create_spreadsheet(
            title="A13E Support CRM",
            sheets=[
                "Tickets",
                "Customers",
                "Metrics",
                "Response Templates",
                "Escalation Log",
            ],
            folder_id=support["id"] if support else None,
        )
        spreadsheet_url = spreadsheet.get("spreadsheetUrl", "N/A")
        print("   Created: A13E Support CRM")
        print(f"   URL: {spreadsheet_url}")

        # Add headers to Tickets sheet
        ws.sheets.spreadsheets().values().update(
            spreadsheetId=spreadsheet["spreadsheetId"],
            range="Tickets!A1:L1",
            valueInputOption="USER_ENTERED",
            body={
                "values": [
                    [
                        "Ticket ID",
                        "Date",
                        "Customer Email",
                        "Customer Tier",
                        "Category",
                        "Priority",
                        "Status",
                        "Subject",
                        "Description",
                        "Cloud Provider",
                        "Assigned To",
                        "Resolution Notes",
                    ]
                ]
            },
        ).execute()
        print("   Added headers to Tickets sheet")

        # Add headers to Customers sheet
        ws.sheets.spreadsheets().values().update(
            spreadsheetId=spreadsheet["spreadsheetId"],
            range="Customers!A1:H1",
            valueInputOption="USER_ENTERED",
            body={
                "values": [
                    [
                        "Customer Email",
                        "Company",
                        "Tier",
                        "Cloud Accounts",
                        "First Contact",
                        "Last Contact",
                        "Total Tickets",
                        "Notes",
                    ]
                ]
            },
        ).execute()
        print("   Added headers to Customers sheet")

        # Add headers to Metrics sheet
        ws.sheets.spreadsheets().values().update(
            spreadsheetId=spreadsheet["spreadsheetId"],
            range="Metrics!A1:E1",
            valueInputOption="USER_ENTERED",
            body={
                "values": [
                    [
                        "Date",
                        "New Tickets",
                        "Resolved Tickets",
                        "Avg Response Time (hrs)",
                        "Customer Satisfaction",
                    ]
                ]
            },
        ).execute()
        print("   Added headers to Metrics sheet")

    except Exception as e:
        print(f"   Error: {e}")

    # =========================================================================
    # Summary
    # =========================================================================
    print("\n" + "=" * 60)
    print("Setup Complete!")
    print("=" * 60)
    print(
        """
Next steps:
1. Add team members to support@a13e.com group
2. Set up Gmail filters to auto-label incoming support emails
3. Create response templates in the Templates folder
4. Configure Apps Script for automated ticket processing (optional)

Resources created:
- support@a13e.com (collaborative inbox)
- Gmail labels for ticket management
- A13E Operations folder structure in Drive
- Support CRM spreadsheet
"""
    )


if __name__ == "__main__":
    main()
