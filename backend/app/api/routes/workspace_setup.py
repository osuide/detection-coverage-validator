"""
Google Workspace Setup API endpoint.

One-time setup endpoint to create Workspace resources.
Requires admin authentication.
"""

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.core.security import require_role
from app.models.user import User, UserRole
from app.services.google_workspace_service import get_workspace_service

router = APIRouter()


class SetupResult(BaseModel):
    """Result of workspace setup."""

    success: bool
    message: str
    resources_created: dict


@router.post("/workspace/setup", response_model=SetupResult)
async def setup_workspace(
    current_user: User = Depends(require_role(UserRole.OWNER, UserRole.ADMIN)),
) -> SetupResult:
    """
    Run one-time Google Workspace setup.

    Creates:
    - support@a13e.com collaborative inbox
    - Gmail labels for ticket management
    - Support CRM spreadsheet
    - Drive folder structure

    Requires OWNER or ADMIN role.
    """
    results = {
        "group": None,
        "labels": [],
        "folders": {},
        "spreadsheet": None,
    }
    errors = []

    try:
        ws = get_workspace_service()

        # 1. Create Support Group
        try:
            group = ws.create_google_group(
                email="support@a13e.com",
                name="A13E Support",
                description="Customer support inbox for A13E Detection Coverage Validator",
                collaborative_inbox=True,
            )
            results["group"] = group.get("email", "support@a13e.com")
        except Exception as e:
            errors.append(f"Group creation: {e}")

        # 2. Create Gmail Labels
        labels = [
            "Support/Category/Billing",
            "Support/Category/Technical",
            "Support/Category/Feature Request",
            "Support/Category/Bug Report",
            "Support/Category/Account",
            "Support/Category/Integration",
            "Support/Priority/Urgent",
            "Support/Priority/High",
            "Support/Priority/Normal",
            "Support/Priority/Low",
            "Support/Status/New",
            "Support/Status/In Progress",
            "Support/Status/Waiting on Customer",
            "Support/Status/Escalated",
            "Support/Status/Resolved",
            "Support/Status/Closed",
            "Support/Tier/Free",
            "Support/Tier/Individual",
            "Support/Tier/Pro",
            "Support/Tier/Enterprise",
            "Support/Cloud/AWS",
            "Support/Cloud/GCP",
            "Support/Cloud/Multi-Cloud",
        ]

        try:
            created_labels = ws.create_gmail_labels(labels)
            results["labels"] = [label.get("name") for label in created_labels]
        except Exception as e:
            errors.append(f"Label creation: {e}")

        # 3. Create Drive Folder Structure
        try:
            root = ws.create_drive_folder("A13E Operations")
            results["folders"]["root"] = root.get("webViewLink")

            support = ws.create_drive_folder("Support", parent_id=root["id"])
            ws.create_drive_folder("Templates", parent_id=support["id"])
            ws.create_drive_folder("Runbooks", parent_id=support["id"])
            ws.create_drive_folder("Escalations", parent_id=support["id"])

            ws.create_drive_folder("Sales", parent_id=root["id"])
            ws.create_drive_folder("Engineering", parent_id=root["id"])

            results["folders"]["support_id"] = support["id"]
        except Exception as e:
            errors.append(f"Folder creation: {e}")

        # 4. Create CRM Spreadsheet
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
                folder_id=results["folders"].get("support_id"),
            )
            results["spreadsheet"] = spreadsheet.get("spreadsheetUrl")

            # Add headers
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

        except Exception as e:
            errors.append(f"Spreadsheet creation: {e}")

        if errors:
            return SetupResult(
                success=False,
                message=f"Partial success with errors: {'; '.join(errors)}",
                resources_created=results,
            )

        return SetupResult(
            success=True,
            message="Workspace setup completed successfully",
            resources_created=results,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Setup failed: {e}")


@router.get("/workspace/test")
async def test_workspace_connection() -> dict:
    """
    Test Google Workspace WIF connection.

    Returns connection status and basic info.
    No authentication required (for health checks).
    """
    try:
        ws = get_workspace_service()

        # Test Gmail API
        labels = ws.gmail.users().labels().list(userId="me").execute()
        label_count = len(labels.get("labels", []))

        return {
            "status": "connected",
            "wif_enabled": ws.use_wif,
            "delegated_user": ws.delegated_user,
            "gmail_labels": label_count,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
        }
