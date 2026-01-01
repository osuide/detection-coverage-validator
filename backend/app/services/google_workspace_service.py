"""
Google Workspace Service - WIF Authentication

This service provides access to Google Workspace APIs (Gmail, Drive, Sheets, etc.)
using Workload Identity Federation (WIF) for authentication.

Architecture:
    AWS ECS Task → IAM Role → WIF → GCP Service Account → Workspace APIs

The implementation handles two challenges:
1. ECS Fargate doesn't work with standard WIF credential_source (uses different metadata)
2. Domain-wide delegation requires a `sub` claim which WIF doesn't natively support

Solution: Custom AwsSecurityCredentialsSupplier + JWT signing for domain delegation.

No service account keys required in production - uses short-lived credentials.
"""

from functools import cached_property
from typing import Any, Optional, Union

import structlog
from google.oauth2 import credentials as oauth2_credentials
from google.oauth2 import service_account
from googleapiclient.discovery import build, Resource
from googleapiclient.errors import HttpError

from app.core.config import get_settings
from app.services.ecs_wif_credentials import get_wif_delegated_credentials

logger = structlog.get_logger()
settings = get_settings()


class GoogleWorkspaceService:
    """
    Service for accessing Google Workspace APIs via WIF.

    Supports:
    - Gmail API (labels, messages, drafts)
    - Drive API (files, folders)
    - Sheets API (spreadsheets)
    - Docs API (documents)
    - Calendar API (events)
    - Forms API (forms)
    - Admin Directory API (groups, users)

    Usage:
        service = GoogleWorkspaceService()

        # Gmail
        labels = service.gmail.users().labels().list(userId='me').execute()

        # Sheets
        sheet = service.sheets.spreadsheets().get(spreadsheetId='xxx').execute()
    """

    # OAuth scopes for Workspace APIs
    SCOPES = [
        # Admin Directory (Groups, Users)
        "https://www.googleapis.com/auth/admin.directory.group",
        "https://www.googleapis.com/auth/admin.directory.group.member",
        "https://www.googleapis.com/auth/admin.directory.user.readonly",
        # Gmail
        "https://www.googleapis.com/auth/gmail.labels",
        "https://www.googleapis.com/auth/gmail.settings.basic",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/gmail.send",
        # Drive
        "https://www.googleapis.com/auth/drive",
        # Sheets
        "https://www.googleapis.com/auth/spreadsheets",
        # Docs
        "https://www.googleapis.com/auth/documents",
        # Calendar
        "https://www.googleapis.com/auth/calendar",
        # Forms
        "https://www.googleapis.com/auth/forms",
        # Groups Settings
        "https://www.googleapis.com/auth/apps.groups.settings",
    ]

    def __init__(
        self,
        delegated_user: Optional[str] = None,
        use_wif: bool = True,
    ):
        """
        Initialise the Workspace service.

        Args:
            delegated_user: Email of user to impersonate (for domain-wide delegation).
                           Defaults to settings.workspace_admin_email.
            use_wif: If True, use Workload Identity Federation.
                    If False, fall back to service account key (for local dev).
        """
        self.delegated_user = delegated_user or settings.workspace_admin_email
        self.use_wif = use_wif and settings.workspace_wif_enabled
        self._credentials = None

    @cached_property
    def credentials(
        self,
    ) -> Union[oauth2_credentials.Credentials, service_account.Credentials]:
        """Get authenticated credentials with domain-wide delegation."""
        if self.use_wif:
            return self._get_wif_credentials()
        else:
            return self._get_service_account_credentials()

    def _get_wif_credentials(self) -> oauth2_credentials.Credentials:
        """
        Get credentials via Workload Identity Federation with domain-wide delegation.

        This uses a custom implementation that:
        1. Gets AWS credentials via boto3 (works on ECS Fargate)
        2. Federates to GCP via WIF
        3. Impersonates the target service account
        4. Signs a JWT with `sub` claim for domain-wide delegation
        5. Exchanges the JWT for an access token

        Returns:
            Credentials that can be used with Google Workspace APIs
        """
        try:
            # Validate required settings
            if not settings.workspace_gcp_project_number:
                raise ValueError(
                    "WORKSPACE_GCP_PROJECT_NUMBER must be set for WIF authentication"
                )
            if not settings.workspace_service_account_email:
                raise ValueError(
                    "WORKSPACE_SERVICE_ACCOUNT_EMAIL must be set for WIF authentication"
                )

            credentials = get_wif_delegated_credentials(
                gcp_project_number=settings.workspace_gcp_project_number,
                wif_pool_id=settings.workspace_wif_pool_id,
                wif_provider_id=settings.workspace_wif_provider_id,
                service_account_email=settings.workspace_service_account_email,
                scopes=self.SCOPES,
                delegated_user=self.delegated_user,
            )

            logger.info(
                "workspace_wif_credentials_created",
                delegated_user=self.delegated_user,
                pool_id=settings.workspace_wif_pool_id,
                provider_id=settings.workspace_wif_provider_id,
            )

            return credentials

        except Exception as e:
            logger.error(
                "workspace_wif_credentials_failed",
                error=str(e),
                pool_id=settings.workspace_wif_pool_id,
            )
            raise

    def _get_service_account_credentials(self) -> service_account.Credentials:
        """
        Fallback: Get credentials from service account key file.

        Only for local development - production should use WIF.
        """
        if not settings.workspace_service_account_key_path:
            raise ValueError(
                "WIF disabled but no service account key path configured. "
                "Set WORKSPACE_SERVICE_ACCOUNT_KEY_PATH for local development."
            )

        credentials = service_account.Credentials.from_service_account_file(
            settings.workspace_service_account_key_path,
            scopes=self.SCOPES,
            subject=self.delegated_user,
        )

        logger.info(
            "workspace_service_account_credentials_created",
            delegated_user=self.delegated_user,
            key_path=settings.workspace_service_account_key_path,
        )

        return credentials

    # =========================================================================
    # Service Clients (lazy-loaded)
    # =========================================================================

    @cached_property
    def gmail(self) -> Resource:
        """Gmail API client."""
        return build("gmail", "v1", credentials=self.credentials)

    @cached_property
    def drive(self) -> Resource:
        """Drive API client."""
        return build("drive", "v3", credentials=self.credentials)

    @cached_property
    def sheets(self) -> Resource:
        """Sheets API client."""
        return build("sheets", "v4", credentials=self.credentials)

    @cached_property
    def docs(self) -> Resource:
        """Docs API client."""
        return build("docs", "v1", credentials=self.credentials)

    @cached_property
    def calendar(self) -> Resource:
        """Calendar API client."""
        return build("calendar", "v3", credentials=self.credentials)

    @cached_property
    def forms(self) -> Resource:
        """Forms API client."""
        return build("forms", "v1", credentials=self.credentials)

    @cached_property
    def admin(self) -> Resource:
        """Admin Directory API client."""
        return build("admin", "directory_v1", credentials=self.credentials)

    @cached_property
    def groups_settings(self) -> Resource:
        """Groups Settings API client."""
        return build("groupssettings", "v1", credentials=self.credentials)

    # =========================================================================
    # High-Level Methods
    # =========================================================================

    def create_gmail_labels(self, labels: list[str]) -> list[dict]:
        """
        Create Gmail labels.

        Args:
            labels: List of label names (can include nested like 'Support/Category/Billing')

        Returns:
            List of created label objects
        """
        created = []
        for label_name in labels:
            try:
                label = (
                    self.gmail.users()
                    .labels()
                    .create(
                        userId="me",
                        body={
                            "name": label_name,
                            "labelListVisibility": "labelShow",
                            "messageListVisibility": "show",
                        },
                    )
                    .execute()
                )
                created.append(label)
                logger.info("gmail_label_created", label=label_name)
            except HttpError as e:
                if e.resp.status == 409:
                    logger.info("gmail_label_exists", label=label_name)
                else:
                    logger.error("gmail_label_error", label=label_name, error=str(e))
        return created

    def create_spreadsheet(
        self,
        title: str,
        sheets: list[str],
        folder_id: Optional[str] = None,
    ) -> dict:
        """
        Create a Google Sheets spreadsheet.

        Args:
            title: Spreadsheet title
            sheets: List of sheet names
            folder_id: Optional Drive folder ID to move spreadsheet to

        Returns:
            Created spreadsheet object
        """
        spreadsheet = {
            "properties": {"title": title},
            "sheets": [{"properties": {"title": name}} for name in sheets],
        }

        result = self.sheets.spreadsheets().create(body=spreadsheet).execute()

        if folder_id:
            # Move to folder
            self.drive.files().update(
                fileId=result["spreadsheetId"],
                addParents=folder_id,
                removeParents="root",
            ).execute()

        logger.info(
            "spreadsheet_created",
            title=title,
            spreadsheet_id=result["spreadsheetId"],
        )

        return result

    def create_drive_folder(
        self,
        name: str,
        parent_id: Optional[str] = None,
    ) -> dict:
        """
        Create a Drive folder.

        Args:
            name: Folder name
            parent_id: Optional parent folder ID

        Returns:
            Created folder object
        """
        file_metadata = {
            "name": name,
            "mimeType": "application/vnd.google-apps.folder",
        }
        if parent_id:
            file_metadata["parents"] = [parent_id]

        folder = (
            self.drive.files()
            .create(
                body=file_metadata,
                fields="id, name, webViewLink",
            )
            .execute()
        )

        logger.info("drive_folder_created", name=name, folder_id=folder["id"])

        return folder

    def create_google_group(
        self,
        email: str,
        name: str,
        description: str = "",
        collaborative_inbox: bool = True,
    ) -> dict:
        """
        Create a Google Group.

        Args:
            email: Group email address
            name: Group display name
            description: Group description
            collaborative_inbox: Enable collaborative inbox features

        Returns:
            Created group object
        """
        group_config = {
            "email": email,
            "name": name,
            "description": description,
        }

        try:
            group = self.admin.groups().insert(body=group_config).execute()
            logger.info("google_group_created", email=email)

            if collaborative_inbox:
                # Configure as collaborative inbox
                settings = {
                    "whoCanPostMessage": "ANYONE_CAN_POST",
                    "whoCanViewGroup": "ALL_MEMBERS_CAN_VIEW",
                    "whoCanViewMembership": "ALL_MEMBERS_CAN_VIEW",
                    "allowExternalMembers": "false",
                    "whoCanJoin": "INVITED_CAN_JOIN",
                    "messageModerationLevel": "MODERATE_NONE",
                    "isArchived": "false",
                    "enableCollaborativeInbox": "true",
                }
                self.groups_settings.groups().update(
                    groupUniqueId=email,
                    body=settings,
                ).execute()
                logger.info("google_group_configured_collaborative", email=email)

            return group

        except HttpError as e:
            if e.resp.status == 409:
                logger.info("google_group_exists", email=email)
                return self.admin.groups().get(groupKey=email).execute()
            raise

    def append_to_sheet(
        self,
        spreadsheet_id: str,
        sheet_name: str,
        values: list[list[Any]],
    ) -> dict:
        """
        Append rows to a sheet.

        Args:
            spreadsheet_id: Spreadsheet ID
            sheet_name: Sheet name
            values: 2D array of values to append

        Returns:
            Update response
        """
        result = (
            self.sheets.spreadsheets()
            .values()
            .append(
                spreadsheetId=spreadsheet_id,
                range=f"{sheet_name}!A1",
                valueInputOption="USER_ENTERED",
                insertDataOption="INSERT_ROWS",
                body={"values": values},
            )
            .execute()
        )

        logger.debug(
            "sheet_rows_appended",
            spreadsheet_id=spreadsheet_id,
            sheet=sheet_name,
            rows=len(values),
        )

        return result


# Singleton instance
_workspace_service: Optional[GoogleWorkspaceService] = None


def get_workspace_service() -> GoogleWorkspaceService:
    """Get the singleton Workspace service instance."""
    global _workspace_service
    if _workspace_service is None:
        _workspace_service = GoogleWorkspaceService()
    return _workspace_service
