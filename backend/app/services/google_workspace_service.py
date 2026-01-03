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

from typing import Any, Optional, Union
import time

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
        self._credentials_expiry = 0.0
        # WIF credentials expire after 1 hour, refresh after 50 mins to be safe
        self._credentials_ttl = 50 * 60  # 50 minutes in seconds

    @property
    def credentials(
        self,
    ) -> Union[oauth2_credentials.Credentials, service_account.Credentials]:
        """Get authenticated credentials with domain-wide delegation.

        Credentials are cached for 50 minutes (WIF tokens expire after 1 hour).
        """
        current_time = time.time()

        # Check if we have valid cached credentials
        if self._credentials is not None and current_time < self._credentials_expiry:
            return self._credentials

        # Get fresh credentials
        if self.use_wif:
            self._credentials = self._get_wif_credentials()
        else:
            self._credentials = self._get_service_account_credentials()

        self._credentials_expiry = current_time + self._credentials_ttl
        return self._credentials

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
    # Service Clients (rebuilt when credentials refresh)
    # =========================================================================
    # Note: We cache service clients but invalidate when credentials are refreshed.
    # This avoids the expensive build() call on every request while still ensuring
    # fresh credentials are used.

    def _get_or_build_service(self, cache_key: str, api: str, version: str) -> Resource:
        """Get a cached service client or build a new one.

        Invalidates cache when credentials are refreshed.
        """
        # Access credentials first to trigger refresh if needed
        creds = self.credentials

        # Check if we have a cached service with current credentials expiry
        if hasattr(self, f"_{cache_key}_service"):
            service, expiry = getattr(self, f"_{cache_key}_service")
            if expiry == self._credentials_expiry:
                return service

        # Build new service
        service = build(api, version, credentials=creds)
        setattr(self, f"_{cache_key}_service", (service, self._credentials_expiry))
        return service

    @property
    def gmail(self) -> Resource:
        """Gmail API client."""
        return self._get_or_build_service("gmail", "gmail", "v1")

    @property
    def drive(self) -> Resource:
        """Drive API client."""
        return self._get_or_build_service("drive", "drive", "v3")

    @property
    def sheets(self) -> Resource:
        """Sheets API client."""
        return self._get_or_build_service("sheets", "sheets", "v4")

    @property
    def docs(self) -> Resource:
        """Docs API client."""
        return self._get_or_build_service("docs", "docs", "v1")

    @property
    def calendar(self) -> Resource:
        """Calendar API client."""
        return self._get_or_build_service("calendar", "calendar", "v3")

    @property
    def forms(self) -> Resource:
        """Forms API client."""
        return self._get_or_build_service("forms", "forms", "v1")

    @property
    def admin(self) -> Resource:
        """Admin Directory API client."""
        return self._get_or_build_service("admin", "admin", "directory_v1")

    @property
    def groups_settings(self) -> Resource:
        """Groups Settings API client."""
        return self._get_or_build_service("groups_settings", "groupssettings", "v1")

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

    # =========================================================================
    # Group Member Management
    # =========================================================================

    def add_group_member(
        self,
        group_email: str,
        member_email: str,
        role: str = "MEMBER",
    ) -> dict:
        """
        Add a member to a Google Group.

        Args:
            group_email: Group email address (e.g., support@a13e.com)
            member_email: Email of the member to add
            role: Member role - MEMBER, MANAGER, or OWNER

        Returns:
            Created member object
        """
        try:
            member = (
                self.admin.members()
                .insert(
                    groupKey=group_email,
                    body={
                        "email": member_email,
                        "role": role,
                    },
                )
                .execute()
            )
            logger.info(
                "group_member_added",
                group=group_email,
                member=member_email,
                role=role,
            )
            return member
        except HttpError as e:
            if e.resp.status == 409:
                logger.info(
                    "group_member_exists",
                    group=group_email,
                    member=member_email,
                )
                return {"email": member_email, "role": role, "status": "exists"}
            raise

    def remove_group_member(
        self,
        group_email: str,
        member_email: str,
    ) -> None:
        """
        Remove a member from a Google Group.

        Args:
            group_email: Group email address
            member_email: Email of the member to remove
        """
        self.admin.members().delete(
            groupKey=group_email,
            memberKey=member_email,
        ).execute()
        logger.info(
            "group_member_removed",
            group=group_email,
            member=member_email,
        )

    def list_group_members(self, group_email: str) -> list[dict]:
        """
        List all members of a Google Group.

        Args:
            group_email: Group email address

        Returns:
            List of member objects with email, role, and status
        """
        members = []
        page_token = None

        while True:
            response = (
                self.admin.members()
                .list(
                    groupKey=group_email,
                    pageToken=page_token,
                )
                .execute()
            )

            members.extend(response.get("members", []))
            page_token = response.get("nextPageToken")

            if not page_token:
                break

        logger.debug(
            "group_members_listed",
            group=group_email,
            count=len(members),
        )
        return members

    # =========================================================================
    # Gmail Filter Management
    # =========================================================================

    def get_label_id(self, label_name: str) -> Optional[str]:
        """
        Get the ID of a Gmail label by name.

        Args:
            label_name: Label name (e.g., 'Support/Category/Billing')

        Returns:
            Label ID or None if not found
        """
        labels = self.gmail.users().labels().list(userId="me").execute()
        for label in labels.get("labels", []):
            if label.get("name") == label_name:
                return label.get("id")
        return None

    def create_gmail_filter(
        self,
        criteria: dict,
        action: dict,
    ) -> dict:
        """
        Create a Gmail filter for automated labelling.

        Args:
            criteria: Filter criteria dict with keys like:
                - from: Sender email/domain
                - to: Recipient
                - subject: Subject contains
                - query: Full search query
            action: Action dict with keys like:
                - addLabelIds: List of label IDs to add
                - removeLabelIds: List of label IDs to remove
                - forward: Email address to forward to

        Returns:
            Created filter object
        """
        filter_body = {
            "criteria": criteria,
            "action": action,
        }

        result = (
            self.gmail.users()
            .settings()
            .filters()
            .create(userId="me", body=filter_body)
            .execute()
        )

        logger.info(
            "gmail_filter_created",
            filter_id=result.get("id"),
            criteria=criteria,
        )
        return result

    def list_gmail_filters(self) -> list[dict]:
        """
        List all Gmail filters.

        Returns:
            List of filter objects
        """
        result = self.gmail.users().settings().filters().list(userId="me").execute()
        filters = result.get("filter", [])
        logger.debug("gmail_filters_listed", count=len(filters))
        return filters

    def delete_gmail_filter(self, filter_id: str) -> None:
        """
        Delete a Gmail filter.

        Args:
            filter_id: ID of the filter to delete
        """
        self.gmail.users().settings().filters().delete(
            userId="me",
            id=filter_id,
        ).execute()
        logger.info("gmail_filter_deleted", filter_id=filter_id)

    # =========================================================================
    # Sheet Reading Operations
    # =========================================================================

    def get_sheet_values(
        self,
        spreadsheet_id: str,
        range_name: str,
    ) -> list[list[Any]]:
        """
        Read values from a sheet range.

        Args:
            spreadsheet_id: Spreadsheet ID
            range_name: A1 notation range (e.g., 'Tickets!A1:L100')

        Returns:
            2D array of values
        """
        result = (
            self.sheets.spreadsheets()
            .values()
            .get(
                spreadsheetId=spreadsheet_id,
                range=range_name,
            )
            .execute()
        )

        values = result.get("values", [])
        logger.debug(
            "sheet_values_read",
            spreadsheet_id=spreadsheet_id,
            range=range_name,
            rows=len(values),
        )
        return values

    def update_sheet_values(
        self,
        spreadsheet_id: str,
        range_name: str,
        values: list[list[Any]],
    ) -> dict:
        """
        Update values in a sheet range.

        Args:
            spreadsheet_id: Spreadsheet ID
            range_name: A1 notation range
            values: 2D array of values to write

        Returns:
            Update response
        """
        result = (
            self.sheets.spreadsheets()
            .values()
            .update(
                spreadsheetId=spreadsheet_id,
                range=range_name,
                valueInputOption="USER_ENTERED",
                body={"values": values},
            )
            .execute()
        )

        logger.debug(
            "sheet_values_updated",
            spreadsheet_id=spreadsheet_id,
            range=range_name,
        )
        return result

    # =========================================================================
    # Drive File Operations
    # =========================================================================

    def list_files_in_folder(
        self,
        folder_id: str,
        mime_type: Optional[str] = None,
    ) -> list[dict]:
        """
        List files in a Drive folder.

        Args:
            folder_id: Folder ID
            mime_type: Optional MIME type filter (e.g., 'application/vnd.google-apps.document')

        Returns:
            List of file objects with id, name, mimeType, webViewLink
        """
        query = f"'{folder_id}' in parents and trashed = false"
        if mime_type:
            query += f" and mimeType = '{mime_type}'"

        files = []
        page_token = None

        while True:
            response = (
                self.drive.files()
                .list(
                    q=query,
                    fields="nextPageToken, files(id, name, mimeType, webViewLink, modifiedTime)",
                    pageToken=page_token,
                )
                .execute()
            )

            files.extend(response.get("files", []))
            page_token = response.get("nextPageToken")

            if not page_token:
                break

        logger.debug(
            "drive_files_listed",
            folder_id=folder_id,
            count=len(files),
        )
        return files

    def get_document_content(self, doc_id: str) -> str:
        """
        Get the text content of a Google Doc.

        Args:
            doc_id: Document ID

        Returns:
            Plain text content of the document
        """
        doc = self.docs.documents().get(documentId=doc_id).execute()

        # Extract text from document body
        content = []
        for element in doc.get("body", {}).get("content", []):
            if "paragraph" in element:
                for text_run in element["paragraph"].get("elements", []):
                    if "textRun" in text_run:
                        content.append(text_run["textRun"].get("content", ""))

        text = "".join(content)
        logger.debug(
            "document_content_read",
            doc_id=doc_id,
            length=len(text),
        )
        return text

    def send_email(
        self,
        to: str,
        subject: str,
        body: str,
        cc: Optional[list[str]] = None,
        reply_to: Optional[str] = None,
        from_address: Optional[str] = None,
    ) -> dict:
        """
        Send an email via Gmail API.

        Args:
            to: Recipient email address
            subject: Email subject
            body: Email body (plain text)
            cc: Optional list of CC recipients
            reply_to: Optional Reply-To address (for sending on behalf of a group)
            from_address: Optional From address (must be configured as "Send mail as" alias in Gmail)

        Returns:
            Sent message object
        """
        import base64
        from email.mime.text import MIMEText

        message = MIMEText(body)
        message["to"] = to
        message["subject"] = subject
        if from_address:
            message["from"] = from_address
        if cc:
            message["cc"] = ", ".join(cc)
        if reply_to:
            message["reply-to"] = reply_to

        raw = base64.urlsafe_b64encode(message.as_bytes()).decode()

        result = (
            self.gmail.users().messages().send(userId="me", body={"raw": raw}).execute()
        )

        logger.info(
            "email_sent",
            to=to,
            subject=subject,
            message_id=result.get("id"),
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
