"""CLI script to setup MFA for an admin user.

This bypasses the web UI authentication to solve the chicken-and-egg problem:
- Can't login without MFA in staging/production
- Can't setup MFA without logging in

Usage:
    python -m app.cli.setup_admin_mfa <email>
    python -m app.cli.setup_admin_mfa <email> --verify <code>
"""

import asyncio
import sys

import pyotp
from cryptography.fernet import Fernet


async def get_admin_by_email(email: str):
    """Get admin user by email."""
    from sqlalchemy import text
    from app.core.database import engine

    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                """
                SELECT id, email, full_name, mfa_enabled, mfa_secret_encrypted
                FROM admin_users
                WHERE email = :email
                """
            ),
            {"email": email.lower()},
        )
        row = result.fetchone()
        if row:
            return {
                "id": row[0],
                "email": row[1],
                "full_name": row[2],
                "mfa_enabled": row[3],
                "mfa_secret_encrypted": row[4],
            }
        return None


def get_encryption_key():
    """Get the credential encryption key."""
    from app.core.config import get_settings

    settings = get_settings()
    key = settings.credential_encryption_key
    if not key:
        return None
    try:
        key_value = key.get_secret_value()
        Fernet(key_value.encode())  # Validate
        return key_value.encode()
    except Exception:
        return None


def encrypt_secret(secret: str) -> bytes:
    """Encrypt MFA secret."""
    key = get_encryption_key()
    if not key:
        print("Warning: No encryption key configured - storing secret unencrypted")
        return secret.encode()
    fernet = Fernet(key)
    return fernet.encrypt(secret.encode())


def decrypt_secret(encrypted: bytes) -> str:
    """Decrypt MFA secret."""
    key = get_encryption_key()
    if not key:
        return encrypted.decode()
    try:
        fernet = Fernet(key)
        return fernet.decrypt(encrypted).decode()
    except Exception:
        return encrypted.decode()


async def setup_mfa(email: str):
    """Generate MFA secret and provisioning URI for an admin."""
    from sqlalchemy import text
    from app.core.database import engine

    admin = await get_admin_by_email(email)
    if not admin:
        print(f"Error: Admin with email '{email}' not found")
        return None

    if admin["mfa_enabled"]:
        print(f"Warning: MFA is already enabled for {email}")
        print("Use --disable first if you want to reset MFA")
        return None

    # Generate new TOTP secret
    secret = pyotp.random_base32()
    encrypted_secret = encrypt_secret(secret)

    # Store encrypted secret
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                UPDATE admin_users
                SET mfa_secret_encrypted = :secret
                WHERE email = :email
                """
            ),
            {"secret": encrypted_secret, "email": email.lower()},
        )

    # Generate provisioning URI
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="A13E Admin")

    print("\n" + "=" * 60)
    print("MFA Setup for Admin Account")
    print("=" * 60)
    print(f"\nEmail: {email}")
    print(f"Name: {admin['full_name']}")
    print("\n" + "-" * 60)
    print("STEP 1: Scan this QR code with your authenticator app")
    print("-" * 60)
    print(f"\nProvisioning URI:\n{provisioning_uri}")
    print(f"\nManual entry secret: {secret}")
    print("\n" + "-" * 60)
    print("STEP 2: Verify and enable MFA")
    print("-" * 60)
    print("\nRun this command with a code from your authenticator:")
    print(f"  python -m app.cli.setup_admin_mfa {email} --verify <6-digit-code>")
    print("\n" + "=" * 60)

    return secret


async def verify_and_enable_mfa(email: str, totp_code: str):
    """Verify TOTP code and enable MFA."""
    from sqlalchemy import text
    from app.core.database import engine

    admin = await get_admin_by_email(email)
    if not admin:
        print(f"Error: Admin with email '{email}' not found")
        return False

    if admin["mfa_enabled"]:
        print(f"MFA is already enabled for {email}")
        return True

    if not admin["mfa_secret_encrypted"]:
        print(f"Error: No MFA secret found for {email}")
        print(f"Run: python -m app.cli.setup_admin_mfa {email}")
        return False

    # Decrypt and verify
    secret = decrypt_secret(admin["mfa_secret_encrypted"])
    totp = pyotp.TOTP(secret)

    if not totp.verify(totp_code, valid_window=1):
        print("Error: Invalid TOTP code")
        print("Make sure you're using the correct authenticator entry")
        return False

    # Enable MFA
    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                UPDATE admin_users
                SET mfa_enabled = true
                WHERE email = :email
                """
            ),
            {"email": email.lower()},
        )

    print("\n" + "=" * 60)
    print("SUCCESS: MFA Enabled!")
    print("=" * 60)
    print(f"\nAdmin: {email}")
    print("You can now login to the admin portal with MFA.")
    print("\n" + "=" * 60)

    return True


async def disable_mfa(email: str):
    """Disable MFA for an admin (for resetting)."""
    from sqlalchemy import text
    from app.core.database import engine

    admin = await get_admin_by_email(email)
    if not admin:
        print(f"Error: Admin with email '{email}' not found")
        return False

    async with engine.begin() as conn:
        await conn.execute(
            text(
                """
                UPDATE admin_users
                SET mfa_enabled = false, mfa_secret_encrypted = NULL
                WHERE email = :email
                """
            ),
            {"email": email.lower()},
        )

    print(f"MFA disabled for {email}")
    print(f"Run: python -m app.cli.setup_admin_mfa {email}")
    return True


async def list_admins():
    """List all admin users."""
    from sqlalchemy import text
    from app.core.database import engine

    async with engine.begin() as conn:
        result = await conn.execute(
            text(
                """
                SELECT email, full_name, role, mfa_enabled, is_active
                FROM admin_users
                ORDER BY email
                """
            )
        )
        rows = result.fetchall()

    if not rows:
        print("No admin users found")
        return

    print("\n" + "=" * 80)
    print("Admin Users")
    print("=" * 80)
    print(f"{'Email':<35} {'Name':<20} {'Role':<12} {'MFA':<6} {'Active':<6}")
    print("-" * 80)
    for row in rows:
        email, name, role, mfa, active = row
        mfa_status = "Yes" if mfa else "No"
        active_status = "Yes" if active else "No"
        print(
            f"{email:<35} {name or '-':<20} {role:<12} {mfa_status:<6} {active_status:<6}"
        )
    print("=" * 80)


def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python -m app.cli.setup_admin_mfa <email>           # Setup MFA")
        print(
            "  python -m app.cli.setup_admin_mfa <email> --verify <code>  # Verify & enable"
        )
        print("  python -m app.cli.setup_admin_mfa <email> --disable  # Disable MFA")
        print("  python -m app.cli.setup_admin_mfa --list            # List admins")
        sys.exit(1)

    if sys.argv[1] == "--list":
        asyncio.run(list_admins())
        return

    email = sys.argv[1]

    if len(sys.argv) >= 3 and sys.argv[2] == "--verify":
        if len(sys.argv) < 4:
            print("Error: Missing TOTP code")
            print(f"Usage: python -m app.cli.setup_admin_mfa {email} --verify <code>")
            sys.exit(1)
        code = sys.argv[3]
        success = asyncio.run(verify_and_enable_mfa(email, code))
        sys.exit(0 if success else 1)

    if len(sys.argv) >= 3 and sys.argv[2] == "--disable":
        success = asyncio.run(disable_mfa(email))
        sys.exit(0 if success else 1)

    asyncio.run(setup_mfa(email))


if __name__ == "__main__":
    main()
