"""CLI script to create the first super admin user."""

import asyncio
import sys
from uuid import uuid4

import bcrypt


async def create_super_admin(email: str, password: str, full_name: str = "Super Admin"):
    """Create a super admin user directly in the database."""
    from sqlalchemy import text
    from app.core.database import engine

    # Hash password
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
    admin_id = uuid4()

    async with engine.begin() as conn:
        # Check if admin already exists
        result = await conn.execute(
            text("SELECT id FROM admin_users WHERE email = :email"),
            {"email": email.lower()}
        )
        existing = result.fetchone()

        if existing:
            print(f"Admin with email {email} already exists!")
            return None

        # Insert admin
        await conn.execute(
            text("""
                INSERT INTO admin_users (
                    id, email, password_hash, role, full_name,
                    mfa_enabled, is_active, failed_login_attempts,
                    requires_password_change
                ) VALUES (
                    :id, :email, :password_hash, 'super_admin', :full_name,
                    false, true, 0, false
                )
            """),
            {
                "id": admin_id,
                "email": email.lower(),
                "password_hash": password_hash,
                "full_name": full_name,
            }
        )

        print(f"Super admin created successfully!")
        print(f"  ID: {admin_id}")
        print(f"  Email: {email}")
        print(f"  Role: super_admin")
        return admin_id


def main():
    if len(sys.argv) < 3:
        print("Usage: python -m app.cli.create_admin <email> <password> [full_name]")
        print("Example: python -m app.cli.create_admin admin@a13e.io MySecurePass123! 'Platform Admin'")
        sys.exit(1)

    email = sys.argv[1]
    password = sys.argv[2]
    full_name = sys.argv[3] if len(sys.argv) > 3 else "Super Admin"

    # Validate password
    if len(password) < 16:
        print("Error: Password must be at least 16 characters long")
        sys.exit(1)

    asyncio.run(create_super_admin(email, password, full_name))


if __name__ == "__main__":
    main()
