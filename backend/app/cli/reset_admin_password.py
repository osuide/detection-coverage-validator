"""CLI script to reset an admin user's password."""

import asyncio
import sys

import bcrypt


async def reset_admin_password(email: str, new_password: str):
    """Reset an admin user's password."""
    from sqlalchemy import text
    from app.core.database import engine

    # Hash password
    password_hash = bcrypt.hashpw(
        new_password.encode(), bcrypt.gensalt(rounds=12)
    ).decode()

    async with engine.begin() as conn:
        # Check if admin exists
        result = await conn.execute(
            text("SELECT id FROM admin_users WHERE email = :email"),
            {"email": email.lower()},
        )
        existing = result.fetchone()

        if not existing:
            print(f"Admin with email {email} not found!")
            return False

        # Update password
        await conn.execute(
            text(
                """
                UPDATE admin_users
                SET password_hash = :password_hash,
                    failed_login_attempts = 0,
                    locked_until = NULL,
                    requires_password_change = false
                WHERE email = :email
            """
            ),
            {
                "email": email.lower(),
                "password_hash": password_hash,
            },
        )

        print("Password reset successfully!")
        print(f"  Email: {email}")
        return True


def main():
    if len(sys.argv) < 3:
        print("Usage: python -m app.cli.reset_admin_password <email> <new_password>")
        print(
            "Example: python -m app.cli.reset_admin_password admin@a13e.com NewSecurePass123!"
        )
        sys.exit(1)

    email = sys.argv[1]
    new_password = sys.argv[2]

    # Validate password
    if len(new_password) < 16:
        print("Error: Password must be at least 16 characters long")
        sys.exit(1)

    asyncio.run(reset_admin_password(email, new_password))


if __name__ == "__main__":
    main()
