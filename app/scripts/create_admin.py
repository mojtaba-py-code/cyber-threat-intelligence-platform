"""Create or promote the first administrator.

Bootstrapping an admin has to happen outside the HTTP API — an endpoint that
mints admins is an endpoint an attacker can call. This runs against the
database directly, so it needs shell access to the deployment.

    python -m app.scripts.create_admin --email you@example.com

The password is read from ``TIP_ADMIN_PASSWORD`` if set, otherwise prompted
for without echo. It is never taken from a command-line argument, which would
put the credential in the shell history and in ``ps`` output.

If the account already exists it is promoted to ``admin`` and re-enabled, so
the same command also recovers a deployment whose last admin was locked out.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import sys

from app.database.session import get_sessionmaker
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security.crypto import get_password_hasher
from app.security.rbac import Role

MIN_PASSWORD_LENGTH = 10


def _read_password() -> str:
    password = os.environ.get("TIP_ADMIN_PASSWORD")
    if password:
        return password
    password = getpass.getpass("Password: ")
    if password != getpass.getpass("Repeat password: "):
        raise SystemExit("Passwords do not match.")
    return password


async def _create(email: str, password: str) -> str:
    hasher = get_password_hasher()
    maker = get_sessionmaker()
    async with maker() as session:
        users = UserRepository(session)
        existing = await users.get_by_email(email)
        if existing is not None:
            existing.role = Role.admin.value
            existing.is_active = True
            existing.password_hash = hasher.hash(password)
            await session.commit()
            return f"Promoted existing account {email} to admin and reset its password."
        user = User(
            email=email.lower(),
            password_hash=hasher.hash(password),
            role=Role.admin.value,
        )
        await users.add(user)
        await session.commit()
        return f"Created admin account {email}."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create or promote an admin user.")
    parser.add_argument("--email", required=True, help="Account email address.")
    args = parser.parse_args(argv)

    password = _read_password()
    if len(password) < MIN_PASSWORD_LENGTH:
        print(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters.",
            file=sys.stderr,
        )
        return 1
    print(asyncio.run(_create(args.email, password)))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
