from __future__ import annotations

from sqlalchemy import func, select

from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    model = User

    async def get_by_email(self, email: str) -> User | None:
        result = await self.session.execute(select(User).where(User.email == email.lower()))
        return result.scalar_one_or_none()

    async def email_exists(self, email: str) -> bool:
        result = await self.session.execute(select(User.id).where(User.email == email.lower()))
        return result.first() is not None

    async def list_all(self, *, limit: int = 100, offset: int = 0) -> list[User]:
        result = await self.session.execute(
            select(User).order_by(User.created_at).limit(limit).offset(offset)
        )
        return list(result.scalars().all())

    async def count_active_with_role(self, role: str) -> int:
        result = await self.session.execute(
            select(func.count())
            .select_from(User)
            .where(User.role == role, User.is_active.is_(True))
        )
        return int(result.scalar_one())
