"""User administration.

The `admin` role exists so that someone can hand out and take away access
without editing the database by hand. These are the only endpoints that read or
write another user's record, and every one of them is gated on
``admin:manage`` — the permission no other route requires.

Bootstrapping is deliberately outside the API: the first admin is minted with
``python -m app.scripts.create_admin``, so a fresh deployment never has a
self-service path to privilege.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentPrincipalDep, get_auth_service, require
from app.schemas.auth import UserActiveUpdate, UserOut, UserRoleUpdate
from app.security.rbac import Permission
from app.services.auth_service import AuthService

router = APIRouter()

AuthDep = Annotated[AuthService, Depends(get_auth_service)]


@router.get(
    "/users",
    response_model=list[UserOut],
    dependencies=[Depends(require(Permission.admin_manage))],
    summary="List user accounts",
)
async def list_users(
    service: AuthDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> list[UserOut]:
    users = await service.list_users(limit=limit, offset=offset)
    return [UserOut.model_validate(u) for u in users]


@router.get(
    "/users/{user_id}",
    response_model=UserOut,
    dependencies=[Depends(require(Permission.admin_manage))],
    summary="Fetch one user account",
)
async def get_user(user_id: str, service: AuthDep) -> UserOut:
    return UserOut.model_validate(await service.get_user(user_id))


@router.patch(
    "/users/{user_id}/role",
    response_model=UserOut,
    dependencies=[Depends(require(Permission.admin_manage))],
    summary="Change a user's role",
)
async def set_user_role(
    user_id: str,
    payload: UserRoleUpdate,
    principal: CurrentPrincipalDep,
    service: AuthDep,
) -> UserOut:
    user = await service.set_user_role(actor_id=principal.id, user_id=user_id, role=payload.role)
    return UserOut.model_validate(user)


@router.patch(
    "/users/{user_id}/active",
    response_model=UserOut,
    dependencies=[Depends(require(Permission.admin_manage))],
    summary="Enable or disable a user account",
)
async def set_user_active(
    user_id: str,
    payload: UserActiveUpdate,
    principal: CurrentPrincipalDep,
    service: AuthDep,
) -> UserOut:
    user = await service.set_user_active(
        actor_id=principal.id, user_id=user_id, is_active=payload.is_active
    )
    return UserOut.model_validate(user)
