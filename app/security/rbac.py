"""Role-based access control for the threat platform.

Roles map to sets of fine-grained permissions; endpoints check permissions, not
roles, so the mapping can evolve without touching handlers.
"""

from __future__ import annotations

from enum import StrEnum


class Role(StrEnum):
    admin = "admin"
    analyst = "analyst"
    viewer = "viewer"


class Permission(StrEnum):
    ioc_read = "ioc:read"
    ioc_write = "ioc:write"
    enrich_run = "enrich:run"
    collector_run = "collector:run"
    alert_read = "alert:read"
    alert_manage = "alert:manage"
    report_generate = "report:generate"
    admin_manage = "admin:manage"


_VIEWER: frozenset[Permission] = frozenset({Permission.ioc_read, Permission.alert_read})
_ANALYST: frozenset[Permission] = _VIEWER | frozenset(
    {
        Permission.ioc_write,
        Permission.enrich_run,
        Permission.collector_run,
        Permission.report_generate,
        Permission.alert_manage,
    }
)
_ADMIN: frozenset[Permission] = _ANALYST | frozenset({Permission.admin_manage})

ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.viewer: _VIEWER,
    Role.analyst: _ANALYST,
    Role.admin: _ADMIN,
}


def permissions_for(role: Role | str) -> frozenset[Permission]:
    try:
        role_enum = Role(role)
    except ValueError:
        return frozenset()
    return ROLE_PERMISSIONS.get(role_enum, frozenset())


def has_permission(role: Role | str, permission: Permission) -> bool:
    return permission in permissions_for(role)
