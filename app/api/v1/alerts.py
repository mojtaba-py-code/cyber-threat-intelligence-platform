"""Alert-rule management and alert listing.

Rules are evaluated automatically whenever an indicator is created or updated
(see :meth:`IOCService.upsert`), so creating a rule here makes alerts fire.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.api.deps import CurrentPrincipalDep, get_alert_service, require
from app.schemas.alert import AlertOut, AlertRuleCreate, AlertRuleOut
from app.security.rbac import Permission
from app.services.alert_service import AlertService

router = APIRouter()

AlertDep = Annotated[AlertService, Depends(get_alert_service)]


@router.post(
    "/rules",
    response_model=AlertRuleOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require(Permission.alert_manage))],
)
async def create_rule(payload: AlertRuleCreate, service: AlertDep) -> AlertRuleOut:
    rule = await service.create_rule(
        name=payload.name,
        metric=payload.metric,
        operator=payload.operator,
        threshold=payload.threshold,
        channel=payload.channel,
        channel_config=payload.channel_config,
    )
    return AlertRuleOut.model_validate(rule)


@router.get(
    "/rules",
    response_model=list[AlertRuleOut],
    dependencies=[Depends(require(Permission.alert_read))],
)
async def list_rules(service: AlertDep) -> list[AlertRuleOut]:
    rules = await service.list_rules()
    return [AlertRuleOut.model_validate(r) for r in rules]


@router.delete(
    "/rules/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(require(Permission.alert_manage))],
)
async def delete_rule(rule_id: str, service: AlertDep, _p: CurrentPrincipalDep) -> None:
    await service.delete_rule(rule_id)


@router.get(
    "",
    response_model=list[AlertOut],
    dependencies=[Depends(require(Permission.alert_read))],
)
async def list_alerts(
    service: AlertDep,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> list[AlertOut]:
    alerts = await service.list_alerts(limit=limit, offset=offset)
    return [AlertOut.model_validate(a) for a in alerts]
