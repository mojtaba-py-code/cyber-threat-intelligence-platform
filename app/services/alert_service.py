"""Alert evaluation and delivery.

Rules are evaluated against an IOC; matches create an :class:`Alert` and are
delivered through the configured channel. Delivery is offline-safe: the ``log``
channel just records, and webhook delivery is gated by the SSRF guard and the
live-collector policy so the platform never makes surprise outbound calls.
"""

from __future__ import annotations

from sqlalchemy import select

from app.config import Settings, get_settings
from app.core.events import EventBus, get_event_bus
from app.core.logging import get_logger
from app.core.ssrf import SSRFGuard
from app.models.alert import Alert, AlertRule
from app.models.ioc import IOC

log = get_logger(__name__)


class AlertService:
    def __init__(
        self, session, *, settings: Settings | None = None, events: EventBus | None = None
    ) -> None:
        self._session = session
        self._settings = settings or get_settings()
        self._ssrf = SSRFGuard(self._settings.outbound_allowed_hosts)
        self._events = events or get_event_bus()

    async def _active_rules(self) -> list[AlertRule]:
        result = await self._session.execute(select(AlertRule).where(AlertRule.is_active.is_(True)))
        return list(result.scalars().all())

    @staticmethod
    def _matches(rule: AlertRule, ioc: IOC) -> bool:
        if rule.metric == "new_ioc":
            return True
        if rule.metric != "threat_score":
            return False
        value = ioc.threat_score
        if rule.operator == "gte":
            return value >= rule.threshold
        if rule.operator == "lte":
            return value <= rule.threshold
        return value == rule.threshold

    async def evaluate_ioc(self, ioc: IOC) -> list[Alert]:
        """Create (and deliver) alerts for every rule an IOC matches."""
        created: list[Alert] = []
        for rule in await self._active_rules():
            if not self._matches(rule, ioc):
                continue
            alert = Alert(
                rule_id=rule.id,
                ioc_id=ioc.id,
                severity=ioc.severity,
                title=f"{rule.name}: {ioc.defanged_value}",
                message=(
                    f"IOC {ioc.defanged_value} ({ioc.type}) scored {ioc.threat_score} "
                    f"[{ioc.threat_level}] from source {ioc.source}."
                ),
            )
            self._session.add(alert)
            await self._session.flush()
            await self._deliver(rule, alert)
            await self._publish(alert, ioc)
            created.append(alert)
        return created

    async def _publish(self, alert: Alert, ioc: IOC) -> None:
        """Push the alert to live subscribers (never blocks, never raises)."""
        await self._events.publish(
            "alert",
            {
                "id": alert.id,
                "title": alert.title,
                "message": alert.message,
                "severity": alert.severity,
                "ioc": ioc.defanged_value,
                "ioc_type": ioc.type,
                "threat_score": ioc.threat_score,
                "threat_level": ioc.threat_level,
            },
        )

    async def _deliver(self, rule: AlertRule, alert: Alert) -> None:
        if rule.channel == "log":
            log.info("alert", title=alert.title, severity=alert.severity)
            alert.delivered = True
            return
        if rule.channel in {"webhook", "slack", "discord"}:
            url = rule.channel_config.get("url")
            if not url or not self._settings.enable_live_collectors:
                # Offline / no URL: record but do not attempt an outbound call.
                alert.delivered = False
                return
            try:
                import httpx

                await self._ssrf.validate(url)
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(url, json={"text": alert.title, "message": alert.message})
                alert.delivered = True
            except Exception as exc:  # noqa: BLE001 - delivery failure is non-fatal
                log.warning("alert_delivery_failed", channel=rule.channel, error=str(exc))
                alert.delivered = False

    # -- rule / alert management -------------------------------------------
    async def create_rule(
        self,
        *,
        name: str,
        metric: str,
        operator: str,
        threshold: int,
        channel: str,
        channel_config: dict | None = None,
    ) -> AlertRule:
        rule = AlertRule(
            name=name,
            metric=metric,
            operator=operator,
            threshold=threshold,
            channel=channel,
            channel_config=channel_config or {},
        )
        self._session.add(rule)
        await self._session.flush()
        return rule

    async def list_rules(self) -> list[AlertRule]:
        result = await self._session.execute(select(AlertRule).order_by(AlertRule.created_at))
        return list(result.scalars().all())

    async def delete_rule(self, rule_id: str) -> bool:
        rule = await self._session.get(AlertRule, rule_id)
        if rule is None:
            return False
        await self._session.delete(rule)
        await self._session.flush()
        return True

    async def list_alerts(self, *, limit: int = 50, offset: int = 0) -> list[Alert]:
        result = await self._session.execute(
            select(Alert).order_by(Alert.created_at.desc()).limit(limit).offset(offset)
        )
        return list(result.scalars().all())
