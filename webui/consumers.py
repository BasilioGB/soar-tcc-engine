from __future__ import annotations

from asgiref.sync import sync_to_async
from channels.generic.websocket import AsyncJsonWebsocketConsumer
from django.contrib.auth import get_user_model

from incidents.models import Incident

User = get_user_model()


class IncidentConsumer(AsyncJsonWebsocketConsumer):
    incident_id: int

    async def connect(self) -> None:
        incident_id = self.scope["url_route"]["kwargs"].get("incident_id")
        try:
            self.incident_id = int(incident_id)
        except (TypeError, ValueError):
            await self.close(code=4000)
            return
        if not await self._can_access_incident():
            await self.close(code=4003)
            return
        await self.channel_layer.group_add(self._group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code: int) -> None:  # noqa: D401 - channel interface
        await self.channel_layer.group_discard(self._group_name, self.channel_name)

    async def receive_json(self, content, **kwargs) -> None:  # pragma: no cover - currently unused
        # The UI is read-only for now. Future interactive features can be handled here.
        return

    async def incident_message(self, event: dict) -> None:
        await self.send_json(
            {
                "type": "incident.update",
                "sections": event.get("sections", []),
                "payload": event.get("payload", {}),
            }
        )

    @property
    def _group_name(self) -> str:
        return f"incident_{self.incident_id}"

    async def _can_access_incident(self) -> bool:
        user: User = self.scope.get("user")  # type: ignore[assignment]
        if not user or not user.is_authenticated:
            return False
        return await sync_to_async(Incident.objects.filter(pk=self.incident_id).exists)()


class NotifyConsumer(AsyncJsonWebsocketConsumer):
    group_name = "notify"

    async def connect(self) -> None:
        user: User = self.scope.get("user")  # type: ignore[assignment]
        if not user or not user.is_authenticated:
            await self.close(code=4001)
            return
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, code: int) -> None:  # noqa: D401
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def notify_message(self, event: dict) -> None:
        await self.send_json(
            {
                "type": "notify",
                "kind": event.get("kind", "info"),
                "payload": event.get("payload", {}),
            }
        )
