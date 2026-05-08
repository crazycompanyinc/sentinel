from __future__ import annotations

import os
from typing import Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from sentinel.core.db import SentinelDB
from sentinel.core.models import SecurityEvent
from sentinel.detection.detector import ThreatDetector
from sentinel.investigation.investigator import IncidentInvestigator
from sentinel.response.engine import ResponseEngine


class AlertHub:
    def __init__(self) -> None:
        self.clients: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.clients.append(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.clients:
            self.clients.remove(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        for client in list(self.clients):
            try:
                await client.send_json(payload)
            except RuntimeError:
                self.disconnect(client)


def create_app(db_path: str | None = None) -> FastAPI:
    db = SentinelDB(db_path or os.environ.get("SENTINEL_DB", "sentinel.db"))
    hub = AlertHub()
    app = FastAPI(title="Sentinel SOC", version="0.1.0")

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/events")
    def events(severity: str | None = None) -> list[dict[str, Any]]:
        return [event.to_dict() for event in db.list_events(severity=severity)]

    @app.post("/events")
    async def create_event(payload: dict[str, Any]) -> dict[str, Any]:
        event = SecurityEvent(**payload)
        db.add_event(event)
        await hub.broadcast({"type": "security_event", "event": event.to_dict()})
        return event.to_dict()

    @app.post("/detect")
    async def detect(activity: dict[str, Any]) -> list[dict[str, Any]]:
        detected = ThreatDetector(db).detect_activity(activity)
        for event in detected:
            await hub.broadcast({"type": "security_event", "event": event.to_dict()})
        return [event.to_dict() for event in detected]

    @app.post("/investigate/{event_id}")
    def investigate(event_id: str) -> dict[str, Any]:
        return IncidentInvestigator(db).investigate_event(event_id).to_dict()

    @app.get("/incidents")
    def incidents() -> list[dict[str, Any]]:
        return [incident.to_dict() for incident in db.list_incidents()]

    @app.post("/respond/{incident_id}")
    def respond(incident_id: str) -> list[dict[str, Any]]:
        return [action.to_dict() for action in ResponseEngine(db).respond(incident_id)]

    @app.websocket("/ws/alerts")
    async def alerts(websocket: WebSocket) -> None:
        await hub.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            hub.disconnect(websocket)

    return app


app = create_app()

