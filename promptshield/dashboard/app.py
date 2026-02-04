"""Minimal dashboard for audit log events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

try:
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse, JSONResponse
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError(
        "Dashboard requires fastapi. Install with: pip install promptshield[dashboard]"
    ) from exc


def _load_events(path: Path, limit: int = 200) -> List[dict]:
    if not path.exists():
        return []

    lines = path.read_text(encoding="utf-8").splitlines()
    data: List[dict] = []
    for line in lines[-limit:]:
        try:
            data.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return data


def create_app(audit_log_path: str = "audit.log.jsonl") -> FastAPI:
    app = FastAPI(title="PromptShield Dashboard")
    log_path = Path(audit_log_path)

    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok"}

    @app.get("/events")
    async def events(limit: int = 200) -> JSONResponse:
        return JSONResponse(_load_events(log_path, limit=limit))

    @app.get("/")
    async def index() -> HTMLResponse:
        html = """
        <!doctype html>
        <html>
          <head>
            <meta charset="utf-8" />
            <title>PromptShield Dashboard</title>
            <style>
              body { font-family: system-ui, sans-serif; margin: 2rem; }
              h1 { margin-bottom: 0.5rem; }
              pre { background: #f7f7f7; padding: 1rem; border-radius: 8px; }
            </style>
          </head>
          <body>
            <h1>PromptShield Events</h1>
            <p>Showing recent audit events from <code>audit.log.jsonl</code>.</p>
            <pre id="events">Loading...</pre>
            <script>
              fetch('/events')
                .then(res => res.json())
                .then(data => {
                  document.getElementById('events').textContent = JSON.stringify(data, null, 2);
                })
                .catch(() => {
                  document.getElementById('events').textContent = 'Failed to load events.';
                });
            </script>
          </body>
        </html>
        """
        return HTMLResponse(html)

    return app
