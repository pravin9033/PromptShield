"""FastAPI/Starlette middleware for PromptShield."""

from __future__ import annotations

import json
from typing import Callable, Optional

from promptshield import PromptShieldEngine

try:
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.requests import Request
    from starlette.responses import JSONResponse, Response
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError(
        "PromptShield middleware requires starlette (or fastapi). Install with promptshield[middleware]."  # noqa: E501
    ) from exc


class PromptShieldMiddleware(BaseHTTPMiddleware):
    """Blocks requests with high-risk prompt content."""

    def __init__(
        self,
        app,
        block_threshold: int = 70,
        prompt_field: str = "prompt",
        system_field: str = "system_prompt",
        block_status_code: int = 403,
        max_body_bytes: int = 100_000,
        engine: Optional[PromptShieldEngine] = None,
    ) -> None:
        super().__init__(app)
        self.block_threshold = block_threshold
        self.prompt_field = prompt_field
        self.system_field = system_field
        self.block_status_code = block_status_code
        self.max_body_bytes = max_body_bytes
        self.engine = engine or PromptShieldEngine()

    async def dispatch(self, request: Request, call_next: Callable[[Request], Response]) -> Response:
        if request.method not in {"POST", "PUT", "PATCH"}:
            return await call_next(request)

        content_type = request.headers.get("content-type", "")
        if "application/json" not in content_type:
            return await call_next(request)

        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > self.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": "payload_too_large", "max_body_bytes": self.max_body_bytes},
            )

        body = await request.body()
        if not body:
            return await call_next(request)

        if len(body) > self.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": "payload_too_large", "max_body_bytes": self.max_body_bytes},
            )

        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            request._body = body
            return await call_next(request)

        if not isinstance(payload, dict):
            request._body = body
            return await call_next(request)

        prompt = payload.get(self.prompt_field)
        system_prompt = payload.get(self.system_field)
        if prompt:
            result = self.engine.scan(prompt=prompt, system_prompt=system_prompt)
            if result.risk_score >= self.block_threshold:
                return JSONResponse(
                    status_code=self.block_status_code,
                    content={
                        "error": "blocked",
                        "risk_score": result.risk_score,
                        "category": result.category,
                        "confidence": result.confidence,
                        "explanation": result.explanation,
                    },
                )

        request._body = body
        return await call_next(request)
