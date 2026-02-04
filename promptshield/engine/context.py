"""Prompt context normalization and multi-turn helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from .types import Message, MessageLike, MessageSequence


@dataclass(frozen=True)
class PromptContext:
    prompt: str
    system_prompt: Optional[str]
    messages: List[Message]
    combined_text: str


def normalize_messages(messages: Optional[MessageSequence]) -> List[Message]:
    if not messages:
        return []

    normalized: List[Message] = []
    for idx, message in enumerate(messages, start=1):
        if isinstance(message, Message):
            role = message.role
            content = message.content
        else:
            role = message.get("role") if message else None
            content = message.get("content") if message else None
        if not role or not content:
            raise ValueError(f"message #{idx} must include role and content")
        normalized.append(Message(role=str(role), content=str(content)))

    return normalized


def _derive_prompt(messages: List[Message]) -> str:
    for message in reversed(messages):
        if message.role.lower() == "user":
            return message.content
    return messages[-1].content if messages else ""


def _combine_text(
    prompt: Optional[str],
    system_prompt: Optional[str],
    messages: List[Message],
) -> str:
    parts: List[str] = []

    if system_prompt:
        parts.append(f"[SYSTEM] {system_prompt}")

    if messages:
        for message in messages:
            role = message.role.upper()
            parts.append(f"[{role}] {message.content}")
        if prompt:
            parts.append(f"[USER] {prompt}")
    elif prompt:
        parts.append(prompt)

    return "\n".join(parts)


def build_context(
    prompt: Optional[str] = None,
    system_prompt: Optional[str] = None,
    messages: Optional[MessageSequence] = None,
) -> PromptContext:
    normalized_messages = normalize_messages(messages)

    prompt_value = "" if prompt is None else str(prompt)
    prompt_provided = bool(prompt_value.strip())

    if not prompt_provided and normalized_messages:
        prompt_value = _derive_prompt(normalized_messages)

    if not prompt_value.strip() and not normalized_messages:
        raise ValueError("prompt or messages must be provided")

    combined_text = _combine_text(prompt_value if prompt_provided else None, system_prompt, normalized_messages)

    return PromptContext(
        prompt=prompt_value,
        system_prompt=system_prompt,
        messages=normalized_messages,
        combined_text=combined_text,
    )
