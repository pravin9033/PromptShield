"""PromptShield command-line interface."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

try:
    import typer
except ImportError as exc:  # pragma: no cover - optional dependency
    raise ImportError(
        "PromptShield CLI requires typer. Install with: pip install promptshield[cli]"
    ) from exc

from promptshield import scan_messages, scan_prompt

app = typer.Typer(add_completion=False)


try:
    from promptshield.cli.redteam import app as redteam_app

    app.add_typer(redteam_app, name="redteam")
except ImportError:

    @app.command("redteam")
    def redteam_unavailable() -> None:
        """Placeholder when red-team extras are not installed."""
        typer.echo("Red-team commands require promptshield[redteam].")
        raise typer.Exit(code=1)


def _format_result(result) -> str:
    status = "BLOCKED" if result.block else "ALLOWED"
    lines = [
        f"STATUS: {status}",
        f"Risk Score: {result.risk_score}/100",
        f"Category: {result.category}",
        f"Confidence: {result.confidence:.2f}",
        f"Reason: {result.explanation}",
    ]
    return "\n".join(lines)


def _result_to_dict(result) -> Dict[str, Any]:
    return {
        "block": result.block,
        "risk_score": result.risk_score,
        "category": result.category,
        "confidence": result.confidence,
        "explanation": result.explanation,
        "signals": [
            {
                "name": signal.name,
                "category": signal.category,
                "score": signal.score,
                "confidence": signal.confidence,
                "explanation": signal.explanation,
                "matches": signal.matches,
            }
            for signal in result.signals
        ],
    }


def _read_stdin() -> str:
    data = sys.stdin.read()
    return data.strip()


def _load_messages(messages_arg: Optional[str]) -> Optional[list[dict[str, str]]]:
    if not messages_arg:
        return None

    payload = messages_arg
    if payload.startswith("@"):
        path = payload[1:]
        with open(path, "r", encoding="utf-8") as handle:
            payload = handle.read()

    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise typer.BadParameter("messages must be valid JSON") from exc

    if not isinstance(data, list):
        raise typer.BadParameter("messages must be a JSON array")

    return data


@app.command()
def scan(
    prompt: Optional[str] = typer.Argument(None, help="Prompt text (defaults to stdin)"),
    system_prompt: Optional[str] = typer.Option(None, "--system", help="Optional system prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
    messages: Optional[str] = typer.Option(
        None, "--messages", help="JSON array of messages or @path/to/file.json"
    ),
) -> None:
    """Scan a prompt or message list for injection or jailbreak signals."""
    messages_data = _load_messages(messages)

    if messages_data is not None:
        if prompt:
            messages_data.append({"role": "user", "content": prompt})
        result = scan_messages(messages=messages_data, system_prompt=system_prompt)
    else:
        prompt_value = prompt or _read_stdin()
        if not prompt_value:
            raise typer.BadParameter("prompt is required (pass as arg, stdin, or --messages)")
        result = scan_prompt(prompt=prompt_value, system_prompt=system_prompt)

    if json_output:
        typer.echo(json.dumps(_result_to_dict(result), indent=2))
    else:
        typer.echo(_format_result(result))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
