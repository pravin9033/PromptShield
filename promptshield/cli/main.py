"""PromptShield command-line interface."""

from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

import typer

from promptshield import scan_prompt
from promptshield.cli.redteam import app as redteam_app

app = typer.Typer(add_completion=False)
app.add_typer(redteam_app, name="redteam")


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


@app.command()
def scan(
    prompt: Optional[str] = typer.Argument(None, help="Prompt text (defaults to stdin)"),
    system_prompt: Optional[str] = typer.Option(None, "--system", help="Optional system prompt"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
) -> None:
    """Scan a prompt for injection or jailbreak signals."""
    prompt_value = prompt or _read_stdin()
    if not prompt_value:
        raise typer.BadParameter("prompt is required (pass as arg or via stdin)")

    result = scan_prompt(prompt=prompt_value, system_prompt=system_prompt)
    if json_output:
        typer.echo(json.dumps(_result_to_dict(result), indent=2))
    else:
        typer.echo(_format_result(result))


def main() -> None:
    app()


if __name__ == "__main__":
    main()
