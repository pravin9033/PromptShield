"""PromptShield compliance CLI commands."""

from __future__ import annotations

import json
import sys
from typing import Optional

import typer

from promptshield.compliance import ComplianceEngine

app = typer.Typer(help="Scan outputs for PII or secrets")


@app.command("scan")
def scan_output(
    text: Optional[str] = typer.Argument(None, help="Output text (defaults to stdin)"),
    json_output: bool = typer.Option(False, "--json", help="Output JSON"),
) -> None:
    """Scan output text for compliance issues."""
    if text is None:
        text = sys.stdin.read().strip()
    if not text:
        raise typer.BadParameter("text is required (pass as arg or via stdin)")

    engine = ComplianceEngine()
    result = engine.scan(text)

    if json_output:
        typer.echo(
            json.dumps(
                {
                    "block": result.block,
                    "risk_score": result.risk_score,
                    "category": result.category,
                    "confidence": result.confidence,
                    "explanation": result.explanation,
                    "issues": [
                        {
                            "category": issue.category,
                            "score": issue.score,
                            "confidence": issue.confidence,
                            "explanation": issue.explanation,
                            "matches": issue.matches,
                        }
                        for issue in result.issues
                    ],
                },
                indent=2,
            )
        )
    else:
        status = "BLOCKED" if result.block else "ALLOWED"
        typer.echo(f"STATUS: {status}")
        typer.echo(f"Risk Score: {result.risk_score}/100")
        typer.echo(f"Category: {result.category}")
        typer.echo(f"Confidence: {result.confidence:.2f}")
        typer.echo(f"Reason: {result.explanation}")
