"""PromptShield model scan CLI commands."""

from __future__ import annotations

from typing import Optional

import json
import typer

from promptshield.modelscan import get_adapter, run_model_scan
from promptshield.redteam import load_attack_pack

app = typer.Typer(help="Run model scans using attack packs")


@app.command("run")
def run(
    pack_path: str = typer.Argument(..., help="Path to attack pack YAML"),
    adapter: str = typer.Option("echo", "--adapter", help="Model adapter name"),
    scan_outputs: bool = typer.Option(True, "--scan-outputs/--no-scan-outputs"),
) -> None:
    """Run a model scan on a pack and print JSON results."""
    model_adapter = get_adapter(adapter)
    if model_adapter is None:
        raise typer.BadParameter(f"Unknown adapter: {adapter}")

    pack = load_attack_pack(pack_path)
    result = run_model_scan(pack, model_adapter, scan_outputs=scan_outputs)

    payload = {
        "adapter": result.adapter,
        "pack": result.pack_name,
        "outcomes": [
            {
                "attack_id": outcome.attack_id,
                "output": outcome.output,
                "compliance": {
                    "block": outcome.compliance.block,
                    "risk_score": outcome.compliance.risk_score,
                    "category": outcome.compliance.category,
                    "confidence": outcome.compliance.confidence,
                }
                if outcome.compliance
                else None,
            }
            for outcome in result.outcomes
        ],
    }

    typer.echo(json.dumps(payload, indent=2))
