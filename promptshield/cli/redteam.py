"""PromptShield red-team CLI commands."""

from __future__ import annotations

from typing import Optional

import typer

from promptshield.redteam import load_attack_pack, run_attack_pack, write_reports
from promptshield.redteam.runner import summarize_run

app = typer.Typer(help="Run red-team attack packs")


@app.command("run")
def run_pack(
    pack_path: str = typer.Argument(..., help="Path to attack pack YAML"),
    threshold: int = typer.Option(70, "--threshold", help="Block threshold"),
    reports_dir: str = typer.Option("reports", "--reports-dir", help="Report output directory"),
    system_prompt: Optional[str] = typer.Option(None, "--system", help="Override system prompt"),
) -> None:
    """Run a red-team pack and generate reports."""
    pack = load_attack_pack(pack_path)
    run = run_attack_pack(pack, threshold=threshold, system_prompt=system_prompt)
    report_paths = write_reports(run, reports_dir=reports_dir)
    summary = summarize_run(run)

    typer.echo(f"Pack: {pack.name} ({pack.version})")
    typer.echo(f"Total: {summary['total']}")
    typer.echo(f"Blocked: {summary['blocked']}")
    typer.echo(f"Allowed: {summary['allowed']}")
    typer.echo(f"Expected mismatches: {summary['expected_mismatches']}")
    typer.echo("Reports:")
    typer.echo(f"- JSON: {report_paths.json_path}")
    typer.echo(f"- Markdown: {report_paths.markdown_path}")
    typer.echo(f"- Repro script: {report_paths.repro_script_path}")


@app.command("lint")
def lint_pack(
    pack_paths: list[str] = typer.Argument(..., help="Attack pack YAML files to validate"),
) -> None:
    """Validate attack packs against the schema."""
    failed = False
    for pack_path in pack_paths:
        try:
            load_attack_pack(pack_path)
            typer.echo(f"{pack_path}: OK")
        except Exception as exc:
            failed = True
            typer.echo(f"{pack_path}: FAILED")
            typer.echo(str(exc))
    if failed:
        raise typer.Exit(code=1)
