"""Report generation for red-team runs."""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from .runner import RedTeamRun, summarize_run


@dataclass(frozen=True)
class ReportPaths:
    json_path: Path
    markdown_path: Path
    repro_script_path: Path


def _slugify(value: str) -> str:
    return "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")


def _timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")


def _run_id(run: RedTeamRun) -> str:
    return f"{_slugify(run.pack.name)}_{_timestamp()}"


def _render_json(run: RedTeamRun) -> Dict[str, object]:
    summary = summarize_run(run)
    return {
        "pack": {
            "name": run.pack.name,
            "version": run.pack.version,
            "description": run.pack.description,
            "source_path": str(run.pack.source_path),
        },
        "threshold": run.threshold,
        "started_at": run.started_at.isoformat(),
        "finished_at": run.finished_at.isoformat(),
        "summary": summary,
        "results": [
            {
                "id": result.case.attack_id,
                "category": result.case.category or result.scan.category,
                "prompt": result.case.prompt,
                "system_prompt": result.system_prompt,
                "block": result.block,
                "risk_score": result.scan.risk_score,
                "confidence": result.scan.confidence,
                "explanation": result.scan.explanation,
                "expect_block": result.case.expect_block,
                "matched_expected": result.matched_expected,
                "signals": [
                    {
                        "name": signal.name,
                        "category": signal.category,
                        "score": signal.score,
                        "confidence": signal.confidence,
                        "explanation": signal.explanation,
                        "matches": signal.matches,
                    }
                    for signal in result.scan.signals
                ],
            }
            for result in run.results
        ],
    }


def _render_markdown(run: RedTeamRun) -> str:
    summary = summarize_run(run)
    lines: List[str] = []
    lines.append(f"# PromptShield Red-Team Report: {run.pack.name}")
    lines.append("")
    lines.append(f"- Pack version: {run.pack.version}")
    lines.append(f"- Threshold: {run.threshold}")
    lines.append(f"- Started: {run.started_at.isoformat()}")
    lines.append(f"- Finished: {run.finished_at.isoformat()}")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Total attacks: {summary['total']}")
    lines.append(f"- Blocked: {summary['blocked']}")
    lines.append(f"- Allowed: {summary['allowed']}")
    lines.append(f"- Expected mismatches: {summary['expected_mismatches']}")
    lines.append("")
    lines.append("## Results")
    lines.append("")

    for result in run.results:
        status = "BLOCKED" if result.block else "ALLOWED"
        lines.append(f"### {result.case.attack_id} — {status}")
        lines.append("")
        lines.append(f"- Category: {result.case.category or result.scan.category}")
        lines.append(f"- Risk score: {result.scan.risk_score}")
        lines.append(f"- Confidence: {result.scan.confidence:.2f}")
        lines.append(f"- Explanation: {result.scan.explanation}")
        if result.case.expect_block is not None:
            lines.append(f"- Expected block: {result.case.expect_block}")
            lines.append(f"- Matched expected: {result.matched_expected}")
        if result.system_prompt:
            lines.append("- System prompt override: yes")
        lines.append("")
        lines.append("Prompt:")
        lines.append("")
        lines.append("```text")
        lines.append(result.case.prompt)
        lines.append("```")
        lines.append("")

    return "\n".join(lines)


def _render_repro_script(run: RedTeamRun) -> str:
    lines: List[str] = ["#!/usr/bin/env bash", "set -euo pipefail", ""]
    for result in run.results:
        prompt = shlex.quote(result.case.prompt)
        if result.system_prompt:
            system_prompt = shlex.quote(result.system_prompt)
            line = f"promptshield scan --system {system_prompt} {prompt}"
        else:
            line = f"promptshield scan {prompt}"
        lines.append(line)
    lines.append("")
    return "\n".join(lines)


def write_reports(run: RedTeamRun, reports_dir: str = "reports") -> ReportPaths:
    output_dir = Path(reports_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    run_id = _run_id(run)
    json_path = output_dir / f"{run_id}.json"
    markdown_path = output_dir / f"{run_id}.md"
    repro_script_path = output_dir / f"{run_id}.sh"

    json_payload = _render_json(run)
    json_path.write_text(json.dumps(json_payload, indent=2), encoding="utf-8")
    markdown_path.write_text(_render_markdown(run), encoding="utf-8")
    repro_script_path.write_text(_render_repro_script(run), encoding="utf-8")
    repro_script_path.chmod(0o755)

    return ReportPaths(
        json_path=json_path,
        markdown_path=markdown_path,
        repro_script_path=repro_script_path,
    )
