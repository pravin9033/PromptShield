"""Run attack packs against the PromptShield engine."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional

from promptshield import PromptShieldEngine
from promptshield.engine.verdict import ScanResult

from .packs import AttackCase, AttackPack


@dataclass(frozen=True)
class AttackOutcome:
    case: AttackCase
    scan: ScanResult
    block: bool
    matched_expected: Optional[bool]
    system_prompt: Optional[str]


@dataclass(frozen=True)
class RedTeamRun:
    pack: AttackPack
    results: List[AttackOutcome]
    threshold: int
    started_at: datetime
    finished_at: datetime


def run_attack_pack(
    pack: AttackPack,
    threshold: int = 70,
    system_prompt: Optional[str] = None,
    engine: Optional[PromptShieldEngine] = None,
) -> RedTeamRun:
    started_at = datetime.now(timezone.utc)
    results: List[AttackOutcome] = []

    engine = engine or PromptShieldEngine()

    for case in pack.attacks:
        run_system_prompt = system_prompt if system_prompt is not None else case.system_prompt
        if case.messages:
            messages = list(case.messages)
            if case.prompt:
                messages.append({"role": "user", "content": case.prompt})
            scan = engine.scan_messages(messages=messages, system_prompt=run_system_prompt)
        else:
            scan = engine.scan(prompt=case.prompt, system_prompt=run_system_prompt)
        block = scan.risk_score >= threshold
        if case.expect_block is None:
            matched_expected = None
        else:
            matched_expected = block == case.expect_block
        results.append(
            AttackOutcome(
                case=case,
                scan=scan,
                block=block,
                matched_expected=matched_expected,
                system_prompt=run_system_prompt,
            )
        )

    finished_at = datetime.now(timezone.utc)
    return RedTeamRun(
        pack=pack,
        results=results,
        threshold=threshold,
        started_at=started_at,
        finished_at=finished_at,
    )


def summarize_run(run: RedTeamRun) -> Dict[str, object]:
    total = len(run.results)
    blocked = sum(1 for result in run.results if result.block)
    allowed = total - blocked
    expected_mismatches = sum(
        1 for result in run.results if result.matched_expected is False
    )

    by_category: Dict[str, int] = {}
    for result in run.results:
        category = result.case.category or result.scan.category
        by_category[category] = by_category.get(category, 0) + 1

    return {
        "total": total,
        "blocked": blocked,
        "allowed": allowed,
        "expected_mismatches": expected_mismatches,
        "by_category": by_category,
    }
