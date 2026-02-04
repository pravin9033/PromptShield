"""Run model scans using attack packs."""

from __future__ import annotations

from typing import Optional

from promptshield.compliance.scanner import ComplianceEngine
from promptshield.redteam.packs import AttackPack

from .types import ModelAdapter, ModelScanOutcome, ModelScanResult


def run_model_scan(
    pack: AttackPack,
    adapter: ModelAdapter,
    scan_outputs: bool = True,
    compliance_engine: Optional[ComplianceEngine] = None,
) -> ModelScanResult:
    compliance_engine = compliance_engine or ComplianceEngine()
    outcomes: list[ModelScanOutcome] = []

    for case in pack.attacks:
        messages = (
            [{"role": msg.role, "content": msg.content} for msg in case.messages]
            if case.messages
            else None
        )
        if messages is not None and case.prompt:
            messages = [*messages, {"role": "user", "content": case.prompt}]

        output = adapter.generate(
            prompt=case.prompt if messages is None else None,
            system_prompt=case.system_prompt,
            messages=messages,
        )

        compliance = compliance_engine.scan(output) if scan_outputs else None

        outcomes.append(
            ModelScanOutcome(
                attack_id=case.attack_id,
                prompt=case.prompt,
                system_prompt=case.system_prompt,
                messages=messages,
                output=output,
                compliance=compliance,
            )
        )

    return ModelScanResult(adapter=adapter.name, pack_name=pack.name, outcomes=outcomes)
