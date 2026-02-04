"""PromptShield command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict

from promptshield import scan_prompt


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


def main() -> None:
    parser = argparse.ArgumentParser(prog="promptshield")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a prompt")
    scan_parser.add_argument("prompt", nargs="?", help="Prompt text (defaults to stdin)")
    scan_parser.add_argument("--system", dest="system_prompt", help="Optional system prompt")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    if args.command == "scan":
        prompt = args.prompt or _read_stdin()
        if not prompt:
            parser.error("prompt is required (pass as arg or via stdin)")
        result = scan_prompt(prompt=prompt, system_prompt=args.system_prompt)
        if args.json:
            print(json.dumps(_result_to_dict(result), indent=2))
        else:
            print(_format_result(result))


if __name__ == "__main__":
    main()
