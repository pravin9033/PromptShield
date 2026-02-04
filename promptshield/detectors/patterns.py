"""Pattern loading helpers for detectors."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Iterable, List, Pattern, Tuple


@dataclass(frozen=True)
class PatternRule:
    pattern: str
    regex: Pattern[str]


@dataclass(frozen=True)
class PatternSet:
    critical: Tuple[PatternRule, ...]
    soft: Tuple[PatternRule, ...]


def find_matches(text: str, rules: Iterable[PatternRule]) -> List[str]:
    return [rule.pattern for rule in rules if rule.regex.search(text)]


@lru_cache(maxsize=None)
def load_pattern_set(name: str, flags: int = 0) -> PatternSet:
    path = resources.files("promptshield.data.patterns").joinpath(f"{name}.json")
    data = json.loads(path.read_text(encoding="utf-8"))

    critical_rules = tuple(_compile_rules(data.get("critical", []), flags))
    soft_rules = tuple(_compile_rules(data.get("soft", []), flags))
    return PatternSet(critical=critical_rules, soft=soft_rules)


def _compile_rules(patterns: Iterable[str], flags: int) -> List[PatternRule]:
    compiled: List[PatternRule] = []
    for pattern in patterns:
        compiled.append(PatternRule(pattern=pattern, regex=re.compile(pattern, flags=flags)))
    return compiled
