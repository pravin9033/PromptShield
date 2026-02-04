"""Pattern definitions for compliance scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable, List, Pattern, Tuple


@dataclass(frozen=True)
class PatternRule:
    name: str
    regex: Pattern[str]


@dataclass(frozen=True)
class PatternSet:
    critical: Tuple[PatternRule, ...]
    soft: Tuple[PatternRule, ...]


def _compile(name: str, pattern: str, flags: int = 0) -> PatternRule:
    return PatternRule(name=name, regex=re.compile(pattern, flags))


@lru_cache(maxsize=None)
def pii_patterns() -> PatternSet:
    critical = (
        _compile("email", r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE),
        _compile("ssn", r"\b\d{3}-\d{2}-\d{4}\b"),
        _compile("phone", r"\b\+?\d{1,2}?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        _compile("credit_card", r"\b(?:\d[ -]*?){13,16}\b"),
    )
    soft = (
        _compile("address_hint", r"\baddress\b", re.IGNORECASE),
        _compile("dob_hint", r"\bdate of birth\b", re.IGNORECASE),
    )
    return PatternSet(critical=critical, soft=soft)


@lru_cache(maxsize=None)
def secret_patterns() -> PatternSet:
    critical = (
        _compile("aws_access_key", r"\bAKIA[0-9A-Z]{16}\b"),
        _compile("github_token", r"\bghp_[A-Za-z0-9]{36}\b"),
        _compile("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        _compile("openai_key", r"\bsk-[A-Za-z0-9]{20,}\b"),
    )
    soft = (
        _compile("api_key_phrase", r"\bapi key\b", re.IGNORECASE),
        _compile("secret_phrase", r"\bsecret\b", re.IGNORECASE),
        _compile("token_phrase", r"\baccess token\b", re.IGNORECASE),
    )
    return PatternSet(critical=critical, soft=soft)


def find_matches(text: str, rules: Iterable[PatternRule]) -> List[str]:
    return [rule.name for rule in rules if rule.regex.search(text)]
