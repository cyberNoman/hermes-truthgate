"""Deterministic, value-redacting secret pattern detection."""

from __future__ import annotations

import hashlib
import re
from typing import NamedTuple


class SecretFinding(NamedTuple):
    """A possible embedded credential. The matched value is never retained."""

    kind: str
    lineno: int
    message: str
    fingerprint: str


_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    (
        "private_key",
        "private-key material is embedded in source",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    ),
    (
        "aws_access_key",
        "AWS access-key identifier is embedded in source",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    (
        "github_token",
        "GitHub token is embedded in source",
        re.compile(r"(?<![A-Za-z0-9])(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})"),
    ),
    (
        "slack_token",
        "Slack token is embedded in source",
        re.compile(r"(?<![A-Za-z0-9])xox[baprs]-[A-Za-z0-9-]{20,255}"),
    ),
)

_ASSIGNMENT_RE = re.compile(
    r"(?im)\b(password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
    r"\s*(?:=|:)\s*([\"'])([^\r\n\"']{12,})\2"
)
_PLACEHOLDER_RE = re.compile(
    r"^(?:example|sample|placeholder|changeme|replace[_ -]?me|your[_ -]?.*|x+|\*+|<.*>)$",
    re.IGNORECASE,
)


def _fingerprint(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}\0{value}".encode("utf-8", "surrogatepass")).hexdigest()


def _line_number(source: str, offset: int) -> int:
    return source.count("\n", 0, offset) + 1


def find_secrets(source: str) -> tuple[SecretFinding, ...]:
    """Return possible hard-coded secrets without returning their values.

    Invalid inputs fail open. Fingerprints are used only for in-memory baseline
    comparison and are never included in messages or persisted findings.
    """

    if not isinstance(source, str):
        return ()
    try:
        findings: list[SecretFinding] = []
        seen: set[tuple[str, int, str]] = set()
        for kind, message, pattern in _PATTERNS:
            for match in pattern.finditer(source):
                fingerprint = _fingerprint(kind, match.group(0))
                identity = (kind, match.start(), fingerprint)
                if identity not in seen:
                    seen.add(identity)
                    findings.append(SecretFinding(kind, _line_number(source, match.start()), message, fingerprint))
        for match in _ASSIGNMENT_RE.finditer(source):
            value = match.group(3).strip()
            if _PLACEHOLDER_RE.fullmatch(value):
                continue
            kind = "credential_assignment"
            fingerprint = _fingerprint(kind, value)
            identity = (kind, match.start(), fingerprint)
            if identity not in seen:
                seen.add(identity)
                findings.append(
                    SecretFinding(
                        kind,
                        _line_number(source, match.start()),
                        "credential-like value is assigned directly in source",
                        fingerprint,
                    )
                )
        findings.sort(key=lambda item: (item.lineno, item.kind))
        return tuple(findings)
    except Exception:
        return ()
