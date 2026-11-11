"""Append-only sanitized JSONL finding storage."""

from __future__ import annotations

import hashlib
import json
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_ALLOWED = frozenset({"event", "session", "path", "line", "category", "kind", "status"})


def _clean(value: Any, *, limit: int = 300) -> str:
    text = str(value or "").replace("\r", " ").replace("\n", " ")
    return "".join(ch for ch in text if ch.isprintable())[:limit]


def session_tag(session_id: str) -> str:
    """Return a non-reversible short tag suitable for diagnostics."""

    if not session_id:
        return "unknown"
    return hashlib.sha256(session_id.encode("utf-8", "surrogatepass")).hexdigest()[:12]


class FindingStore:
    """Persist an allowlisted record shape; never accepts source or matched values."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, **fields: Any) -> bool:
        try:
            record: dict[str, Any] = {
                "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds")
            }
            for key in _ALLOWED:
                if key not in fields:
                    continue
                value = fields[key]
                if key == "line":
                    record[key] = max(0, int(value))
                else:
                    record[key] = _clean(value)
            encoded = json.dumps(record, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            with self._lock:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                    handle.write(encoded + "\n")
            return True
        except Exception:
            return False

    def summary(self) -> str:
        """Return aggregate status without replaying paths or other record detail."""

        try:
            counts: Counter[str] = Counter()
            total = 0
            with self._lock:
                with self.path.open("r", encoding="utf-8") as handle:
                    for line in handle:
                        try:
                            record = json.loads(line)
                        except (TypeError, ValueError):
                            continue
                        if isinstance(record, dict):
                            counts[_clean(record.get("event") or "unknown", limit=40)] += 1
                            total += 1
            breakdown = ", ".join(f"{key}={counts[key]}" for key in sorted(counts)) or "none"
            return f"TruthGate 0.2.1: {total} sanitized records ({breakdown})."
        except FileNotFoundError:
            return "TruthGate 0.2.1: no findings recorded."
        except Exception:
            return "TruthGate 0.2.1: findings store unavailable (gate remains fail-open)."
