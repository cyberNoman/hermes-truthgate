"""Hermes hook orchestration for bounded deterministic verification."""

from __future__ import annotations

import hashlib
import io
import logging
import os
import threading
import tokenize
from pathlib import Path
from typing import Any, Callable

from .baseline import BaselineStore
from .store import FindingStore, session_tag


logger = logging.getLogger(__name__)
DEFAULT_MAX_BYTES = 1024 * 1024
DEFAULT_MAX_CONTINUATIONS = 2
_SCANNABLE_SUFFIXES = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg", ".conf"}
)


class TruthGate:
    """Capture initial file state and request bounded repairs for new findings."""

    def __init__(
        self,
        store: FindingStore,
        *,
        cwd_resolver: Callable[[], Path] | None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_continuations: int = DEFAULT_MAX_CONTINUATIONS,
    ) -> None:
        self.store = store
        self.cwd_resolver = cwd_resolver
        self.max_bytes = max(0, int(max_bytes))
        self.max_continuations = max(1, int(max_continuations))
        self.baselines = BaselineStore(max_bytes=self.max_bytes)
        self._session_turn: dict[str, str] = {}
        self._last_signature: dict[str, str] = {}
        self._continuations: dict[str, int] = {}
        self._lock = threading.RLock()

    def pre_tool_call(self, **kwargs: Any) -> None:
        """Observe supported mutation calls before dispatch. Internal errors are ignored."""

        try:
            tool_name = kwargs.get("tool_name")
            args = kwargs.get("args")
            turn_id = kwargs.get("turn_id")
            session_id = kwargs.get("session_id")
            if not all(isinstance(value, str) and value for value in (tool_name, turn_id, session_id)):
                return None
            cwd = self._cwd()
            snapshots = self.baselines.capture_tool_call(tool_name, args, turn_id=turn_id, cwd=cwd)
            if snapshots:
                with self._lock:
                    self._session_turn[session_id] = turn_id
            return None
        except Exception:
            logger.debug("TruthGate pre_tool_call failed open", exc_info=True)
            return None

    def pre_verify(self, **kwargs: Any) -> dict[str, str] | None:
        """Scan changed files and ask Hermes for a bounded corrective continuation."""

        try:
            if kwargs.get("coding") is not True:
                return None
            attempt = kwargs.get("attempt")
            session_id = kwargs.get("session_id")
            changed_paths = kwargs.get("changed_paths")
            if type(attempt) is not int or attempt < 0 or not isinstance(session_id, str) or not session_id:
                return None
            if not isinstance(changed_paths, (list, tuple)) or not changed_paths:
                return None
            with self._lock:
                turn_id = self._session_turn.get(session_id)
            if not turn_id:
                return None
            cwd = self._cwd()
            findings = self._scan(turn_id, changed_paths, cwd)
            if not findings:
                self._finish(session_id, turn_id)
                return None

            signature = self._signature(findings)
            with self._lock:
                repeated = self._last_signature.get(session_id) == signature
                used = self._continuations.get(session_id, 0)
                allowed = attempt < self.max_continuations and used < self.max_continuations and not repeated
                if allowed:
                    self._last_signature[session_id] = signature
                    self._continuations[session_id] = used + 1

            event = "continuation" if allowed else "suppressed"
            for finding in findings:
                self.store.append(
                    event=event,
                    session=session_tag(session_id),
                    path=finding["path"],
                    line=finding["line"],
                    category=finding["category"],
                    kind=finding["kind"],
                    status="new",
                )
            if not allowed:
                logger.info("TruthGate suppressed repeated or exhausted finding set session=%s", session_tag(session_id))
                self._finish(session_id, turn_id)
                return None

            logger.info(
                "TruthGate requested corrective continuation session=%s attempt=%d findings=%d",
                session_tag(session_id),
                attempt,
                len(findings),
            )
            return {"action": "continue", "message": self._message(findings)}
        except Exception:
            logger.debug("TruthGate pre_verify failed open", exc_info=True)
            return None

    def status(self) -> str:
        return self.store.summary()

    def _cwd(self) -> Path:
        if self.cwd_resolver is None:
            raise RuntimeError("Hermes session cwd resolver unavailable")
        cwd = self.cwd_resolver()
        if not isinstance(cwd, (str, os.PathLike)):
            raise TypeError("Hermes session cwd resolver returned an invalid path")
        return Path(cwd).resolve(strict=False)

    def _read(self, path: Path) -> str | None:
        try:
            if path.suffix.lower() not in _SCANNABLE_SUFFIXES or path.stat().st_size > self.max_bytes:
                return None
            data = path.read_bytes()
            if len(data) > self.max_bytes or b"\x00" in data:
                return None
            if path.suffix.lower() in {".py", ".pyi"}:
                encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
                return data.decode(encoding)
            return data.decode("utf-8")
        except (OSError, UnicodeError, LookupError, SyntaxError):
            return None

    def _scan(self, turn_id: str, changed_paths: list[Any] | tuple[Any, ...], cwd: Path) -> list[dict[str, Any]]:
        found: list[dict[str, Any]] = []
        for raw_path in dict.fromkeys(path for path in changed_paths if isinstance(path, str) and path):
            path = Path(raw_path).expanduser()
            if not path.is_absolute():
                path = cwd / path
            path = path.resolve(strict=False)
            source = self._read(path)
            if source is None:
                continue
            comparison = self.baselines.compare(turn_id, path, source, cwd=cwd)
            if comparison.status != "ok":
                continue
            try:
                display = str(path.relative_to(cwd))
            except ValueError:
                display = path.name
            for item in comparison.findings:
                found.append(
                    {"path": display, "line": item.lineno, "category": "stub", "kind": item.kind,
                     "name": item.qualified_name, "identity": item.qualified_name}
                )
            for item in comparison.secrets:
                found.append(
                    {"path": display, "line": item.lineno, "category": "secret", "kind": item.kind,
                     "name": "", "identity": item.fingerprint}
                )
        found.sort(key=lambda item: (item["path"], item["line"], item["category"], item["kind"]))
        return found

    @staticmethod
    def _signature(findings: list[dict[str, Any]]) -> str:
        stable = "\n".join(
            f"{item['path']}\0{item['category']}\0{item['kind']}\0{item['identity']}" for item in findings
        )
        return hashlib.sha256(stable.encode("utf-8", "surrogatepass")).hexdigest()

    @staticmethod
    def _message(findings: list[dict[str, Any]]) -> str:
        lines = ["TruthGate found newly introduced release risks. Fix them before finalizing:"]
        for item in findings[:12]:
            label = f"function {item['name']}" if item["category"] == "stub" else "possible embedded credential"
            lines.append(f"- {item['path']}:{item['line']} [{item['category']}/{item['kind']}] {label}")
        if len(findings) > 12:
            lines.append(f"- and {len(findings) - 12} more finding(s)")
        lines.append("Do not print or repeat credential values. Remove the finding, then run the relevant checks.")
        return "\n".join(lines)

    def _finish(self, session_id: str, turn_id: str) -> None:
        self.baselines.discard_turn(turn_id)
        with self._lock:
            self._session_turn.pop(session_id, None)
            self._last_signature.pop(session_id, None)
            self._continuations.pop(session_id, None)
