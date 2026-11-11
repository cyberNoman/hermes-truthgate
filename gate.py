"""Hermes hook orchestration for bounded deterministic verification."""

from __future__ import annotations

import hashlib
import logging
import os
import threading
from typing import Any, Callable, NamedTuple

from .baseline import (
    SCANNABLE_SUFFIXES,
    BaselineStore,
    SessionCwd,
    is_regular_file,
    is_dotenv_path,
    lexical_absolute,
    path_suffix,
    read_text_bounded,
    real_key,
)
from .store import FindingStore, session_tag


logger = logging.getLogger(__name__)
DEFAULT_MAX_BYTES = 1024 * 1024
DEFAULT_MAX_CONTINUATIONS = 2
MAX_VERIFY_PATHS = 64
MAX_SESSIONS = 256
VERIFY_IO_BUDGET_SECONDS = 8.0
_MUTATION_TOOLS = frozenset({"write_file", "patch"})


class _Inspection(NamedTuple):
    key: str
    display: str
    uncaptured: str
    findings: tuple[dict[str, Any], ...]


class TruthGate:
    """Capture initial file state and request bounded repairs for new findings."""

    def __init__(
        self,
        store: FindingStore,
        *,
        cwd_resolver: Callable[[], Any] | None,
        max_bytes: int = DEFAULT_MAX_BYTES,
        max_continuations: int = DEFAULT_MAX_CONTINUATIONS,
    ) -> None:
        self.store = store
        self.cwd_resolver = cwd_resolver
        self.max_bytes = max(0, int(max_bytes))
        self.max_continuations = max(1, int(max_continuations))
        self.baselines = BaselineStore(max_bytes=self.max_bytes)
        self.verify_budget = VERIFY_IO_BUDGET_SECONDS
        self._session_turn: dict[str, str] = {}
        self._last_signature: dict[str, str] = {}
        self._continuations: dict[str, int] = {}
        self._reported: dict[str, set[str]] = {}
        self._lock = threading.RLock()

    def pre_tool_call(self, **kwargs: Any) -> None:
        """Observe supported mutation calls before dispatch.

        Always returns ``None``: Hermes treats a ``pre_tool_call`` exception or
        timeout as a veto, so this hook never raises and never waits on a file
        beyond the baseline I/O budget.
        """

        try:
            tool_name = kwargs.get("tool_name")
            if tool_name not in _MUTATION_TOOLS:
                return None
            turn_id = kwargs.get("turn_id")
            session_id = kwargs.get("session_id")
            if not all(isinstance(value, str) and value for value in (turn_id, session_id)):
                return None
            self._bind_turn(session_id, turn_id)
            self.baselines.capture_tool_call(
                tool_name, kwargs.get("args"), turn_id=turn_id, cwd=SessionCwd(self.cwd_resolver)
            )
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
                turn_id = self._session_turn.get(session_id, "")
            findings = self._scan(session_id, turn_id, changed_paths)
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

    def _bind_turn(self, session_id: str, turn_id: str) -> None:
        """Point the session at its current turn and drop state left by an older one."""

        stale = ""
        with self._lock:
            previous = self._session_turn.get(session_id)
            if previous == turn_id:
                return
            if previous:
                stale = previous
                self._last_signature.pop(session_id, None)
                self._continuations.pop(session_id, None)
                self._reported.pop(session_id, None)
            self._session_turn.pop(session_id, None)
            while len(self._session_turn) >= MAX_SESSIONS:
                oldest = next(iter(self._session_turn))
                evicted = self._session_turn.pop(oldest)
                self._last_signature.pop(oldest, None)
                self._continuations.pop(oldest, None)
                self._reported.pop(oldest, None)
                self.baselines.discard_turn(evicted)
            self._session_turn[session_id] = turn_id
        if stale:
            self.baselines.discard_turn(stale)

    def _inspect(self, turn_id: str, absolute: str, real_cwd: Callable[[], str | None]) -> _Inspection:
        """Worker-side: classify one changed path. Performs filesystem access."""

        real, key = real_key(absolute)
        display = self._display(real, real_cwd())
        nothing = _Inspection(key, display, "", ())
        snapshot = self.baselines.lookup(turn_id, key)
        if snapshot is None or snapshot.status not in {"ok", "missing"}:
            # Nothing reliable to compare against: never read, never nudge. A
            # path that no longer exists (deleted or moved away) is not reported.
            if not is_regular_file(real):
                return nothing
            return _Inspection(key, display, snapshot.status if snapshot else "no_baseline", ())
        if is_dotenv_path(real):
            # The path-level creation is the risk. Existing dotenv files are
            # ignored, and newly created ones are never opened or parsed.
            if snapshot.status != "missing" or not is_regular_file(real):
                return nothing
            return _Inspection(
                key,
                display,
                "",
                ({"path": display, "line": 1, "category": "secret", "kind": "dotenv_file",
                  "name": "", "identity": "dotenv_file"},),
            )
        read = read_text_bounded(real, self.max_bytes)
        if read.status != "ok":
            return nothing
        comparison = self.baselines.compare_key(turn_id, key, real, read.text)
        if comparison.status != "ok":
            return _Inspection(key, display, comparison.reason or comparison.status, ())
        found: list[dict[str, Any]] = []
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
        return _Inspection(key, display, "", tuple(found))

    @staticmethod
    def _display(real: str, real_cwd: str | None) -> str:
        """Workspace-relative path, or only the basename outside the workspace."""

        if real_cwd:
            try:
                if os.path.commonpath([os.path.normcase(real), os.path.normcase(real_cwd)]) == os.path.normcase(
                    real_cwd
                ):
                    return os.path.relpath(real, real_cwd)
            except (OSError, ValueError):
                pass
        return os.path.basename(real)

    def _scan(self, session_id: str, turn_id: str, changed_paths: list[Any] | tuple[Any, ...]) -> list[dict[str, Any]]:
        # Resolved on this (the hook's) thread; see ``SessionCwd``.
        session = SessionCwd(self.cwd_resolver)
        absolutes: list[str] = []
        unsupported = 0
        considered = 0
        over_limit = 0
        for raw in dict.fromkeys(path for path in changed_paths if isinstance(path, str) and path):
            if considered >= MAX_VERIFY_PATHS:
                over_limit += 1
                continue
            considered += 1
            absolute = lexical_absolute(raw, session)
            if absolute is None:
                unsupported += 1
            elif path_suffix(absolute) in SCANNABLE_SUFFIXES:
                absolutes.append(absolute)
        absolutes = list(dict.fromkeys(absolutes))

        # The session directory is used here only to shorten displayed paths;
        # without it findings are still produced and shown by basename.
        cwd_text = lexical_absolute(".", session) if absolutes else None
        cache: list[str | None] = []

        def real_cwd() -> str | None:
            if not cache:
                cache.append(real_key(cwd_text)[0] if cwd_text else None)
            return cache[0]

        # One worker pool serves both hooks so the stalled-thread cap is global.
        outcomes = self.baselines.io.run(
            lambda absolute: self._inspect(turn_id, absolute, real_cwd), absolutes, budget=self.verify_budget
        )
        # ``None`` means the worker never produced an answer for that path.
        unfinished = sum(1 for outcome in outcomes if outcome is None)

        tag = session_tag(session_id)
        found: list[dict[str, Any]] = []
        for outcome in outcomes:
            if outcome is None:
                continue
            if outcome.uncaptured:
                with self._lock:
                    reported = self._reported.setdefault(session_id, set())
                    fresh = outcome.key not in reported and len(reported) < MAX_VERIFY_PATHS * 4
                    if fresh:
                        reported.add(outcome.key)
                if fresh:
                    self.store.append(
                        event="uncaptured", session=tag, path=outcome.display, line=0,
                        category="baseline", kind=outcome.uncaptured, status="unverified",
                    )
                continue
            found.extend(outcome.findings)
        for kind, count in (("path_limit", over_limit), ("unsupported_path", unsupported), ("not_inspected", unfinished)):
            if count:
                self.store.append(
                    event="skipped", session=tag, path="", line=count,
                    category="limit", kind=kind, status="unverified",
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
        if turn_id:
            self.baselines.discard_turn(turn_id)
        with self._lock:
            self._session_turn.pop(session_id, None)
            self._last_signature.pop(session_id, None)
            self._continuations.pop(session_id, None)
            self._reported.pop(session_id, None)
