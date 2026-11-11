"""Turn-isolated snapshots taken before Hermes mutates Python files."""

from __future__ import annotations

import io
import os
import re
import threading
import tokenize
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

try:
    from .secrets import SecretFinding, find_secrets
    from .stubs import StubFinding, find_stubs
except ImportError:  # Direct module loading in the isolated test suite.
    from secrets import SecretFinding, find_secrets
    from stubs import StubFinding, find_stubs


DEFAULT_MAX_BYTES = 1024 * 1024
_V4A_PATH_RE = re.compile(
    r"^\*\*\* (?:Update File|Add File|Delete File|Move to):\s*(.+?)\s*$",
    re.MULTILINE,
)
_TRUSTED_BASELINES = frozenset({"ok", "missing"})


class BaselineSnapshot(NamedTuple):
    """The first observed state of one path in one coding turn."""

    path: str
    status: str
    findings: tuple[StubFinding, ...]
    secrets: tuple[SecretFinding, ...] = ()


class BaselineComparison(NamedTuple):
    """New findings relative to a captured initial state."""

    path: str
    status: str
    findings: tuple[StubFinding, ...]
    secrets: tuple[SecretFinding, ...] = ()


def _tool_paths(tool_name: str, args: Any) -> tuple[str, ...]:
    if not isinstance(args, dict):
        return ()
    raw: list[str] = []
    if tool_name == "write_file":
        if isinstance(args.get("path"), str):
            raw.append(args["path"])
    elif tool_name == "patch":
        mode = args.get("mode", "replace")
        if mode == "patch":
            patch_text = args.get("patch")
            if not isinstance(patch_text, str):
                return ()
            raw.extend(match.group(1) for match in _V4A_PATH_RE.finditer(patch_text))
        elif isinstance(args.get("path"), str):
            raw.append(args["path"])
    return tuple(dict.fromkeys(path.strip() for path in raw if path.strip()))


def _resolve_path(raw_path: str | os.PathLike[str], cwd: str | os.PathLike[str] | None) -> Path:
    path = Path(raw_path).expanduser()
    if not path.is_absolute():
        path = Path(cwd or Path.cwd()) / path
    return path.resolve(strict=False)


def _decode_python(data: bytes) -> str:
    stream = io.BytesIO(data)
    encoding, _ = tokenize.detect_encoding(stream.readline)
    return data.decode(encoding)


class BaselineStore:
    """Capture-once baseline state partitioned by Hermes ``turn_id``."""

    def __init__(self, *, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.max_bytes = max(0, int(max_bytes))
        self._turns: dict[str, dict[str, BaselineSnapshot]] = {}
        self._lock = threading.RLock()

    def capture_tool_call(
        self,
        tool_name: str,
        args: Any,
        *,
        turn_id: str,
        cwd: str | os.PathLike[str] | None = None,
    ) -> tuple[BaselineSnapshot, ...]:
        """Capture every path a supported Hermes mutation call may touch.

        All errors fail open. Repeated calls in the same turn return the original
        snapshot and never replace it with post-mutation state.
        """

        try:
            if not isinstance(turn_id, str) or not turn_id:
                return ()
            raw_paths = _tool_paths(tool_name, args)
            if not raw_paths:
                return ()
            with self._lock:
                turn = self._turns.setdefault(turn_id, {})
                snapshots: list[BaselineSnapshot] = []
                for raw_path in raw_paths:
                    path = _resolve_path(raw_path, cwd)
                    key = os.path.normcase(str(path))
                    snapshot = turn.get(key)
                    if snapshot is None:
                        snapshot = self._capture(path)
                        turn[key] = snapshot
                    snapshots.append(snapshot)
            return tuple(snapshots)
        except Exception:
            return ()

    def _capture(self, path: Path) -> BaselineSnapshot:
        display = str(path)
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            return BaselineSnapshot(display, "missing", ())
        except OSError:
            return BaselineSnapshot(display, "inaccessible", ())
        if size > self.max_bytes:
            return BaselineSnapshot(display, "oversized", ())
        try:
            with path.open("rb") as handle:
                data = handle.read(self.max_bytes + 1)
        except FileNotFoundError:
            return BaselineSnapshot(display, "missing", ())
        except OSError:
            return BaselineSnapshot(display, "inaccessible", ())
        if len(data) > self.max_bytes:
            return BaselineSnapshot(display, "oversized", ())
        if b"\x00" in data:
            return BaselineSnapshot(display, "binary", ())
        try:
            source = _decode_python(data)
        except (LookupError, UnicodeError, SyntaxError):
            return BaselineSnapshot(display, "inaccessible", ())
        stubs = find_stubs(source, filename=display) if path.suffix.lower() == ".py" else ()
        return BaselineSnapshot(display, "ok", stubs, find_secrets(source))

    def compare(
        self,
        turn_id: str,
        path: str | os.PathLike[str],
        current_source: str,
        *,
        cwd: str | os.PathLike[str] | None = None,
    ) -> BaselineComparison:
        """Return stubs newly introduced since this turn's initial snapshot."""

        try:
            resolved = _resolve_path(path, cwd)
            display = str(resolved)
            key = os.path.normcase(display)
            with self._lock:
                snapshot = self._turns.get(turn_id, {}).get(key)
            if snapshot is None:
                return BaselineComparison(display, "uncaptured", ())
            if snapshot.status not in _TRUSTED_BASELINES or not isinstance(current_source, str):
                return BaselineComparison(display, "indeterminate", ())
            current = find_stubs(current_source, filename=display) if resolved.suffix.lower() == ".py" else ()
            existing = Counter((item.qualified_name, item.kind) for item in snapshot.findings)
            introduced: list[StubFinding] = []
            for finding in current:
                identity = (finding.qualified_name, finding.kind)
                if existing[identity]:
                    existing[identity] -= 1
                else:
                    introduced.append(finding)
            existing_secrets = Counter((item.kind, item.fingerprint) for item in snapshot.secrets)
            introduced_secrets: list[SecretFinding] = []
            for finding in find_secrets(current_source):
                identity = (finding.kind, finding.fingerprint)
                if existing_secrets[identity]:
                    existing_secrets[identity] -= 1
                else:
                    introduced_secrets.append(finding)
            return BaselineComparison(display, "ok", tuple(introduced), tuple(introduced_secrets))
        except Exception:
            try:
                display = str(path)
            except Exception:
                display = "<unknown>"
            return BaselineComparison(display, "indeterminate", ())

    def discard_turn(self, turn_id: str) -> None:
        """Release one completed turn without touching any other turn."""

        with self._lock:
            self._turns.pop(turn_id, None)
