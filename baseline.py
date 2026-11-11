"""Turn-isolated snapshots taken before Hermes mutates supported files.

Three properties matter for the host and are enforced here:

* the shared lock only ever guards dictionary state, never filesystem access;
* every filesystem call runs on a deadline-bounded daemon worker, so a stalled
  read costs the hook its time budget rather than Hermes's fail-closed
  ``pre_tool_call`` timeout; and
* paths are spelled the way Hermes's own file tools spell them, so a baseline
  key matches the ``changed_paths`` entry Hermes reports later.
"""

from __future__ import annotations

import io
import ntpath
import os
import posixpath
import re
import stat
import threading
import tokenize
from collections import Counter
from typing import Any, Callable, NamedTuple, Sequence

try:
    from .secrets import SecretFinding, find_secrets
    from .stubs import StubFinding, find_stubs
except ImportError:  # Direct module loading in the isolated test suite.
    from secrets import SecretFinding, find_secrets
    from stubs import StubFinding, find_stubs


DEFAULT_MAX_BYTES = 1024 * 1024
MAX_PATHS_PER_CALL = 32
MAX_PATHS_PER_TURN = 512
MAX_TURNS = 64
IO_BUDGET_SECONDS = 4.0
MAX_STALLED_WORKERS = 2

SCANNABLE_SUFFIXES = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".json", ".yaml", ".yml", ".toml", ".env", ".ini", ".cfg", ".conf"}
)
_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
_TRUSTED_BASELINES = frozenset({"ok", "missing"})

_IS_WINDOWS = os.name == "nt"
_MAX_PATH_CHARS = 4096
_MAX_HEADER_CHARS = 8192
_READ_CHUNK = 64 * 1024

# Hermes v0.23 V4A headers (tools/patch_parser.py, tools/file_tools.py):
# ``*** Update File: p``, ``*** Add File: p``, ``*** Delete File: p`` and
# ``*** Move File: src -> dst``. The space after ``***`` is optional there too.
# Only the fixed prefix is matched by regex; the remainder is split by hand so a
# hostile header line cannot trigger quadratic backtracking inside the hook.
_V4A_HEADER_RE = re.compile(r"\*\*\*\s*(Update|Add|Delete|Move)\s+File:")
# Git Bash / Cygwin / WSL drive spellings, as tools/environments/local.py maps them.
_MSYS_DRIVE_RE = re.compile(r"^/(?:(?:cygdrive|mnt)/)?([a-zA-Z])(/.*)?$")
_WINDOWS_RESERVED_CHARS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{c}" for c in "123456789\xb9\xb2\xb3"}
    | {f"LPT{c}" for c in "123456789\xb9\xb2\xb3"}
)
# FILE_ATTRIBUTE_OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS: opening such a
# cloud placeholder makes Windows fetch it over the network, so it is never opened.
_WINDOWS_RECALL_ATTRIBUTES = 0x1000 | 0x40000 | 0x400000


class BaselineSnapshot(NamedTuple):
    """The first observed state of one path in one coding turn."""

    path: str
    status: str
    findings: tuple[StubFinding, ...]
    secrets: tuple[SecretFinding, ...] = ()


class BaselineComparison(NamedTuple):
    """New findings relative to a captured initial state.

    ``status`` is ``ok`` (compared against a trusted baseline), ``uncaptured``
    (no baseline exists for the path in this turn), or ``indeterminate`` (a
    baseline exists but cannot be trusted). ``reason`` names why a comparison
    was not possible; it never contains file content.
    """

    path: str
    status: str
    findings: tuple[StubFinding, ...]
    secrets: tuple[SecretFinding, ...] = ()
    reason: str = ""


class FileRead(NamedTuple):
    """Outcome of one bounded read; ``text`` is set only when ``status == "ok"``."""

    status: str
    text: str = ""


class ToolOperation(NamedTuple):
    """One mutation target; ``destination`` is set only for ``Move File``."""

    path: str
    destination: str | None = None


# --------------------------------------------------------------------------
# Tool-call parsing
# --------------------------------------------------------------------------


def _v4a_operations(patch_text: str) -> list[ToolOperation]:
    operations: list[ToolOperation] = []
    for line in patch_text.split("\n"):
        if not line.startswith("***") or len(line) > _MAX_HEADER_CHARS:
            continue
        match = _V4A_HEADER_RE.match(line)
        if match is None:
            continue
        rest = line[match.end():]
        if match.group(1) == "Move":
            source, arrow, destination = rest.partition("->")
            source, destination = source.strip(), destination.strip()
            if arrow and source and destination:
                operations.append(ToolOperation(source, destination))
        elif rest.strip():
            operations.append(ToolOperation(rest.strip()))
    return operations


def tool_operations(tool_name: str, args: Any) -> tuple[tuple[ToolOperation, ...], bool]:
    """Return the paths a Hermes ``write_file``/``patch`` call targets.

    The result is capped at ``MAX_PATHS_PER_CALL`` distinct path spellings; the
    boolean reports whether anything was dropped by that cap.
    """

    if not isinstance(args, dict):
        return (), False
    operations: list[ToolOperation] = []
    if tool_name == "write_file":
        if isinstance(args.get("path"), str) and args["path"].strip():
            operations.append(ToolOperation(args["path"].strip()))
    elif tool_name == "patch":
        mode = args.get("mode") or "replace"
        if mode == "patch":
            patch_text = args.get("patch")
            if isinstance(patch_text, str):
                operations = _v4a_operations(patch_text)
        elif mode == "replace":
            if isinstance(args.get("path"), str) and args["path"].strip():
                operations.append(ToolOperation(args["path"].strip()))
    kept: list[ToolOperation] = []
    seen: set[str] = set()
    truncated = False
    for operation in operations:
        fresh = {path for path in operation if path is not None} - seen
        if len(seen) + len(fresh) > MAX_PATHS_PER_CALL:
            truncated = True
            continue
        seen |= fresh
        kept.append(operation)
    return tuple(kept), truncated


# --------------------------------------------------------------------------
# Lexical path handling (no filesystem access)
# --------------------------------------------------------------------------


class SessionCwd:
    """Resolve the session working directory lazily and at most once.

    The source is a value or a zero-argument callable (``ctx.session_cwd``).
    Absolute tool paths never trigger resolution. Any failure, an empty answer,
    or a non-absolute answer yields ``None`` so relative paths fail open; the
    process working directory is deliberately never consulted.

    ``get`` must run on the hook's own thread: Hermes identifies the calling
    session from that thread's context, in-process and in the plugin host alike.
    """

    def __init__(self, source: Any) -> None:
        self._source = source
        self._resolved = False
        self._value: str | None = None

    def get(self) -> str | None:
        if not self._resolved:
            self._resolved = True
            try:
                value = self._source() if callable(self._source) else self._source
                text = os.fspath(value) if value is not None else None
                self._value = text if isinstance(text, str) and text.strip() else None
            except Exception:
                self._value = None
        return self._value


def _host_text(raw: Any, windows: bool) -> str | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text or len(text) > _MAX_PATH_CHARS or "\x00" in text:
        return None
    if windows:
        match = _MSYS_DRIVE_RE.match(text)
        if match:
            tail = (match.group(2) or "").replace("/", "\\")
            text = f"{match.group(1).upper()}:{tail or chr(92)}"
    if text.startswith("~"):
        expanded = os.path.expanduser(text)
        if expanded.startswith("~"):
            return None
        text = expanded
    return text


def _path_kind(text: str, windows: bool) -> str:
    if not windows:
        return "absolute" if text.startswith("/") else "relative"
    drive, tail = ntpath.splitdrive(text)
    rooted = tail[:1] in ("\\", "/")
    if drive and rooted:
        return "absolute"
    if not drive and not rooted:
        return "relative"
    # ``C:name`` and ``\name`` depend on per-drive process state: unsupported.
    return "unsupported"


def _windows_unsafe(text: str) -> bool:
    """True for UNC and device namespaces, reserved device names and stream syntax.

    Every ``\\\\``-prefixed path is refused: ``\\\\.\\`` and ``\\\\?\\`` reach devices
    and pipes, and ``\\\\host\\share`` makes Windows open a network connection to a
    host named by the tool call, which this plugin must never initiate.
    """

    if text.startswith("\\\\"):
        return True
    _, tail = ntpath.splitdrive(text)
    for part in tail.split("\\"):
        if not part:
            continue
        if part.endswith((".", " ")):
            return True
        if any(char in _WINDOWS_RESERVED_CHARS or ord(char) < 32 for char in part):
            return True
        if part.partition(".")[0].rstrip(" ").upper() in _WINDOWS_RESERVED_NAMES:
            return True
    return False


def lexical_absolute(raw: Any, cwd: Any = None, *, windows: bool = _IS_WINDOWS) -> str | None:
    """Spell *raw* as Hermes's host file tools would, or ``None`` if unsupported.

    Mirrors ``tools/file_tools_paths.py``: Git Bash drive paths become native
    drive paths on Windows, ``~`` is expanded, and a relative path is joined to
    the session working directory. Windows results are normalized lexically
    (Hermes does not dereference there); POSIX results are left for
    ``real_key`` because Hermes resolves symlinks there. Pure string work.
    """

    text = _host_text(raw, windows)
    if text is None:
        return None
    pathmod = ntpath if windows else posixpath
    kind = _path_kind(text, windows)
    if kind == "relative":
        session = cwd if isinstance(cwd, SessionCwd) else SessionCwd(cwd)
        base = _host_text(session.get(), windows)
        if base is None or _path_kind(base, windows) != "absolute":
            return None
        text = pathmod.join(base, text)
    elif kind != "absolute":
        return None
    if windows:
        text = ntpath.normpath(text)
        if _windows_unsafe(text):
            return None
    return text


def path_suffix(text: str, *, windows: bool = _IS_WINDOWS) -> str:
    pathmod = ntpath if windows else posixpath
    basename = pathmod.basename(text)
    # ``splitext('.env')`` is intentionally empty on every supported host, but
    # an exact dotenv file is an approved path-level release risk. Keep variants
    # such as ``.env.local`` out of scope.
    if basename.lower() == ".env":
        return ".env"
    return pathmod.splitext(basename)[1].lower()


def is_dotenv_path(text: str, *, windows: bool = _IS_WINDOWS) -> bool:
    """Return whether *text* names the exact ``.env`` file."""

    pathmod = ntpath if windows else posixpath
    return pathmod.basename(text).lower() == ".env"


# --------------------------------------------------------------------------
# Filesystem access (call only from a BoundedIO worker)
# --------------------------------------------------------------------------


def real_key(absolute: str) -> tuple[str, str]:
    """Return ``(real_path, comparison_key)`` for a lexically absolute path."""

    try:
        real = os.path.realpath(absolute)
    except (OSError, ValueError):
        real = absolute
    return real, os.path.normcase(real)


def is_regular_file(path: str) -> bool:
    try:
        return stat.S_ISREG(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def regular_file_status(path: str) -> str:
    """Classify a path using metadata only, without opening or reading it."""

    try:
        info = os.stat(path)
    except (FileNotFoundError, NotADirectoryError):
        return "missing"
    except (OSError, ValueError):
        return "inaccessible"
    if not stat.S_ISREG(info.st_mode):
        return "not_regular"
    if getattr(info, "st_file_attributes", 0) & _WINDOWS_RECALL_ATTRIBUTES:
        return "offline"
    return "ok"


def _checked(info: os.stat_result, max_bytes: int) -> str | None:
    if not stat.S_ISREG(info.st_mode):
        return "not_regular"
    if getattr(info, "st_file_attributes", 0) & _WINDOWS_RECALL_ATTRIBUTES:
        return "offline"
    if info.st_size > max_bytes:
        return "oversized"
    return None


def read_text_bounded(path: str, max_bytes: int) -> FileRead:
    """Read at most ``max_bytes + 1`` bytes of one regular file.

    The type is checked with ``stat`` before opening and again with ``fstat``
    on the opened descriptor, so FIFOs, sockets, devices and directories are
    never read even if the path is swapped in between. ``O_NONBLOCK`` keeps a
    FIFO that appears in that window from blocking ``open``. It does not make
    regular-file I/O on a stalled network or FUSE mount return, which is why
    callers also run this under ``BoundedIO``.
    """

    try:
        problem = _checked(os.stat(path), max_bytes)
    except (FileNotFoundError, NotADirectoryError):
        return FileRead("missing")
    except (OSError, ValueError):
        return FileRead("inaccessible")
    if problem:
        return FileRead(problem)
    flags = os.O_RDONLY
    for name in ("O_BINARY", "O_NONBLOCK", "O_NOCTTY", "O_CLOEXEC", "O_NOINHERIT"):
        flags |= getattr(os, name, 0)
    try:
        descriptor = os.open(path, flags)
    except (FileNotFoundError, NotADirectoryError):
        return FileRead("missing")
    except (OSError, ValueError):
        return FileRead("inaccessible")
    chunks: list[bytes] = []
    try:
        problem = _checked(os.fstat(descriptor), max_bytes)
        if problem:
            return FileRead(problem)
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(remaining, _READ_CHUNK))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    except (OSError, ValueError):
        return FileRead("inaccessible")
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    data = b"".join(chunks)
    if len(data) > max_bytes:
        return FileRead("oversized")
    if b"\x00" in data:
        return FileRead("binary")
    try:
        if path_suffix(path) in _PYTHON_SUFFIXES:
            encoding, _ = tokenize.detect_encoding(io.BytesIO(data).readline)
            return FileRead("ok", data.decode(encoding))
        return FileRead("ok", data.decode("utf-8"))
    except (LookupError, UnicodeError, SyntaxError):
        return FileRead("undecodable")


class BoundedIO:
    """Run blocking work on a daemon thread under a wall-clock budget.

    A worker that misses the budget is abandoned, never joined, and its late
    results are discarded. At most ``max_stalled`` workers may be alive at
    once; a dead mount therefore cannot accumulate threads even when hook calls
    arrive concurrently.
    """

    def __init__(self, *, budget: float = IO_BUDGET_SECONDS, max_stalled: int = MAX_STALLED_WORKERS) -> None:
        self.budget = max(0.0, float(budget))
        self.max_stalled = max(1, int(max_stalled))
        self._stalled = 0
        self._active = 0
        self._lock = threading.Lock()

    @property
    def stalled(self) -> int:
        with self._lock:
            return self._stalled

    def run(self, function: Callable[[Any], Any], items: Sequence[Any], *, budget: float | None = None) -> list[Any]:
        """Apply *function* to each item; unfinished or failed items are ``None``."""

        limit = self.budget if budget is None else max(0.0, float(budget))
        results: list[Any] = [None] * len(items)
        if not items:
            return results
        with self._lock:
            # Reserve capacity before starting the thread. Checking only the
            # abandoned-worker count lets simultaneous calls all pass the check
            # and later exceed the advertised global cap when they stall.
            if self._active >= self.max_stalled:
                return results
            self._active += 1
        guard = threading.Lock()
        done = threading.Event()
        state = {"cancelled": False, "abandoned": False}

        def work() -> None:
            try:
                for index, item in enumerate(items):
                    with guard:
                        if state["cancelled"]:
                            return
                    try:
                        value = function(item)
                    except Exception:
                        value = None
                    with guard:
                        if state["cancelled"]:
                            return
                        results[index] = value
            finally:
                with self._lock:
                    done.set()
                    self._active -= 1
                    if state["abandoned"]:
                        self._stalled -= 1

        try:
            threading.Thread(target=work, name="truthgate-io", daemon=True).start()
        except RuntimeError:
            with self._lock:
                self._active -= 1
            return results
        if done.wait(limit):
            return results
        with guard:
            state["cancelled"] = True
            partial = list(results)
        with self._lock:
            if not done.is_set():
                state["abandoned"] = True
                self._stalled += 1
        return partial


# --------------------------------------------------------------------------
# Baseline state
# --------------------------------------------------------------------------


class _Turn:
    __slots__ = ("snapshots", "moves")

    def __init__(self) -> None:
        self.snapshots: dict[str, BaselineSnapshot] = {}
        self.moves: set[tuple[str, str]] = set()


def _merge_move(destination: BaselineSnapshot, source: BaselineSnapshot | None) -> BaselineSnapshot:
    """Baseline for a move destination: whatever either side already contained."""

    if destination.status not in _TRUSTED_BASELINES:
        return destination
    if source is None:
        return BaselineSnapshot(destination.path, "move_source_unknown", ())
    if source.status not in _TRUSTED_BASELINES:
        return BaselineSnapshot(destination.path, source.status, ())
    return BaselineSnapshot(
        destination.path,
        "ok",
        destination.findings + source.findings,
        destination.secrets + source.secrets,
    )


class BaselineStore:
    """Capture-once baseline state partitioned by Hermes ``turn_id``."""

    def __init__(
        self,
        *,
        max_bytes: int = DEFAULT_MAX_BYTES,
        io: BoundedIO | None = None,
    ) -> None:
        self.max_bytes = max(0, int(max_bytes))
        self.io = io if io is not None else BoundedIO()
        self._turns: dict[str, _Turn] = {}
        self._lock = threading.Lock()

    def capture_tool_call(
        self,
        tool_name: str,
        args: Any,
        *,
        turn_id: str,
        cwd: Any = None,
    ) -> tuple[BaselineSnapshot, ...]:
        """Capture every scannable path a supported Hermes mutation call targets.

        All errors fail open. Repeated calls in the same turn return the original
        snapshot and never replace it with post-mutation state. Paths that are
        unsupported, unscannable, over a limit, or not inspected within the I/O
        budget get no baseline and are later reported as ``uncaptured``.
        """

        try:
            if not isinstance(turn_id, str) or not turn_id:
                return ()
            operations, _ = tool_operations(tool_name, args)
            if not operations:
                return ()
            session = cwd if isinstance(cwd, SessionCwd) else SessionCwd(cwd)
            targets: dict[str, str | None] = {}
            for operation in operations:
                for raw in operation:
                    if raw is None or raw in targets:
                        continue
                    absolute = lexical_absolute(raw, session)
                    scannable = absolute is not None and path_suffix(absolute) in SCANNABLE_SUFFIXES
                    targets[raw] = absolute if scannable else None
            wanted = list(dict.fromkeys(path for path in targets.values() if path is not None))
            outcomes = self.io.run(lambda absolute: self._inspect(turn_id, absolute), wanted)
            inspected = {absolute: outcome for absolute, outcome in zip(wanted, outcomes) if outcome is not None}

            ordered: list[BaselineSnapshot] = []
            with self._lock:
                turn = self._turn(turn_id)
                keys: dict[str, str] = {}
                for raw, absolute in targets.items():
                    if absolute is None or absolute not in inspected:
                        continue
                    key, snapshot = inspected[absolute]
                    if key not in turn.snapshots:
                        if len(turn.snapshots) >= MAX_PATHS_PER_TURN:
                            continue
                        turn.snapshots[key] = snapshot
                    keys[raw] = key
                for operation in operations:
                    if operation.destination is None:
                        continue
                    destination_key = keys.get(operation.destination)
                    if destination_key is None:
                        continue
                    source_key = keys.get(operation.path)
                    move = (source_key or "", destination_key)
                    if source_key == destination_key or move in turn.moves:
                        continue
                    turn.moves.add(move)
                    source = turn.snapshots.get(source_key) if source_key else None
                    destination = turn.snapshots[destination_key]
                    if source is not None and path_suffix(destination.path) == ".py" != path_suffix(source.path):
                        source = None  # Stubs were never computed for a non-Python source.
                    turn.snapshots[destination_key] = _merge_move(destination, source)
                for raw in targets:
                    key = keys.get(raw)
                    if key is not None:
                        ordered.append(turn.snapshots[key])
            return tuple(ordered)
        except Exception:
            return ()

    def _turn(self, turn_id: str) -> _Turn:
        turn = self._turns.get(turn_id)
        if turn is None:
            while len(self._turns) >= MAX_TURNS:
                self._turns.pop(next(iter(self._turns)))
            turn = self._turns[turn_id] = _Turn()
        return turn

    def _inspect(self, turn_id: str, absolute: str) -> tuple[str, BaselineSnapshot]:
        """Worker-side: resolve one path and read it unless already captured."""

        real, key = real_key(absolute)
        existing = self.lookup(turn_id, key)
        if existing is not None:
            return key, existing
        return key, self._snapshot(real)

    def _snapshot(self, real: str) -> BaselineSnapshot:
        if is_dotenv_path(real):
            # Creation of an exact .env is itself the finding. Record only
            # whether it existed before the tool call; never open its contents.
            return BaselineSnapshot(real, regular_file_status(real), ())
        read = read_text_bounded(real, self.max_bytes)
        if read.status != "ok":
            return BaselineSnapshot(real, read.status, ())
        stubs = find_stubs(read.text, filename=real) if path_suffix(real) == ".py" else ()
        return BaselineSnapshot(real, "ok", stubs, find_secrets(read.text))

    def lookup(self, turn_id: str, key: str) -> BaselineSnapshot | None:
        with self._lock:
            turn = self._turns.get(turn_id)
            return turn.snapshots.get(key) if turn is not None else None

    def compare_key(self, turn_id: str, key: str, display: str, current_source: str) -> BaselineComparison:
        """Return findings newly introduced since this turn's initial snapshot."""

        try:
            snapshot = self.lookup(turn_id, key)
            if snapshot is None:
                return BaselineComparison(display, "uncaptured", (), (), "no_baseline")
            if snapshot.status not in _TRUSTED_BASELINES:
                return BaselineComparison(display, "indeterminate", (), (), snapshot.status)
            if not isinstance(current_source, str):
                return BaselineComparison(display, "indeterminate", (), (), "invalid_source")
            current = find_stubs(current_source, filename=display) if path_suffix(display) == ".py" else ()
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
            for secret in find_secrets(current_source):
                secret_identity = (secret.kind, secret.fingerprint)
                if existing_secrets[secret_identity]:
                    existing_secrets[secret_identity] -= 1
                else:
                    introduced_secrets.append(secret)
            return BaselineComparison(display, "ok", tuple(introduced), tuple(introduced_secrets))
        except Exception:
            return BaselineComparison(str(display), "indeterminate", (), (), "internal_error")

    def compare(
        self,
        turn_id: str,
        path: str | os.PathLike[str],
        current_source: str,
        *,
        cwd: Any = None,
    ) -> BaselineComparison:
        """Path-based convenience wrapper around :meth:`compare_key`.

        Resolves the path on the calling thread; hook code uses ``compare_key``
        from a bounded worker instead.
        """

        try:
            absolute = lexical_absolute(os.fspath(path), cwd)
            if absolute is None:
                return BaselineComparison(str(path), "indeterminate", (), (), "unsupported_path")
            real, key = real_key(absolute)
            return self.compare_key(turn_id, key, real, current_source)
        except Exception:
            try:
                display = str(path)
            except Exception:
                display = "<unknown>"
            return BaselineComparison(display, "indeterminate", (), (), "internal_error")

    def discard_turn(self, turn_id: str) -> None:
        """Release one completed turn without touching any other turn."""

        with self._lock:
            self._turns.pop(turn_id, None)
