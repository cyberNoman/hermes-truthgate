"""Regression tests for the 0.2.1 hardening of the Hermes hook layer."""

import importlib
import json
import os
import threading
import time
from pathlib import Path

from truthgate import baseline


gate_module = importlib.import_module("truthgate.gate")
store_module = importlib.import_module("truthgate.store")

STUB = "def unfinished():\n    pass\n"
ROOT = Path(__file__).resolve().parents[1]


def make_gate(tmp_path, cwd_resolver="default"):
    workspace = tmp_path / "workspace"
    workspace.mkdir(exist_ok=True)
    resolver = (lambda: str(workspace)) if cwd_resolver == "default" else cwd_resolver
    gate = gate_module.TruthGate(
        store_module.FindingStore(tmp_path / "state" / "findings.jsonl"), cwd_resolver=resolver
    )
    return gate, workspace


def call(gate, tool_name, args, turn_id="turn-1", session_id="session-1"):
    return gate.pre_tool_call(tool_name=tool_name, args=args, turn_id=turn_id, session_id=session_id)


def verify(gate, paths, attempt=0, session_id="session-1"):
    return gate.pre_verify(
        coding=True, attempt=attempt, session_id=session_id, changed_paths=[str(path) for path in paths]
    )


def records(gate):
    try:
        return [json.loads(line) for line in gate.store.path.read_text(encoding="utf-8").splitlines()]
    except FileNotFoundError:
        return []


# --- HIGH-2 ---------------------------------------------------------------


def test_relative_and_git_bash_spellings_match_hermes_changed_paths(tmp_path):
    gate, workspace = make_gate(tmp_path)
    relative = workspace / "pkg" / "relative.py"
    relative.parent.mkdir()
    spellings = {"pkg/relative.py": relative}
    if os.name == "nt":
        drive, tail = os.path.splitdrive(str(workspace / "bash.py"))
        spellings["/" + drive[0].lower() + tail.replace("\\", "/")] = workspace / "bash.py"

    for spelling, target in spellings.items():
        assert call(gate, "write_file", {"path": spelling, "content": STUB}) is None
        target.write_text(STUB, encoding="utf-8")
    # Hermes reports absolute, normalized paths in ``changed_paths``.
    result = verify(gate, [os.path.normpath(str(target)) for target in spellings.values()])

    assert result is not None and result["action"] == "continue"
    assert f"{os.path.join('pkg', 'relative.py')}:1 [stub/pass] function unfinished" in result["message"]
    if os.name == "nt":
        assert "bash.py:1 [stub/pass] function unfinished" in result["message"]
    assert all(record["event"] == "continuation" for record in records(gate))


def test_moved_file_reports_only_stubs_introduced_this_turn(tmp_path):
    gate, workspace = make_gate(tmp_path)
    (workspace / "legacy.py").write_text("def old_stub():\n    pass\n", encoding="utf-8")
    patch_text = "*** Begin Patch\n*** Move File: legacy.py -> renamed.py\n*** End Patch\n"
    call(gate, "patch", {"mode": "patch", "patch": patch_text})
    (workspace / "legacy.py").unlink()
    (workspace / "renamed.py").write_text("def old_stub():\n    pass\n", encoding="utf-8")
    changed = [workspace / "legacy.py", workspace / "renamed.py"]  # Hermes lists both sides.

    assert verify(gate, changed) is None
    assert records(gate) == []

    call(gate, "patch", {"mode": "patch", "patch": patch_text})
    (workspace / "renamed.py").write_text(
        "def old_stub():\n    pass\n\ndef new_stub():\n    ...\n", encoding="utf-8"
    )
    result = verify(gate, changed)

    assert result is not None
    assert "function new_stub" in result["message"]
    assert "old_stub" not in result["message"]


def test_missing_baseline_is_recorded_as_uncaptured_and_never_nudges(tmp_path):
    gate, workspace = make_gate(tmp_path)
    secret = "AKIA1234567890ABCDEF"
    unseen = workspace / "unseen.py"
    unseen.write_text(f'{STUB}KEY = "{secret}"\n', encoding="utf-8")
    call(gate, "write_file", {"path": "other.py"})  # Binds the turn; unseen.py has no baseline.
    deleted = workspace / "deleted.py"

    assert verify(gate, [unseen, deleted, workspace / "notes.bin"]) is None

    logged = records(gate)
    assert [(item["event"], item["path"], item["kind"], item["status"]) for item in logged] == [
        ("uncaptured", "unseen.py", "no_baseline", "unverified")
    ]
    assert set(logged[0]) == {"timestamp", "event", "session", "path", "line", "category", "kind", "status"}
    assert secret not in gate.store.path.read_text(encoding="utf-8")
    assert "uncaptured=1" in gate.status()


def test_new_exact_dotenv_is_reported_without_reading_or_persisting_contents(tmp_path, monkeypatch):
    gate, workspace = make_gate(tmp_path)
    target = workspace / ".env"
    sensitive = "API_KEY=do-not-read-or-log-this-value"
    call(gate, "write_file", {"path": ".env"})
    target.write_text(sensitive + "\n", encoding="utf-8")
    monkeypatch.setattr(gate_module, "read_text_bounded", lambda *args: 1 / 0)

    result = verify(gate, [target])

    assert result is not None and result["action"] == "continue"
    assert ".env:1 [secret/dotenv_file]" in result["message"]
    assert sensitive not in result["message"]
    persisted = gate.store.path.read_text(encoding="utf-8")
    assert sensitive not in persisted
    assert "do-not-read-or-log-this-value" not in persisted


def test_existing_exact_dotenv_is_not_reported_or_read(tmp_path, monkeypatch):
    gate, workspace = make_gate(tmp_path)
    target = workspace / ".env"
    target.write_text("API_KEY=existing-sensitive-value\n", encoding="utf-8")
    monkeypatch.setattr(baseline, "read_text_bounded", lambda *args: 1 / 0)
    monkeypatch.setattr(gate_module, "read_text_bounded", lambda *args: 1 / 0)
    call(gate, "write_file", {"path": ".env"})
    target.write_text("API_KEY=changed-sensitive-value\n", encoding="utf-8")

    assert verify(gate, [target]) is None
    assert records(gate) == []


def test_untrusted_baseline_is_uncaptured_and_reported_once_per_turn(tmp_path, monkeypatch):
    gate, workspace = make_gate(tmp_path)
    binary = workspace / "binary.py"
    binary.write_bytes(b"\x00\x01")
    fine = workspace / "fine.py"
    call(gate, "write_file", {"path": "binary.py"})
    call(gate, "write_file", {"path": "fine.py"})
    binary.write_text(STUB, encoding="utf-8")
    fine.write_text(STUB, encoding="utf-8")
    monkeypatch.setattr(gate_module, "read_text_bounded", baseline.read_text_bounded)

    first = verify(gate, [binary, fine])
    verify(gate, [binary, fine], attempt=1)

    assert first is not None and "binary.py" not in first["message"]
    uncaptured = [item for item in records(gate) if item["event"] == "uncaptured"]
    assert [(item["path"], item["kind"]) for item in uncaptured] == [("binary.py", "binary")]


def test_changed_path_limit_is_enforced_and_recorded(tmp_path, monkeypatch):
    monkeypatch.setattr(gate_module, "MAX_VERIFY_PATHS", 3)
    gate, workspace = make_gate(tmp_path)
    paths = []
    for index in range(5):
        path = workspace / f"m{index}.py"
        call(gate, "write_file", {"path": str(path)})
        path.write_text(STUB, encoding="utf-8")
        paths.append(path)

    result = verify(gate, paths)

    assert result is not None
    assert result["message"].count("[stub/pass]") == 3
    skipped = [item for item in records(gate) if item["event"] == "skipped"]
    assert [(item["kind"], item["line"], item["path"]) for item in skipped] == [("path_limit", 2, "")]


# --- HIGH-3 ---------------------------------------------------------------


def test_absolute_paths_work_without_any_cwd_api(tmp_path):
    gate, workspace = make_gate(tmp_path, cwd_resolver=None)
    target = workspace / "absolute.py"
    call(gate, "write_file", {"path": str(target)})
    target.write_text(STUB, encoding="utf-8")

    result = verify(gate, [target])

    assert result is not None
    assert "absolute.py:1 [stub/pass]" in result["message"]  # Basename only: no workspace is known.


def test_relative_paths_fail_open_when_cwd_is_unavailable(tmp_path, monkeypatch):
    def broken():
        raise RuntimeError("no session")

    for resolver in (None, broken, lambda: "", lambda: "relative"):
        gate, workspace = make_gate(tmp_path, cwd_resolver=resolver)
        monkeypatch.chdir(workspace)  # Must not be used as a stand-in for the session directory.
        target = workspace / "relative.py"
        assert call(gate, "write_file", {"path": "relative.py"}) is None
        target.write_text(STUB, encoding="utf-8")

        assert verify(gate, [target]) is None
        assert verify(gate, ["relative.py"]) is None
        gate.store.path.unlink()


def test_plugin_sources_use_only_the_supported_cwd_api():
    for name in ("__init__.py", "baseline.py", "gate.py", "store.py", "stubs.py", "secrets.py"):
        source = (ROOT / name).read_text(encoding="utf-8")
        assert "runtime_cwd" not in source, name
        assert "resolve_agent_cwd" not in source, name
        assert "getcwd" not in source and "Path.cwd" not in source, name


# --- HIGH-1 ---------------------------------------------------------------


def test_stalled_baseline_read_never_blocks_or_vetoes_the_tool(tmp_path, monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(baseline, "read_text_bounded", lambda path, limit: release.wait(30) and None)
    gate, workspace = make_gate(tmp_path)
    gate.baselines.io = baseline.BoundedIO(budget=0.2, max_stalled=1)
    try:
        started = time.perf_counter()
        outcomes = [call(gate, "write_file", {"path": f"slow{index}.py"}) for index in range(3)]
        elapsed = time.perf_counter() - started
    finally:
        release.set()

    assert outcomes == [None, None, None]  # Never a block directive.
    assert elapsed < 5


def test_stalled_verification_read_fails_open_and_is_recorded(tmp_path, monkeypatch):
    gate, workspace = make_gate(tmp_path)
    target = workspace / "slow.py"
    call(gate, "write_file", {"path": str(target)})
    target.write_text(STUB, encoding="utf-8")
    release = threading.Event()
    monkeypatch.setattr(gate_module, "read_text_bounded", lambda path, limit: release.wait(30) and None)
    gate.verify_budget = 0.2
    try:
        started = time.perf_counter()
        result = verify(gate, [target])
        elapsed = time.perf_counter() - started
    finally:
        release.set()

    assert result is None
    assert elapsed < 5
    assert [(item["event"], item["kind"], item["line"]) for item in records(gate)] == [("skipped", "not_inspected", 1)]


def test_hooks_never_raise_on_hostile_payloads(tmp_path):
    gate, workspace = make_gate(tmp_path)
    hostile = [
        {"path": "\x00.py"},
        {"path": "x" * 100_000 + ".py"},
        {"path": ["a.py"]},
        {"mode": "patch", "patch": "*** Move File: " + "-> " * 50_000},
        {"mode": "patch", "patch": "*** Update File: \\\\.\\pipe\\x.py\n*** Add File: NUL\n"},
        {"mode": "patch", "patch": None},
        None,
    ]
    for args in hostile:
        assert call(gate, "write_file", args) is None
        assert call(gate, "patch", args) is None
    assert gate.pre_tool_call(tool_name="patch", args={"path": "a.py"}, turn_id=5, session_id="s") is None
    assert verify(gate, ["\x00.py", "x" * 100_000 + ".py", "\\\\.\\pipe\\x.py"]) is None


def test_non_mutation_tools_do_no_work(tmp_path, monkeypatch):
    gate, workspace = make_gate(tmp_path, cwd_resolver=lambda: 1 / 0)
    monkeypatch.setattr(gate.baselines, "capture_tool_call", lambda *a, **k: 1 / 0)

    assert call(gate, "terminal", {"command": "echo hi"}) is None
    assert call(gate, "read_file", {"path": "a.py"}) is None
    assert gate._session_turn == {}


# --- Bounded state --------------------------------------------------------


def test_new_turn_discards_state_left_by_an_unfinished_turn(tmp_path):
    gate, workspace = make_gate(tmp_path)
    target = workspace / "demo.py"
    call(gate, "write_file", {"path": "demo.py"}, turn_id="turn-1")
    target.write_text(STUB, encoding="utf-8")
    assert verify(gate, [target]) is not None  # Turn 1 ends without another pre_verify.

    target.unlink()
    call(gate, "write_file", {"path": "demo.py"}, turn_id="turn-2")
    target.write_text(STUB, encoding="utf-8")

    assert gate.baselines.lookup("turn-1", baseline.real_key(str(target))[1]) is None
    assert verify(gate, [target]) is not None  # Not suppressed by turn 1's signature.


def test_tracked_sessions_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(gate_module, "MAX_SESSIONS", 4)
    gate, workspace = make_gate(tmp_path)
    for index in range(10):
        call(gate, "write_file", {"path": "demo.py"}, turn_id=f"turn-{index}", session_id=f"session-{index}")

    assert len(gate._session_turn) == 4
    assert len(gate.baselines._turns) == 4
