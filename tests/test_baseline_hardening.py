"""Regression tests for the 0.2.1 hardening of baseline capture."""

import os
import stat as stat_module
import threading
import time
import types
from pathlib import Path

from truthgate import baseline


STUB = "def old_stub():\n    pass\n"


def finding_names(comparison):
    return [(finding.qualified_name, finding.kind) for finding in comparison.findings]


def op_paths(patch_text):
    operations, truncated = baseline.tool_operations("patch", {"mode": "patch", "patch": patch_text})
    return [tuple(operation) for operation in operations], truncated


def refuse(message):
    def raiser(*args, **kwargs):
        raise AssertionError(message)

    return raiser


# --- HIGH-2: Hermes V4A headers, moves, and path spelling -----------------


def test_hermes_v4a_headers_and_whitespace_variants_are_recognized():
    patch_text = (
        "*** Begin Patch\r\n"
        "*** Update File: a.py\r\n"
        "@@\r\n"
        "***Add File:b.py\n"
        "***   Delete   File:   c.py   \n"
        "*** Move File: old/d.py -> new/d.py\n"
        "***Move  File:e.py->f.py\n"
        "*** End Patch\n"
    )

    assert op_paths(patch_text) == (
        [("a.py", None), ("b.py", None), ("c.py", None), ("old/d.py", "new/d.py"), ("e.py", "f.py")],
        False,
    )


def test_lines_that_are_not_hermes_headers_are_ignored():
    patch_text = (
        "*** Update File: real.py\n"
        "*** Move to: codex_style.py\n"  # Not a Hermes header.
        "+*** Add File: quoted_in_content.py\n"
        " *** Delete File: indented.py\n"
        "*** Move File: missing_arrow.py\n"
        "*** Move File:  -> no_source.py\n"
        "*** Rename File: other.py\n"
    )

    assert op_paths(patch_text) == ([("real.py", None)], False)


def test_tool_modes_match_hermes_dispatch():
    assert baseline.tool_operations("write_file", {"path": " a.py ", "mode": "patch", "patch": "x"})[0] == (
        baseline.ToolOperation("a.py"),
    )
    assert baseline.tool_operations("patch", {"mode": None, "path": "b.py"})[0] == (baseline.ToolOperation("b.py"),)
    assert baseline.tool_operations("patch", {"mode": "other", "path": "b.py"})[0] == ()
    assert baseline.tool_operations("terminal", {"path": "b.py"})[0] == ()


def test_hostile_header_line_is_parsed_in_linear_time():
    patch_text = "*** Move File: " + " " * 200_000 + "\n" + "*** Update File: " + "a" * 100_000 + "\n"
    started = time.perf_counter()
    operations, _ = op_paths(patch_text)

    assert operations == []
    assert time.perf_counter() - started < 1.0


def test_paths_per_call_are_capped():
    patch_text = "".join(f"*** Add File: file_{index}.py\n" for index in range(baseline.MAX_PATHS_PER_CALL + 8))
    operations, truncated = op_paths(patch_text)

    assert len(operations) == baseline.MAX_PATHS_PER_CALL
    assert truncated is True


def test_exact_dotenv_is_scannable_without_expanding_dotenv_scope():
    assert baseline.path_suffix(".env") == ".env"
    assert baseline.path_suffix("config/.env") == ".env"
    assert baseline.path_suffix(".env.local") == ".local"
    assert baseline.path_suffix(".env.example") == ".example"


def test_existing_dotenv_baseline_reads_metadata_only(tmp_path, monkeypatch):
    target = tmp_path / ".env"
    target.write_text("API_KEY=do-not-read-this-value\n", encoding="utf-8")
    monkeypatch.setattr(baseline, "read_text_bounded", refuse("dotenv contents must not be read"))
    store = baseline.BaselineStore()

    captured = store.capture_tool_call("write_file", {"path": str(target)}, turn_id="turn-a")

    assert [item.status for item in captured] == ["ok"]
    assert captured[0].findings == ()
    assert captured[0].secrets == ()


def test_move_destination_inherits_the_source_baseline(tmp_path):
    (tmp_path / "legacy.py").write_text(STUB, encoding="utf-8")
    store = baseline.BaselineStore()
    patch_text = "*** Begin Patch\n*** Move File: legacy.py -> renamed.py\n*** End Patch\n"

    for _ in range(2):  # A retried call must not change the result.
        captured = store.capture_tool_call(
            "patch", {"mode": "patch", "patch": patch_text}, turn_id="turn-a", cwd=tmp_path
        )

    assert [Path(item.path).name for item in captured] == ["legacy.py", "renamed.py"]
    moved = STUB + "\ndef new_stub():\n    pass\n"
    assert finding_names(store.compare("turn-a", tmp_path / "renamed.py", moved)) == [("new_stub", "pass")]


def test_move_uses_the_turn_initial_state_of_the_source(tmp_path):
    source = tmp_path / "fresh.py"
    store = baseline.BaselineStore()
    store.capture_tool_call("write_file", {"path": str(source)}, turn_id="turn-a")
    source.write_text(STUB, encoding="utf-8")  # Hermes creates the file with a stub this turn.

    store.capture_tool_call(
        "patch", {"mode": "patch", "patch": f"*** Move File: {source} -> {tmp_path / 'moved.py'}\n"}, turn_id="turn-a"
    )

    assert finding_names(store.compare("turn-a", tmp_path / "moved.py", STUB)) == [("old_stub", "pass")]


def test_move_from_an_unknown_source_makes_the_destination_indeterminate(tmp_path):
    (tmp_path / "notes.txt").write_text(STUB, encoding="utf-8")
    store = baseline.BaselineStore()

    store.capture_tool_call(
        "patch", {"mode": "patch", "patch": "*** Move File: notes.txt -> module.py\n"}, turn_id="turn-a", cwd=tmp_path
    )
    result = store.compare("turn-a", tmp_path / "module.py", STUB)

    assert result.status == "indeterminate"
    assert result.reason == "move_source_unknown"
    assert result.findings == ()


def test_git_bash_drive_paths_follow_hermes_on_windows_only():
    def win(raw, cwd=None):
        return baseline.lexical_absolute(raw, cwd, windows=True)

    assert win("/c/Users/dev/app.py") == "C:\\Users\\dev\\app.py"
    assert win("/cygdrive/d/work/app.py") == "D:\\work\\app.py"
    assert win("/mnt/e/work/app.py") == "E:\\work\\app.py"
    assert win("C:/Users/dev/./pkg/../app.py") == "C:\\Users\\dev\\app.py"
    assert win("src/app.py", "/c/Users/dev") == "C:\\Users\\dev\\src\\app.py"
    assert win("src\\app.py", "C:\\Users\\dev") == "C:\\Users\\dev\\src\\app.py"
    # A rooted path without a drive is not a drive path and is never guessed.
    assert win("/home/dev/app.py") is None
    assert win("\\Users\\dev\\app.py") is None
    assert win("C:app.py") is None
    # POSIX hosts keep single-letter top-level directories untouched.
    assert baseline.lexical_absolute("/c/Users/dev/app.py", windows=False) == "/c/Users/dev/app.py"
    assert baseline.lexical_absolute("src/app.py", "/work", windows=False) == "/work/src/app.py"


def test_windows_device_and_stream_paths_are_never_candidates():
    def win(raw):
        return baseline.lexical_absolute(raw, windows=True)

    for raw in (
        "\\\\.\\pipe\\agent.py",
        "\\\\?\\C:\\work\\app.py",
        "\\\\fileserver\\share\\app.py",  # UNC: would open a network connection.
        "//fileserver/share/app.py",
        "C:\\work\\NUL",
        "C:\\work\\con.py",
        "C:\\work\\COM1.py",
        "C:\\work\\app.py:stream",
        "C:\\work\\aux\\app.py",
        "C:\\work\\app.py.",
    ):
        assert win(raw) is None, raw
    assert win("C:\\work\\console.py") == "C:\\work\\console.py"
    # A relative path under a UNC session directory is refused as well.
    assert baseline.lexical_absolute("app.py", "\\\\fileserver\\share\\work", windows=True) is None


def test_baseline_key_matches_the_path_hermes_reports_as_changed(tmp_path):
    """Relative and Git Bash spellings land on Hermes's absolute ``changed_paths`` entry."""

    target = tmp_path / "pkg" / "service.py"
    target.parent.mkdir()
    target.write_text(STUB, encoding="utf-8")
    reported = os.path.normpath(str(target))  # tools/file_tools.py reports the resolved absolute path.
    spellings = ["pkg/service.py", "./pkg/../pkg/service.py", str(target)]
    if os.name == "nt":
        drive, tail = os.path.splitdrive(str(target))
        spellings.append("/" + drive[0].lower() + tail.replace("\\", "/"))

    for index, spelling in enumerate(spellings):
        store = baseline.BaselineStore()
        captured = store.capture_tool_call(
            "write_file", {"path": spelling}, turn_id=f"turn-{index}", cwd=str(tmp_path)
        )
        assert [item.status for item in captured] == ["ok"], spelling
        comparison = store.compare(f"turn-{index}", reported, STUB + "\ndef added():\n    ...\n")
        assert comparison.status == "ok", spelling
        assert finding_names(comparison) == [("added", "ellipsis")], spelling


# --- HIGH-3: session working directory ------------------------------------


def test_relative_paths_fail_open_without_an_absolute_session_cwd(tmp_path, monkeypatch):
    (tmp_path / "service.py").write_text(STUB, encoding="utf-8")
    monkeypatch.chdir(tmp_path)  # The process cwd must never be used as a fallback.
    store = baseline.BaselineStore()
    call = {"path": "service.py", "content": "ignored"}

    for cwd in (None, "", ".", "relative/dir", lambda: None, lambda: "", lambda: 1 / 0):
        assert store.capture_tool_call("write_file", call, turn_id="turn-a", cwd=cwd) == ()
    assert store.compare("turn-a", tmp_path / "service.py", STUB).status == "uncaptured"
    assert store.compare("turn-a", "service.py", STUB).status == "indeterminate"


def test_absolute_paths_never_resolve_the_session_cwd(tmp_path):
    calls = []

    def resolver():
        calls.append(1)
        raise AssertionError("cwd must not be resolved for an absolute path")

    store = baseline.BaselineStore()
    captured = store.capture_tool_call(
        "write_file", {"path": str(tmp_path / "absolute.py")}, turn_id="turn-a", cwd=resolver
    )

    assert [item.status for item in captured] == ["missing"]
    assert calls == []


def test_session_cwd_callable_is_resolved_once_per_call(tmp_path):
    calls = []

    def resolver():
        calls.append(1)
        return str(tmp_path)

    store = baseline.BaselineStore()
    patch_text = "*** Add File: a.py\n*** Add File: b.py\n*** Add File: c.py\n"
    captured = store.capture_tool_call("patch", {"mode": "patch", "patch": patch_text}, turn_id="turn-a", cwd=resolver)

    assert len(captured) == 3
    assert calls == [1]


# --- HIGH-1: bounded, non-blocking file access -----------------------------


def test_unscannable_paths_are_never_touched(tmp_path, monkeypatch):
    target = tmp_path / "blob.bin"
    target.write_bytes(b"data")
    monkeypatch.setattr(baseline.os, "open", refuse("must not open"))
    monkeypatch.setattr(baseline, "real_key", refuse("must not resolve"))
    store = baseline.BaselineStore()

    assert store.capture_tool_call("write_file", {"path": str(target)}, turn_id="turn-a") == ()
    assert store.capture_tool_call("write_file", {"path": "/dev/zero"}, turn_id="turn-a") == ()


def test_read_stops_at_limit_plus_one_even_when_size_is_misreported(tmp_path, monkeypatch):
    target = tmp_path / "growing.py"
    target.write_bytes(b"x" * 5000)
    fake = types.SimpleNamespace(st_mode=target.stat().st_mode, st_size=0)
    monkeypatch.setattr(baseline.os, "stat", lambda path: fake)
    monkeypatch.setattr(baseline.os, "fstat", lambda descriptor: fake)
    requested = []
    real_read = os.read

    def counting_read(descriptor, size):
        requested.append(size)
        return real_read(descriptor, size)

    monkeypatch.setattr(baseline.os, "read", counting_read)

    assert baseline.read_text_bounded(str(target), 100) == baseline.FileRead("oversized")
    assert sum(requested) == 101


def test_non_regular_files_are_rejected_before_any_read(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline.os, "read", refuse("must not read"))
    folder = tmp_path / "folder.py"
    folder.mkdir()

    assert baseline.read_text_bounded(str(folder), 1024).status == "not_regular"
    assert baseline.read_text_bounded(str(tmp_path / "absent.py"), 1024).status == "missing"
    if hasattr(os, "mkfifo"):
        fifo = tmp_path / "pipe.py"
        os.mkfifo(fifo)
        started = time.perf_counter()
        assert baseline.read_text_bounded(str(fifo), 1024).status == "not_regular"
        assert time.perf_counter() - started < 2


def test_file_swapped_for_a_non_regular_one_after_stat_is_not_read(tmp_path, monkeypatch):
    target = tmp_path / "swapped.py"
    target.write_text(STUB, encoding="utf-8")
    monkeypatch.setattr(
        baseline.os, "fstat", lambda descriptor: types.SimpleNamespace(st_mode=stat_module.S_IFIFO, st_size=0)
    )
    monkeypatch.setattr(baseline.os, "read", refuse("must not read"))

    assert baseline.read_text_bounded(str(target), 1024).status == "not_regular"


def test_cloud_placeholder_files_are_not_opened(tmp_path, monkeypatch):
    target = tmp_path / "online_only.py"
    target.write_text("x = 1\n", encoding="utf-8")
    info = target.stat()
    fake = types.SimpleNamespace(st_mode=info.st_mode, st_size=info.st_size, st_file_attributes=0x400000)
    monkeypatch.setattr(baseline.os, "stat", lambda path: fake)
    monkeypatch.setattr(baseline.os, "open", refuse("must not open"))

    assert baseline.read_text_bounded(str(target), 1024).status == "offline"


def test_stalled_read_costs_only_the_budget_and_holds_no_shared_lock(tmp_path, monkeypatch):
    release = threading.Event()
    entered = threading.Event()
    real_read = baseline.read_text_bounded

    def stalling_read(path, max_bytes):
        if path.endswith("stalled.py"):
            entered.set()
            release.wait(30)
        return real_read(path, max_bytes)

    monkeypatch.setattr(baseline, "read_text_bounded", stalling_read)
    healthy = tmp_path / "healthy.py"
    healthy.write_text(STUB, encoding="utf-8")
    store = baseline.BaselineStore(io=baseline.BoundedIO(budget=0.2, max_stalled=1))
    try:
        started = time.perf_counter()
        stalled = store.capture_tool_call("write_file", {"path": str(tmp_path / "stalled.py")}, turn_id="turn-a")
        elapsed = time.perf_counter() - started

        assert entered.is_set()
        assert stalled == ()
        assert elapsed < 5
        assert store.io.stalled == 1
        # State operations stay responsive while the worker is still blocked.
        started = time.perf_counter()
        assert store.lookup("turn-a", "anything") is None
        assert store.compare("turn-a", healthy, "x = 1\n").status == "uncaptured"
        store.discard_turn("turn-b")
        # At the stalled-worker cap no further I/O is attempted at all.
        assert store.capture_tool_call("write_file", {"path": str(healthy)}, turn_id="turn-a") == ()
        assert time.perf_counter() - started < 1
    finally:
        release.set()

    deadline = time.time() + 5
    while store.io.stalled and time.time() < deadline:
        time.sleep(0.01)
    assert store.io.stalled == 0
    # The abandoned worker's late answer was discarded, and I/O works again.
    assert store.compare("turn-a", tmp_path / "stalled.py", STUB).status == "uncaptured"
    recovered = store.capture_tool_call("write_file", {"path": str(healthy)}, turn_id="turn-a")
    assert [item.status for item in recovered] == ["ok"]


def test_simultaneous_timeouts_cannot_exceed_the_global_worker_cap():
    io = baseline.BoundedIO(budget=0.1, max_stalled=2)
    callers = 8
    start = threading.Barrier(callers + 1)
    release = threading.Event()
    entered = 0
    entered_lock = threading.Lock()

    def blocked(item):
        nonlocal entered
        with entered_lock:
            entered += 1
        release.wait(30)
        return item

    def run(index):
        start.wait()
        io.run(blocked, [index])

    threads = [threading.Thread(target=run, args=(index,)) for index in range(callers)]
    try:
        for thread in threads:
            thread.start()
        start.wait()
        for thread in threads:
            thread.join(2)

        assert all(not thread.is_alive() for thread in threads)
        assert entered == 2
        assert io.stalled == 2
    finally:
        release.set()


def test_retained_turns_and_paths_per_turn_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(baseline, "MAX_TURNS", 3)
    monkeypatch.setattr(baseline, "MAX_PATHS_PER_TURN", 2)
    store = baseline.BaselineStore()
    for index in range(5):
        store.capture_tool_call("write_file", {"path": str(tmp_path / "a.py")}, turn_id=f"turn-{index}")
    assert store.compare("turn-0", tmp_path / "a.py", "").status == "uncaptured"
    assert store.compare("turn-4", tmp_path / "a.py", "").status == "ok"

    patch_text = "".join(f"*** Add File: {tmp_path / f'f{index}.py'}\n" for index in range(4))
    captured = store.capture_tool_call("patch", {"mode": "patch", "patch": patch_text}, turn_id="turn-4")
    assert len(captured) == 1  # a.py already holds one of the two slots.
