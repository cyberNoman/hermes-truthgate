from pathlib import Path

from truthgate import baseline


def finding_names(comparison):
    return [(finding.qualified_name, finding.kind) for finding in comparison.findings]


def test_write_file_captures_initial_baseline_only_once(tmp_path):
    target = tmp_path / "service.py"
    target.write_text("def existing():\n    pass\n", encoding="utf-8")
    store = baseline.BaselineStore()

    first = store.capture_tool_call(
        "write_file", {"path": "service.py", "content": "ignored"}, turn_id="turn-a", cwd=tmp_path
    )
    target.write_text("def existing():\n    return 1\n", encoding="utf-8")
    second = store.capture_tool_call(
        "write_file", {"path": "service.py", "content": "ignored again"}, turn_id="turn-a", cwd=tmp_path
    )

    assert first == second
    assert first[0].status == "ok"
    assert [(item.qualified_name, item.kind) for item in first[0].findings] == [("existing", "pass")]
    assert store.compare("turn-a", target, target.read_text(encoding="utf-8")).findings == ()


def test_missing_file_treats_all_later_stubs_as_new(tmp_path):
    target = tmp_path / "new_module.py"
    store = baseline.BaselineStore()
    captured = store.capture_tool_call(
        "write_file", {"path": str(target), "content": "ignored"}, turn_id="turn-a", cwd=tmp_path
    )

    comparison = store.compare("turn-a", target, "def introduced():\n    ...\n")

    assert captured[0].status == "missing"
    assert comparison.status == "ok"
    assert finding_names(comparison) == [("introduced", "ellipsis")]


def test_v4a_patch_captures_multiple_files_and_move_destination(tmp_path):
    one = tmp_path / "one.py"
    two = tmp_path / "two.py"
    destination = tmp_path / "moved.py"
    one.write_text("def one():\n    return 1\n", encoding="utf-8")
    two.write_text("def two():\n    return 2\n", encoding="utf-8")
    store = baseline.BaselineStore()
    patch_text = """*** Begin Patch
*** Update File: one.py
@@
*** Update File: two.py
*** Move to: moved.py
@@
*** Add File: added.py
*** End Patch
"""

    snapshots = store.capture_tool_call(
        "patch", {"mode": "patch", "patch": patch_text}, turn_id="turn-a", cwd=tmp_path
    )

    assert [Path(item.path).name for item in snapshots] == ["one.py", "two.py", "moved.py", "added.py"]
    assert [item.status for item in snapshots] == ["ok", "ok", "missing", "missing"]


def test_replace_patch_uses_path_argument(tmp_path):
    target = tmp_path / "replace.py"
    target.write_text("def before():\n    return None\n", encoding="utf-8")
    store = baseline.BaselineStore()

    snapshots = store.capture_tool_call(
        "patch",
        {"mode": "replace", "path": "replace.py", "old_string": "x", "new_string": "y"},
        turn_id="turn-a",
        cwd=tmp_path,
    )

    assert len(snapshots) == 1
    assert snapshots[0].findings[0].kind == "return_none"


def test_unsafe_initial_files_are_indeterminate_and_fail_open(tmp_path):
    binary = tmp_path / "binary.py"
    binary.write_bytes(b"\x00\x01def fake(): pass")
    oversized = tmp_path / "large.py"
    oversized.write_text("x" * 65, encoding="utf-8")
    inaccessible = tmp_path / "folder.py"
    inaccessible.mkdir()
    store = baseline.BaselineStore(max_bytes=64)

    snapshots = []
    for path in (binary, oversized, inaccessible):
        snapshots.extend(
            store.capture_tool_call("write_file", {"path": str(path)}, turn_id="turn-a", cwd=tmp_path)
        )

    assert [item.status for item in snapshots] == ["binary", "oversized", "inaccessible"]
    for path in (binary, oversized, inaccessible):
        result = store.compare("turn-a", path, "def new_stub():\n    pass\n")
        assert result.status == "indeterminate"
        assert result.findings == ()


def test_turns_are_isolated_and_findings_match_without_line_numbers(tmp_path):
    target = tmp_path / "isolated.py"
    target.write_text("def value():\n    pass\n", encoding="utf-8")
    store = baseline.BaselineStore()
    store.capture_tool_call("write_file", {"path": str(target)}, turn_id="turn-a", cwd=tmp_path)

    target.write_text("def value():\n    return 1\n", encoding="utf-8")
    store.capture_tool_call("write_file", {"path": str(target)}, turn_id="turn-b", cwd=tmp_path)

    shifted_stub = "# module comment\n\ndef value():\n    pass\n"
    assert store.compare("turn-a", target, shifted_stub).findings == ()
    assert finding_names(store.compare("turn-b", target, shifted_stub)) == [("value", "pass")]

    store.discard_turn("turn-a")
    assert store.compare("turn-a", target, shifted_stub).status == "uncaptured"


def test_unknown_or_malformed_tool_calls_never_raise(tmp_path):
    store = baseline.BaselineStore()
    assert store.capture_tool_call("terminal", {}, turn_id="turn-a", cwd=tmp_path) == ()
    assert store.capture_tool_call("write_file", None, turn_id="turn-a", cwd=tmp_path) == ()
    assert store.capture_tool_call("patch", {"mode": "patch", "patch": 12}, turn_id="turn-a") == ()
