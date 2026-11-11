import importlib
import json
from pathlib import Path


gate_module = importlib.import_module("truthgate.gate")
store_module = importlib.import_module("truthgate.store")


def make_gate(tmp_path):
    return gate_module.TruthGate(
        store_module.FindingStore(tmp_path / "state" / "findings.jsonl"),
        cwd_resolver=lambda: tmp_path,
    )


def capture_new_file(gate, tmp_path, name="demo.py"):
    gate.pre_tool_call(
        tool_name="write_file",
        args={"path": name, "content": "ignored"},
        turn_id="turn-1",
        session_id="session-1",
    )
    return tmp_path / name


def verify(gate, path, attempt=0):
    return gate.pre_verify(
        coding=True,
        attempt=attempt,
        session_id="session-1",
        changed_paths=[str(path)],
    )


def test_new_stub_requests_one_continuation_then_suppresses_repetition(tmp_path):
    gate = make_gate(tmp_path)
    target = capture_new_file(gate, tmp_path)
    target.write_text("def unfinished():\n    pass\n", encoding="utf-8")

    first = verify(gate, target)
    repeated = verify(gate, target, attempt=1)

    assert first is not None and first["action"] == "continue"
    assert "demo.py:1 [stub/pass] function unfinished" in first["message"]
    assert repeated is None
    events = [json.loads(line)["event"] for line in gate.store.path.read_text().splitlines()]
    assert events == ["continuation", "suppressed"]


def test_repaired_stub_completes_without_another_continuation(tmp_path):
    gate = make_gate(tmp_path)
    target = capture_new_file(gate, tmp_path)
    target.write_text("def unfinished():\n    pass\n", encoding="utf-8")
    assert verify(gate, target) is not None

    target.write_text("def unfinished():\n    return 42\n", encoding="utf-8")
    assert verify(gate, target, attempt=1) is None


def test_changed_finding_set_allows_one_additional_bounded_repair(tmp_path):
    gate = make_gate(tmp_path)
    target = capture_new_file(gate, tmp_path)
    target.write_text("def first():\n    pass\n", encoding="utf-8")
    assert verify(gate, target) is not None

    target.write_text("def second():\n    ...\n", encoding="utf-8")
    assert verify(gate, target, attempt=1) is not None
    assert verify(gate, target, attempt=2) is None


def test_secret_value_is_absent_from_message_log_and_store(tmp_path, caplog):
    gate = make_gate(tmp_path)
    target = capture_new_file(gate, tmp_path)
    value = "AKIA1234567890ABCDEF"
    target.write_text(f'AWS_KEY = "{value}"\n', encoding="utf-8")

    result = verify(gate, target)

    assert result is not None
    assert "secret/aws_access_key" in result["message"]
    assert value not in result["message"]
    assert value not in caplog.text
    assert value not in gate.store.path.read_text(encoding="utf-8")


def test_uncaptured_and_bad_payloads_fail_open(tmp_path):
    gate = make_gate(tmp_path)
    target = tmp_path / "uncaptured.py"
    target.write_text("def stub():\n    pass\n", encoding="utf-8")

    assert verify(gate, target) is None
    assert gate.pre_verify(coding=False, attempt=0, session_id="x", changed_paths=[str(target)]) is None
