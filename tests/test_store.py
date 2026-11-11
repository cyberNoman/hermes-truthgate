import json

from truthgate import store


def test_store_writes_only_allowlisted_sanitized_fields(tmp_path):
    path = tmp_path / "findings.jsonl"
    findings = store.FindingStore(path)
    secret = "never-write-this-secret"

    assert findings.append(
        event="continuation\nforged",
        session="abc",
        path="demo.py",
        line=7,
        category="secret",
        kind="credential_assignment",
        status="new",
        raw_secret=secret,
        source=secret,
    )

    raw = path.read_text(encoding="utf-8")
    record = json.loads(raw)
    assert secret not in raw
    assert "raw_secret" not in record
    assert "source" not in record
    assert record["event"] == "continuation forged"
    assert "1 sanitized records" in findings.summary()


def test_missing_store_has_safe_status(tmp_path):
    assert "no findings" in store.FindingStore(tmp_path / "missing.jsonl").summary()
