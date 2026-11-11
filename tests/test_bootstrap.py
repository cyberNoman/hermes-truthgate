"""Isolated registration contract tests; Hermes Doctor remains the runtime check."""

import truthgate as PLUGIN


class State:
    def __init__(self, data_dir):
        self.data_dir = data_dir


class RecordingContext:
    def __init__(self, data_dir):
        self.state = State(data_dir)
        self.hooks = []
        self.commands = []

    def register_hook(self, event, handler):
        self.hooks.append((event, handler))

    def register_command(self, name, handler, description="", args_hint=""):
        self.commands.append((name, handler, description, args_hint))


def test_registers_supported_hooks_and_command(tmp_path):
    ctx = RecordingContext(tmp_path)
    PLUGIN.register(ctx)

    assert [(name, handler) for name, handler in ctx.hooks] == [
        ("pre_tool_call", PLUGIN._pre_tool_call),
        ("pre_verify", PLUGIN._pre_verify),
    ]
    assert len(ctx.commands) == 1
    assert ctx.commands[0][0] == "truthgate"
    assert ctx.commands[0][1] is PLUGIN._truthgate
    assert "0.2.1" in PLUGIN._truthgate("")


def test_hook_wrappers_fail_open_without_initialized_gate(monkeypatch):
    monkeypatch.setattr(PLUGIN, "_gate", None)
    assert PLUGIN._pre_tool_call(tool_name="write_file") is None
    assert PLUGIN._pre_verify(coding=True, attempt=0, changed_paths=["demo.py"]) is None
    assert "not initialized" in PLUGIN._truthgate("")


class SessionContext(RecordingContext):
    """A context exposing Hermes's supported ``ctx.session_cwd()`` API."""

    def __init__(self, data_dir, workspace):
        super().__init__(data_dir)
        self.workspace = workspace
        self.cwd_calls = 0

    def session_cwd(self):
        self.cwd_calls += 1
        return str(self.workspace)


def test_relative_paths_resolve_through_ctx_session_cwd(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    ctx = SessionContext(tmp_path / "data", workspace)
    monkeypatch.setattr(PLUGIN, "_gate", None)
    PLUGIN.register(ctx)
    assert ctx.cwd_calls == 0  # Read per hook call, never cached at registration.

    assert PLUGIN._pre_tool_call(
        tool_name="write_file", args={"path": "demo.py"}, turn_id="turn-1", session_id="session-1"
    ) is None
    (workspace / "demo.py").write_text("def unfinished():\n    pass\n", encoding="utf-8")
    result = PLUGIN._pre_verify(
        coding=True, attempt=0, session_id="session-1", changed_paths=[str(workspace / "demo.py")]
    )

    assert result is not None and result["action"] == "continue"
    assert "demo.py:1 [stub/pass] function unfinished" in result["message"]
    assert ctx.cwd_calls >= 1


def test_registration_without_session_cwd_api_still_fails_open(tmp_path, monkeypatch):
    monkeypatch.setattr(PLUGIN, "_gate", None)
    PLUGIN.register(RecordingContext(tmp_path))

    assert PLUGIN._gate is not None and PLUGIN._gate.cwd_resolver is None
    assert PLUGIN._pre_tool_call(
        tool_name="write_file", args={"path": "demo.py"}, turn_id="turn-1", session_id="session-1"
    ) is None
