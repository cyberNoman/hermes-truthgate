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
    assert "0.2.0" in PLUGIN._truthgate("")


def test_hook_wrappers_fail_open_without_initialized_gate(monkeypatch):
    monkeypatch.setattr(PLUGIN, "_gate", None)
    assert PLUGIN._pre_tool_call(tool_name="write_file") is None
    assert PLUGIN._pre_verify(coding=True, attempt=0, changed_paths=["demo.py"]) is None
    assert "not initialized" in PLUGIN._truthgate("")
