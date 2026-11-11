"""TruthGate 0.2.0 Hermes plugin registration."""

from __future__ import annotations

import logging
from typing import Any

from .gate import TruthGate
from .store import FindingStore


logger = logging.getLogger(__name__)
_gate: TruthGate | None = None


def _pre_tool_call(**kwargs: Any) -> None:
    try:
        if _gate is not None:
            return _gate.pre_tool_call(**kwargs)
    except Exception:
        logger.debug("TruthGate hook wrapper failed open", exc_info=True)
    return None


def _pre_verify(**kwargs: Any) -> dict[str, str] | None:
    try:
        if _gate is not None:
            return _gate.pre_verify(**kwargs)
    except Exception:
        logger.debug("TruthGate hook wrapper failed open", exc_info=True)
    return None


def _truthgate(raw_args: str) -> str:
    """Handle `/truthgate`; arguments are reserved for future compatible use."""

    del raw_args
    try:
        if _gate is None:
            return "TruthGate 0.2.0: not initialized."
        return _gate.status()
    except Exception:
        return "TruthGate 0.2.0: status unavailable (gate remains fail-open)."


def register(ctx: Any) -> None:
    """Register documented Hermes v0.23 hook and command surfaces."""

    global _gate
    try:
        from agent.runtime_cwd import resolve_agent_cwd
    except ImportError:
        resolve_agent_cwd = None
    try:
        data_dir = ctx.state.data_dir
        _gate = TruthGate(
            FindingStore(data_dir / "findings.jsonl"),
            cwd_resolver=resolve_agent_cwd,
        )
    except Exception:
        logger.exception("TruthGate initialization failed; hooks will remain fail-open")
        _gate = None
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("pre_verify", _pre_verify)
    ctx.register_command(
        "truthgate",
        handler=_truthgate,
        description="Show TruthGate's sanitized finding summary",
    )
