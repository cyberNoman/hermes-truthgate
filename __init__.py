"""TruthGate 0.2.1 Hermes plugin registration."""

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
            return "TruthGate 0.2.1: not initialized."
        return _gate.status()
    except Exception:
        return "TruthGate 0.2.1: status unavailable (gate remains fail-open)."


def register(ctx: Any) -> None:
    """Register documented Hermes v0.23 hook and command surfaces."""

    global _gate
    try:
        # ``ctx.session_cwd()`` is the supported plugin API for the calling
        # session's working directory. It is read lazily inside each hook, only
        # when a relative path needs it. Without it relative paths fail open.
        session_cwd = getattr(ctx, "session_cwd", None)
        _gate = TruthGate(
            FindingStore(ctx.state.data_dir / "findings.jsonl"),
            cwd_resolver=session_cwd if callable(session_cwd) else None,
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
