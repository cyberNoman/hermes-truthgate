## TruthGate 0.2.0 catalog submission

TruthGate adds deterministic final-turn verification for newly introduced
Python stubs and common embedded-secret patterns. It uses `pre_tool_call` for
pre-edit baselines, `pre_verify` for bounded corrective continuations, and a
`/truthgate` command for aggregate sanitized status.

Validation evidence (Windows, Hermes Agent 0.23.0, Python 3.13.6):

- `python -m pytest -q`: 24 passed in 0.18s (rerun after final edits before PR)
- `hermes plugins doctor . --ci`: passed; 0 tools and 2 hooks registered
- `hermes plugins validate . --install-deps`: passed; security scan safe and
  no core override
- Real Hermes stub-repair smoke against the final installed files: session
  `local-9060a169412c8110868ad893c8f32b0e0f7e24e0b1525aa5c51d8086f7679942`
  wrote `pass`, attempted to finish with `DONE`, received one TruthGate
  continuation, patched the body to `return 42`, and ended with `FIXED`.
  Gateway log recorded attempt 0 with one finding.
- `/truthgate`: returned sanitized aggregate counts with zero tool calls. The
  final store has three continuation records: two stub smokes and the optional
  secret detection smoke.
- Optional synthetic-secret smoke: detection and continuation were confirmed,
  and the fabricated value was absent from JSONL. The model did not follow the
  continuation successfully and left the disposable synthetic file unchanged;
  this is disclosed rather than counted as a repair success.

Risk disclosures:

- Reads only changed-file paths supplied by Hermes; no directory crawl.
- Stores sanitized JSONL metadata under the active Hermes profile. It does not
  store source text or raw matched credentials.
- Uses deterministic heuristics, so false positives and false negatives remain.
- Fails open on missing baselines, unreadable/oversized/binary files, malformed
  hook payloads, unsupported mutation tools, and internal errors.
- A finding can add a model continuation and therefore inference cost. Identical
  findings are suppressed; the plugin allows at most two continuations when the
  finding set changes.
- No network access, subprocesses, shell execution, LLM calls, credential reads,
  approval bypass, background processes, third-party dependencies, telemetry,
  self-update behavior, or Hermes core overrides.
