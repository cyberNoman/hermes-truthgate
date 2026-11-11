# TruthGate

TruthGate 0.2.0 is a standard-library-only Hermes Agent plugin that checks files
changed during a coding turn before Hermes returns its final answer. It compares
the final file against a pre-edit snapshot and requests a corrective continuation
only for newly introduced findings.

It detects:

- hollow Python functions (`pass`, ellipsis, `NotImplementedError`, empty
  returns, and explicitly marked placeholder literal returns); and
- deterministic embedded-secret shapes such as private-key headers, AWS access
  keys, GitHub/Slack tokens, and quoted credential assignments.

Existing findings are not re-reported. Abstract methods, overloads, direct
`Protocol` members, `.pyi` declarations, and `# truthgate: allow` functions are
excluded. A repeated unchanged result is never nudged twice; at most two
continuations are possible when the finding set changes between attempts.

## Install and verify

TruthGate requires Hermes Agent 0.23.0 or later.

```text
hermes plugins install .
hermes plugins enable truthgate
hermes plugins doctor . --ci
hermes plugins validate . --install-deps
```

Run its tests from the plugin directory:

```text
python -m pytest -q
```

Use `/truthgate` in a Hermes session to show aggregate sanitized record counts.
The command never displays source text, matched values, or recorded paths.

## Runtime behavior

`pre_tool_call` captures the initial state of paths passed to Hermes's documented
`write_file` and `patch` tools. Relative paths are resolved using the documented
`agent.runtime_cwd.resolve_agent_cwd()` session API. `pre_verify` scans the
corresponding changed files and may return Hermes's documented
`{"action": "continue", "message": "..."}` directive.

The scanner is intentionally fail-open. Missing baselines, unsupported tools,
unreadable/binary/non-UTF-8 files, files over 1 MiB, malformed hook payloads,
and internal errors produce no continuation.

## Security and privacy disclosures

- No third-party runtime dependencies, network requests, subprocesses, shell
  commands, LLM calls, approval changes, background processes, or core patches.
- TruthGate reads only supported changed-file paths supplied by Hermes. A changed
  absolute path outside the session directory is read but persisted only as its
  basename; this follows the host's mutation record rather than broad crawling.
- Secret matches are reduced immediately to type, line number, and an in-memory
  SHA-256 comparison fingerprint. Raw values and source text are never logged or
  persisted.
- Sanitized JSONL records live at `findings.jsonl` inside Hermes's
  profile-scoped `ctx.state.data_dir` for the plugin and contain time, event,
  hashed session tag, display path, line, category, kind, and status. Hermes
  chooses the concrete data-namespace directory for the installation source.
- Deterministic pattern matching has false positives and false negatives; this
  is a release guard, not a complete secret scanner or security boundary.
- Fail-open behavior favors agent availability over enforcement when TruthGate
  cannot safely establish an initial baseline.

## License

MIT. See [LICENSE](LICENSE).
