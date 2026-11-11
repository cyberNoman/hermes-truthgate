## TruthGate 0.2.1 catalog submission

TruthGate adds deterministic final-turn verification for newly introduced
Python stubs and common embedded-secret patterns. It uses `pre_tool_call` for
pre-edit baselines, `pre_verify` for bounded corrective continuations, and a
`/truthgate` command for aggregate sanitized status.

0.2.1 is a security-hardening release. It changes no hook, command, or
capability declaration.

This is post-deadline maintenance. The original 0.2.0 submission remains at
`9fd8c071371721006d9b7254d624481fe49cd02d`; none of the changes below are
represented as part of that original snapshot.

### Fixed in 0.2.1

- **Blocking file access.** Hermes vetoes a tool call whose `pre_tool_call` hook
  raises or times out, and 0.2.0 read files while holding its shared lock with
  no file-type check. File access now happens outside any lock, only on regular
  files (checked with `stat` and again with `fstat`), with a 1 MiB + 1 byte read
  cap, per-call path limits, and a wall-clock budget on a daemon worker. Worker
  capacity is reserved before launch, so concurrent hook calls cannot exceed
  the global two-worker cap. Windows UNC, device and reserved-name paths are
  rejected before any filesystem call.
- **Patch headers and path spelling.** 0.2.0 recognized a `*** Move to:` header
  that Hermes does not use and missed `*** Move File: a -> b`. It also resolved
  Git Bash drive paths (`/c/Users/...`) to the wrong location on Windows, so the
  baseline never matched the path Hermes reported and new findings in that file
  were silently skipped. Headers and path spelling now follow Hermes's file
  tools; a changed file without a reliable baseline is recorded as `uncaptured`
  and never nudged.
- **Working directory.** The private `agent.runtime_cwd` import is replaced by
  the supported `ctx.session_cwd()` plugin API, read lazily and only for
  relative paths. The process working directory is never used as a fallback.
- **Exact `.env` creation.** An exact `.env` was skipped because its conventional
  suffix is empty. TruthGate now records only whether that path existed before
  the mutation and reports a path-level `dotenv_file` finding when it is newly
  created as a regular file. It never opens, parses, displays, or persists the
  file's contents; existing `.env` files and `.env.*` variants remain out of
  scope.

### Validation evidence (Windows, Hermes Agent 0.23.0)

- `python -m pytest -q`: 66 passed in 1.06 s (Python 3.13.6).
- `hermes plugins doctor . --ci`: passed; 0 tools and 2 hooks registered.
- `hermes plugins validate . --install-deps`: passed; security scan safe, no
  core override, compatible with `plugins.isolation: host`.
- Normal unchanged-file `pre_verify` benchmark (200 measured runs after 20
  warmups): 0.762 ms mean, 0.704 ms median, 0.953 ms p95, 2.959 ms maximum.
- Hermes runtime integration, without a model: in an isolated `HERMES_HOME`,
  Hermes 0.23.0's own plugin loader, `pre_tool_call` dispatcher, `write_file`
  and `patch` tools, changed-path extraction, and `pre_verify` resolver were
  driven directly (Python 3.14.9). A new stub written through a relative path
  and through a Git Bash drive path each produced one continuation; repairing
  the stub ended the turn; a V4A `Move File` of a file with an existing stub
  reported only the stub added in the same patch; a change without a baseline
  produced an `uncaptured` record and no continuation; `/truthgate` returned
  aggregate counts. The same script run against 0.2.0 misses the Git Bash case
  and records nothing for the unbaselined change.
- Independent hostile-input run after the final fixes: 6,400 malformed hook
  calls completed in 0.041 s with no exception, no persisted record, and no
  non-`None` result.
- Real gateway-backed Hermes 0.23.0 smoke after a controlled restart: session
  `local-ef5ec276c4b98e53be689090fa8801216661e6a7fbd2775ba12b8122840b7981`
  used native `write_file` to create `smoke_target.py` with `pass`, attempted to
  finish with `INITIAL_DONE`, received one TruthGate continuation, used native
  `patch` to replace the stub with `return 42`, and finished with `FIXED`.
  Gateway and sanitized JSONL evidence record attempt 0 and one `stub/pass`
  continuation for session tag `862deae90f70`. A later `execute_code` check was
  denied by normal unattended-session approval policy; no bypass was enabled.
  `/truthgate` reported TruthGate 0.2.1 and sanitized aggregate counts.

### Risk disclosures

- Reads only paths named by Hermes's `write_file`/`patch` calls and
  `changed_paths`, and only files with a scannable suffix; no directory crawl.
- Exact `.env` creation is detected from path and regular-file metadata only;
  TruthGate never opens an exact `.env` or scans its contents.
- Stores sanitized JSONL metadata under the active Hermes profile. It does not
  store source text or raw matched credentials. The file is not rotated.
- Uses deterministic heuristics, so false positives and false negatives remain.
- Fails open on missing or untrusted baselines, unsupported mutation tools,
  unreadable/oversized/binary/non-regular files, relative paths without an
  absolute session directory, path limits, the I/O budget, malformed hook
  payloads, and internal errors.
- Does not verify edits made on remote or container terminal backends, and may
  miss a relative-path edit made after the agent changes directory in the
  terminal. Both cases are documented in the README.
- A read of a regular file on an unresponsive mount can still occupy a worker
  thread until the operating system returns; at most two such threads exist,
  and TruthGate performs no file access while they do. Mapped drives and local
  symlinks/junctions to remote targets can still cause operating-system
  filesystem access to contact another host.
- A finding can add a model continuation and therefore inference cost. Identical
  findings are suppressed; the plugin allows at most two continuations when the
  finding set changes.
- No network access, subprocesses, shell execution, LLM calls, credential reads,
  approval bypass, background processes, third-party dependencies, telemetry,
  self-update behavior, private Hermes imports, or Hermes core overrides.
