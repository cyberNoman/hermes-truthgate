# TruthGate

TruthGate 0.2.1 is a standard-library-only Hermes Agent plugin that checks files
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

`pre_tool_call` captures the initial state of the paths named by Hermes's
`write_file` and `patch` tools, including every V4A header Hermes accepts:
`*** Update File:`, `*** Add File:`, `*** Delete File:` and
`*** Move File: source -> destination` (both sides; the destination inherits the
source's baseline so a move alone never looks like new code). `pre_verify` then
scans the `changed_paths` Hermes reports and may return Hermes's documented
`{"action": "continue", "message": "..."}` directive.

Paths are spelled the way Hermes's host file tools spell them, so a baseline
matches the absolute path Hermes later reports: Git Bash drive paths such as
`/c/Users/me/app.py` become `C:\Users\me\app.py` on Windows, `~` is expanded,
and relative paths are joined to the session working directory returned by the
supported plugin API `ctx.session_cwd()`. Absolute paths never consult the
working directory, and the plugin never falls back to its own process directory.

Only files with these suffixes are candidates for content scanning: `.py`,
`.pyi`, `.js`, `.jsx`, `.ts`, `.tsx`, `.json`, `.yaml`, `.yml`, `.toml`,
`.ini`, `.cfg`, `.conf`. An exact `.env` is handled more conservatively:
TruthGate records only whether the path existed before the tool call and, when
it is newly created as a regular file, reports a `dotenv_file` finding without
opening or parsing its contents. Existing `.env` files are not reported, and
variants such as `.env.local` remain outside the approved scope.

### Fail-open cases

TruthGate never blocks a tool call and never nudges without a trusted baseline.
When a changed file has no reliable baseline it appends a sanitized `uncaptured`
record (reason only, no content) instead of treating the file as checked. No
continuation is produced for:

- files changed by anything other than `write_file` or `patch` (terminal
  commands, `execute_code`, other plugins' tools, MCP tools);
- relative paths when `ctx.session_cwd()` is unavailable, empty, or not absolute;
- Windows UNC, device, drive-relative (`C:name`) and rootless (`\name`) paths,
  including workspaces opened directly on a UNC share (map it to a drive letter);
- initial files that are missing a baseline, binary, undecodable, over 1 MiB,
  not regular files, or cloud placeholders that are not stored locally;
- paths beyond the per-call limits (32 paths per tool call, 64 changed paths per
  verification, 512 baselines per turn), which are counted in a `skipped` record;
- files not inspected within the I/O budget, malformed hook payloads, and
  internal errors.

### Known limitations

- **Terminal `cd`.** Hermes resolves a relative tool path against the terminal's
  live directory, while `ctx.session_cwd()` returns the session's recorded
  workspace. After the agent runs `cd` in the terminal, a relative path can be
  baselined at a different location than the one Hermes edits; that edit is then
  recorded as `uncaptured` and is not verified. Absolute paths are unaffected.
- **Remote and container backends.** TruthGate inspects only the filesystem of
  the machine running Hermes. With Docker, SSH, Modal, Daytona or similar
  terminal backends the edited files live elsewhere, so TruthGate verifies
  nothing there and may instead look at an unrelated host file of the same path.
- **Profile-specific home directories.** `~` is expanded with the plugin
  process's home, which can differ from the home Hermes uses for a profile.
- **Scope.** Deterministic pattern matching has false positives and false
  negatives. This is a release guard, not a secret scanner or security boundary.

## Security and privacy disclosures

- No third-party runtime dependencies, network requests, subprocesses, shell
  commands, LLM calls, approval changes, background processes, or core patches.
  No private Hermes modules are imported.
- TruthGate reads only paths named by Hermes's own mutation tools and
  `changed_paths`. A changed absolute path outside the session directory is read
  but persisted only as its basename; there is no directory crawling.
- **Bounded file access.** Hermes treats a `pre_tool_call` hook that raises or
  times out (30 s by default) as a veto of the tool call, so file access is
  constrained to keep TruthGate from stalling the agent:
  - a path is checked with `stat` and again with `fstat` on the opened
    descriptor; only regular files are read, so FIFOs, sockets, devices and
    directories are never read, even if the path is swapped between the checks;
  - on Windows, UNC paths (`\\host\share\...`), device namespaces (`\\.\`,
    `\\?\`), reserved device names such as `NUL` or `CON`, and
    alternate-data-stream paths are rejected before any filesystem call;
  - files are opened read-only with `O_NONBLOCK`, `O_NOCTTY` and `O_CLOEXEC`
    where the platform provides them, and at most 1 MiB + 1 byte is read;
  - all filesystem calls run on a short-lived daemon thread with a wall-clock
    budget (4 s for baselines, 8 s for verification). A call that misses the
    budget is abandoned, its late result is discarded, and the hook returns
    without a baseline. No lock is held during filesystem access.
- **Residual stall risk.** `O_NONBLOCK` does not make regular-file I/O on an
  unresponsive network share, FUSE mount, or failing disk return. In that case
  the worker thread stays blocked until the operating system gives up. At most
  two such threads can exist at once; while they do, TruthGate performs no file
  access and verifies nothing. If `plugins.hook_callback_timeout` is configured
  below the budgets above, Hermes's own timeout can still fire first and block
  that tool call. Parsing a pathological file can also consume CPU for the
  duration of the budget. A mapped network drive or a local symlink/junction to
  a remote target can still cause operating-system filesystem access to contact
  another host; only direct UNC and device spellings are rejected lexically.
- Secret matches are reduced immediately to type, line number, and an in-memory
  SHA-256 comparison fingerprint. Raw values and source text are never logged or
  persisted.
- Sanitized JSONL records live at `findings.jsonl` inside Hermes's
  profile-scoped `ctx.state.data_dir` for the plugin and contain time, event
  (`continuation`, `suppressed`, `uncaptured`, `skipped`), hashed session tag,
  display path, line or count, category, kind, and status. The file is
  append-only and is not rotated.
- In-memory state is bounded: 64 retained turns and 256 tracked sessions, with
  the oldest evicted first. State left by a turn that never reached
  verification is discarded when the same session starts its next turn.

## License

MIT. See [LICENSE](LICENSE).
