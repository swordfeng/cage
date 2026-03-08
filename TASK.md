# `cage` — Implementation Task List

Granular breakdown of [SPEC.md §11](SPEC.md#11-implementation-roadmap). Tasks reference the relevant SPEC sections. Check off tasks as completed.

---

## Phase 1a — Core Platforms (Weeks 1–3)

### T1.1 — Project scaffold
- [x] `cargo new cage --bin`; configure workspace layout per SPEC §3.1
- [x] `Cargo.toml`: add `clap` (v4, derive), `serde`, `toml`, `scopeguard`
- [x] Platform-gated dependency blocks: `seccompiler = "0.4"` (Linux, phase 1b), `windows = "0.58"` (Windows, phase 1b) per SPEC §12
- [x] Embed `config/cage.toml` via `include_str!` at compile time for bundled defaults

### T1.2 — CLI argument parsing (`src/cli.rs`)
- [x] `clap` derive struct with all flags from SPEC §9: `--policy`, `--allow-network`, `--no-sandbox`, `--config`, `--writable`, `--write-restrict`, `--read-restrict`, `-v/--verbose`, `--dry-run`
- [x] Positional `<COMMAND> [ARGS]...` with `trailing_var_arg = true` and `allow_hyphen_values`
- [x] `--policy` accepts `NAME` (Phase 1); documented `NAME+NAME` as Phase 2 in help text

### T1.3 — Policy types (`src/policy/types.rs`)
- [x] Define `SandboxPolicy`, `NetworkPolicy`, `EnvMode`, `EnvPolicy`, `CommandPolicy`, `Config` per SPEC §4.4
- [x] Implement `EnvPolicy::filter(env: &HashMap<String,String>) -> HashMap<String,String>` — apply allowlist/blocklist glob matching, then apply `set` overrides
- [x] Glob matching helper `glob_match(pattern: &str, name: &str) -> bool` — support `*` and `?` only (no need for full glob crate)

### T1.4 — Config loading and merge (`src/config.rs`)
- [x] Deserialize TOML into `Config` via `serde`; define `#[derive(Deserialize)]` on all policy types
- [x] Load and layer: bundled defaults → `~/.config/cage/cage.toml` → `.cage.toml` (walk up from `$CWD` to home dir) → CLI flag overrides
- [x] Policy lookup by name; clear error if named policy doesn't exist
- [x] `command_policy` matching: `Config::default_policy_for(command: &str)` using `Path::file_stem()` + `glob_match()` per SPEC §4.1
- [x] Policy selection logic: `--policy` flag → `command_policy` match → `"default"` policy → hard error

### T1.5 — Variable expansion (`src/policy/merge.rs`)
- [x] `expand_path(template: &str, cwd: &Path) -> Option<PathBuf>`: handle `~` (home dir), `$CWD` (cage invocation dir), `$VAR` (env lookup)
- [x] Apply to all `Vec<PathBuf>` fields during policy resolution (not at parse time, so `$CWD` is the runtime invocation dir)
- [x] Drop path entry silently if referenced `$VAR` is unset; log at `-v` level

### T1.6 — Session temp dir (`src/main.rs`)
- [x] Create `/tmp/cage-{PID}-{RAND}/` (Linux/macOS) or `%TEMP%\cage-{PID}-{RAND}\` (Windows) before sandbox setup
- [x] Register cleanup via `scopeguard` `defer!` to remove on exit (including on panic)
- [x] Pass temp dir path to platform backend

### T1.7 — Linux: bubblewrap launcher (`src/platform/linux.rs`)
- [ ] Build `bwrap` argv from resolved `SandboxPolicy`:
  - `--ro-bind / /` first
  - `--dev /dev`, `--proc /proc`
  - `--bind $path $path` per `writable_roots` (in order)
  - `--ro-bind $path $path` per `write_restricted_paths` (after writable roots — overlay wins)
  - `--bind $socket $socket` per MCP socket paths
  - `--bind <session_tmpdir> <session_tmpdir>`
  - `--unshare-pid`, `--die-with-parent` (always; see SPEC §5.1)
  - Network: `--unshare-net` for `None`; nothing for `Full`; `--share-net` for `Localhost` (seccomp handles filtering, phase 1b)
  - `-- <COMMAND> [ARGS]`
- [ ] Canonicalize all paths via `std::fs::canonicalize()` before building argv (resolves symlinks)
- [ ] Check `bwrap` availability on startup: `Command::new("bwrap").arg("--version")`; clear error if missing with install hint
- [ ] Check unprivileged user namespaces: read `/proc/sys/kernel/unprivileged_userns_clone`; error if `0` and bwrap is not setuid
- [ ] Apply `EnvPolicy::filter()` to environment before exec; pass filtered env via `Command::env_clear().envs(...)`
- [ ] `--no-sandbox`: log warning, exec command directly without bwrap

### T1.8 — macOS: Seatbelt launcher (`src/platform/macos.rs`)
- [ ] `fn sbpl_escape_path(path: &str) -> String` — replace `\` → `\\`, `"` → `\"` (see SPEC §5.2)
- [ ] `fn generate_profile(policy: &SandboxPolicy, session_tmpdir: &Path) -> String`:
  - `(version 1)` + `(allow default)`
  - `(deny file-write* (subpath "/"))`
  - `(allow file-write* (subpath "..."))` per `writable_roots` + session tmpdir
  - `(deny file-write* (subpath "..."))` per `write_restricted_paths` (placed after allows — last rule wins)
  - `(deny file-read* (subpath "..."))` per `read_restricted_paths`
  - Network block/allow rules per `NetworkPolicy` (see SPEC §5.2 template)
- [ ] Canonicalize all paths via `std::fs::canonicalize()` before embedding in profile (handles `/tmp` → `/private/tmp`)
- [ ] Write profile to `<session_tmpdir>/profile.sb`
- [ ] Exec: `Command::new("/usr/bin/sandbox-exec").arg("-f").arg(&profile_path).arg("--").arg(command).args(args)` (hardcoded path, not PATH lookup — see SPEC §5.2)
- [ ] `fail_on_sandbox_error = false`: if `sandbox-exec` fails to exec, log warning and exec command directly
- [ ] Apply `EnvPolicy::filter()` to environment before exec

### T1.9 — MCP socket passthrough (Linux/macOS)
- [ ] Read `MCP_SOCKET` environment variable (and agent-specific variants) per SPEC §7
- [ ] Linux: add each socket path as `--bind <path> <path>` to bwrap argv
- [ ] macOS: `(allow network-outbound (remote unix-socket))` already present in `localhost`/`full` network profile; also ensure socket's directory is readable (covered by `(allow default)`)
- [ ] If `MCP_SOCKET` is unset, skip passthrough silently

### T1.10 — `--dry-run` and `-v` output
- [x] `-v`: print resolved `SandboxPolicy` (formatted), temp dir path, and chosen platform backend before exec
- [x] `--dry-run`: also print generated bwrap argv or Seatbelt profile content; do not exec; exit 0

### T1.11 — Integration tests
- [ ] `write_restricted_paths`: attempt to write to `$CWD/.git/COMMIT_EDITMSG`; assert `PermissionDenied`
- [ ] `read_restricted_paths`: attempt to read a mock sensitive path (created in test fixture); assert `PermissionDenied`
- [ ] `network = "none"`: attempt `curl`/`nc` to `8.8.8.8`; assert connection failure
- [ ] `network = "full"`: attempt connection to localhost echo server; assert success
- [ ] Env filtering: verify `*_TOKEN` pattern vars absent in child process env (blocklist mode)
- [ ] Env filtering: verify only `PATH` present in child env (allowlist mode)
- [ ] `--no-sandbox`: command runs, exits with forwarded exit code
- [ ] Run cage as subprocess via `Command`; check exit code forwarding

---

## Phase 1b — Windows + Localhost Network (Weeks 4–5)

### T2.1 — Linux: seccomp supervisor for `localhost` network (`src/platform/linux.rs`)
- [ ] Build BPF filter via `seccompiler`: `connect` syscall → `SECCOMP_RET_USER_NOTIF`, all others → `SECCOMP_RET_ALLOW`
- [ ] Implement supervisor fork+exec flow per SPEC §5.1:
  1. cage creates `socketpair(AF_UNIX, SOCK_SEQPACKET)`
  2. child forks, installs seccomp with `SECCOMP_FILTER_FLAG_NEW_LISTENER`, sends notification FD to cage via `SCM_RIGHTS`
  3. child execs `bwrap ...`; notification FD survives exec
- [ ] cage supervisor thread: read `seccomp_notif` → read sockaddr from `/proc/<pid>/mem` → allow/deny → write `seccomp_notif_resp`
- [ ] Allow: `AF_UNIX`, `AF_INET`/`AF_INET6` to `127.0.0.1`/`::1`. Deny all else with `ECONNREFUSED`
- [ ] Kernel version check: require Linux ≥ 5.0; emit clear error if older

### T2.2 — Windows: `cage-setup.exe` — initial setup (`src/bin/cage-setup.rs`)
- [ ] Separate binary with UAC manifest requesting `requireAdministrator`
- [ ] `cage-setup` (no args): initial one-time setup:
  - Create `<user>-CageUsers` local group
  - Create two local user accounts: `<user>-CageOffline`, `<user>-CageLocalhostOnly`
  - Add both accounts to `<user>-CageUsers` group
  - Grant "Log on as a batch job" right to both accounts
  - Generate random passwords; encrypt with DPAPI; store in `HKCU\Software\Cage\Credentials\`
  - Apply inheritable read ACE for `<user>-CageUsers` on user profile directory
  - Install WFP provider + sublayer + static firewall rules:
    - `<user>-CageOffline` SID: BLOCK all outbound on V4 + V6
    - `<user>-CageLocalhostOnly` SID: PERMIT `127.0.0.1`/`::1` (high weight) + BLOCK rest (low weight)
- [ ] Idempotent: check if accounts/groups/WFP rules already exist before creating; print status
- [ ] Print success summary with instructions

### T2.3 — Windows: `cage-setup.exe` — workspace+policy setup (`src/bin/cage-setup.rs`)
- [ ] `cage-setup --prepare <path> --policy <name>`: per workspace+policy combination (requires admin):
  - Validate `<path>` is not the user profile root (`C:\Users\<user>`) — refuse with error to prevent home-dir DACL pollution
  - Workspace group (if not cached in `HKCU\Software\Cage\Workspaces\<hash>`):
    - Hash canonical path → create `<user>-CageWS-<hash>` local group
    - Add both sandbox accounts as members
    - Apply single inheritable write ACE for `<user>-CageWS-<hash>` on `<path>`
    - `SetNamedSecurityInfoW` propagates to all existing children (O(n), synchronous)
    - Cache group SID + path in `HKCU\Software\Cage\Workspaces\<hash>`
  - Policy group (if not cached in `HKCU\Software\Cage\Policies\<hash>`):
    - Hash writable paths config → create `<user>-CagePolicy-<hash>` local group
    - Add both sandbox accounts as members
    - Apply inheritable write ACE for policy group on each global writable path (`%TEMP%`, etc.)
    - Cache group SID + paths in `HKCU\Software\Cage\Policies\<hash>`
  - Deny ACEs (if not already applied):
    - For each `write_restricted_path` (relative path, e.g., `.git/`), resolve to `<workspace_path>/<write_restricted_path>`
    - Apply inheritable deny ACE for `<user>-CageUsers` on the resolved absolute path
- [ ] `cage-setup --uninstall`: remove WFP rules, accounts, all groups, all ACEs, registry keys

### T2.4 — Windows: runtime token creation (`src/platform/windows.rs`)
- [ ] Look up workspace group from `HKCU\Software\Cage\Workspaces\<hash>` and policy group from `HKCU\Software\Cage\Policies\<hash>`; error with "run `cage-setup --prepare <path> --policy <name>`" if either is not found
- [ ] `none`/`localhost`: decrypt password from DPAPI store → `LogonUser(account, password, LOGON32_LOGON_BATCH)` → base token
- [ ] `full`: `OpenProcessToken(current_process)` → base token
- [ ] `CreateRestrictedToken(base_token, SidsToRestrict=[CageWS-<hash>, CagePolicy-<hash>, CageUsers, BUILTIN\Users, Everyone, RESTRICTED, LogonSID], SidsToDisable=[Administrators, ...dangerous groups])`
- [ ] Verify restricted token: attempt `AccessCheck` against workspace path to confirm write access

### T2.5 — Windows: process launch + signal forwarding (`src/platform/windows.rs`)
- [ ] **DESIGN DECISION PENDING:** Choose implementation approach for `CreateProcessAsUserW` privilege requirements:
  - Option A: Grant `SeIncreaseQuotaPrivilege` at setup time
  - Option B: Use `CreateProcessWithLogonW` (no privileges, no restricted token)
  - Option C: LocalSystem helper service
- [ ] `CreateProcessAsUserW(restricted_token, ...)` with inherited handles (or alternative chosen above)
- [ ] `SetConsoleCtrlHandler` to intercept `CTRL_C_EVENT` and `CTRL_BREAK_EVENT`; forward via `GenerateConsoleCtrlEvent(event, child_pid)`
- [ ] `WaitForSingleObject(child_handle, INFINITE)`; `GetExitCodeProcess`; exit with forwarded code

### T2.6 — Windows: cleanup
- [ ] Per-session: remove `<session_tmpdir>` (best-effort); no ACL cleanup needed (workspace ACEs are persistent/cached)
- [ ] All cleanup steps run in `Drop` impls or `scopeguard` so they fire even on panic
- [ ] No WFP cleanup needed (rules are static, installed at setup time)
- [ ] `cage cleanup`: enumerate `HKCU\Software\Cage\Workspaces\` and `Policies\`; remove groups + ACEs for entries not used in N days
- [ ] `cage-setup --uninstall`: full teardown (WFP, accounts, all groups, all ACEs, registry)

### T2.7 — Integration tests (Windows)
- [ ] Write attempt to non-CWD path (e.g., `C:\Windows\Temp\test.txt`); assert `ACCESS_DENIED`
- [ ] Write to `$CWD`; assert success
- [ ] `write_restricted_paths` deny: attempt write to `$CWD\.git`; assert `ACCESS_DENIED`
- [ ] Network `none`: attempt outbound TCP; assert failure
- [ ] Network `localhost`: connect to `127.0.0.1`; assert success; connect to external; assert failure
- [ ] Network `full`: outbound TCP succeeds
- [ ] Cross-workspace isolation: `none`-session in workspace A cannot write to workspace B (different restricting SIDs)
- [ ] Workspace caching: second session to same workspace skips O(n) ACL propagation
- [ ] Exit code forwarding

---

## Phase 2 — Enhanced Features (Weeks 6–7)

### T3.1 — Policy composition (`src/policy/merge.rs`)
- [ ] Parse `--policy a+b` syntax; split on `+`, look up each named policy
- [ ] Implement `MultiPolicy::resolve() -> SandboxPolicy` per merge rules in SPEC §4.2:
  - `writable_roots`: union
  - `write_restricted_paths`, `read_restricted_paths`: intersection
  - `network`: most permissive (`Full > Localhost > None`)
  - `env.mode`: `Blocklist` if any policy uses it; else `Allowlist`
  - `env.allow`: union; `env.block`: intersection; `env.set`: union (last policy wins on key conflict)
- [ ] Tests: verify each merge rule in isolation

### T3.2 — Config validation
- [ ] Warn if a `write_restricted_path` is not a subdirectory of any `writable_root` (the restriction is redundant — everything outside writable roots is already denied)
- [ ] Error if a path appears in both `writable_roots` and `read_restricted_paths`
- [ ] Warn on `command_policy` entries referencing undefined policy names
- [ ] Run validation after config merge, before sandbox setup

### T3.3 — Structured audit log
- [ ] Write to `<session_tmpdir>/audit.log` in JSON-lines format
- [ ] Entry schema: `{ "ts": "<ISO8601>", "op": "file-write|file-read|connect", "path": "...", "decision": "deny", "rule": "write_restricted_paths[0]" }`
- [ ] Linux: log connect() denials from seccomp supervisor
- [ ] macOS/Windows: log at policy generation time what restrictions are active (static summary, since kernel-level per-access hooks aren't available without audit frameworks)

---

## Phase 3 — Advanced (Future)

> These are tracked here for completeness but are not scheduled. See SPEC §11.

- [ ] Linux: Landlock backend as fallback for systems without user namespaces (no `write_restricted_paths` support)
- [ ] Network proxy mode (`network = "proxy"`) — domain-filtering HTTP proxy for outbound allowlists
- [ ] macOS Containerization (macOS 26+): Linux container mode
- [ ] VM mode (`--isolation=vm`): Firecracker microVM
- [ ] Sandbox escape hatch (`escape_bash`, `escape_bash_ask` MCP tools)
