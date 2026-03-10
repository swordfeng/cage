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
- [x] `clap` derive struct with all flags from SPEC §9: `--policy`, `--allow-network`, `--config`, `--writable`, `--write-restrict`, `--read-restrict`, `-v/--verbose`, `--dry-run`
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
- [x] Build `bwrap` argv from resolved `SandboxPolicy`:
  - `--ro-bind / /` first
  - `--dev /dev`, `--proc /proc`
  - `--bind $path $path` per `writable_roots` (in order)
  - `--ro-bind $path $path` per `write_restricted_paths` (after writable roots — overlay wins)
  - `--bind <session_tmpdir> <session_tmpdir>`
  - `--unshare-pid`, `--die-with-parent` (always; see SPEC §5.1)
  - Network: `--unshare-net` for `None`; nothing for `Full`; `--share-net` for `Localhost` (seccomp handles filtering, phase 1b)
  - `-- <COMMAND> [ARGS]`
- [x] Canonicalize all paths via `std::fs::canonicalize()` before building argv (resolves symlinks)
- [x] Check `bwrap` availability on startup: `Command::new("bwrap").arg("--version")`; clear error if missing with install hint
- [x] Check unprivileged user namespaces: read `/proc/sys/kernel/unprivileged_userns_clone`; error if `0` and bwrap is not setuid
- [x] Apply `EnvPolicy::filter()` to environment before exec; pass filtered env via `Command::env_clear().envs(...)`

### T1.8 — macOS: Seatbelt launcher (`src/platform/macos.rs`)
- [x] `fn sbpl_escape_path(path: &str) -> String` — replace `\` → `\\`, `"` → `\"` (see SPEC §5.2)
- [x] `fn generate_profile(policy: &SandboxPolicy, session_tmpdir: &Path) -> String`:
  - `(version 1)` + `(allow default)`
  - `(deny file-write* (subpath "/"))`
  - `(allow file-write* (subpath "..."))` per `writable_roots` + session tmpdir
  - `(deny file-write* (subpath "..."))` per `write_restricted_paths` (placed after allows — last rule wins)
  - `(deny file-read* (subpath "..."))` per `read_restricted_paths`
  - Network block/allow rules per `NetworkPolicy` (see SPEC §5.2 template)
- [x] Canonicalize all paths via `std::fs::canonicalize()` before embedding in profile (handles `/tmp` → `/private/tmp`)
- [x] Write profile to `<session_tmpdir>/cage.sb`
- [x] Profile file protection: deny read/write access to profile within sandbox
- [x] Exec: `Command::new("/usr/bin/sandbox-exec").arg("-f").arg(&profile_path).arg("--").arg(command).args(args)` (hardcoded path, not PATH lookup — see SPEC §5.2)
- [x] Pre-flight check: verify `/usr/bin/sandbox-exec` exists with helpful error message
- [x] Apply `EnvPolicy::filter()` to environment before exec
- [x] Exit code forwarding from sandboxed process
- [x] Comprehensive test coverage for SBPL escaping and glob matching

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
- [ ] Run cage as subprocess via `Command`; check exit code forwarding

### T1.12 — GUI/Audio Policy Fields (`src/policy/types.rs`)
- [x] Add `enable_gui: Option<bool>` to `SandboxPolicy` struct
- [x] Add `enable_audio: Option<bool>` to `SandboxPolicy` struct
- [x] Update merge logic: override only if explicitly set (per SPEC §4.2 merge rules)
- [x] Add default getter methods: return `false` if field is `None` (secure default; bundled configs set to `true`)
- [x] Update bundled config `cage.toml` with `enable_gui = true` and `enable_audio = true` in both policies

### T1.13 — Linux GUI/Audio Passthrough (`src/platform/linux.rs`)
- [x] When `enable_gui` is true (default):
  - Add `--ro-bind $XDG_RUNTIME_DIR/wayland-0 $XDG_RUNTIME_DIR/wayland-0` if Wayland socket exists
  - Add `--ro-bind /tmp/.X11-unix /tmp/.X11-unix` for X11 (read-only, sockets are writable in practice)
  - Add `--dev-bind /dev/dri /dev/dri` for GPU access (DRI/DRM)
  - **Do NOT add `--unshare-ipc`** (required for X11 shared memory extension)
- [x] When `enable_audio` is true (default):
  - Add `--ro-bind $XDG_RUNTIME_DIR/pulse/native $XDG_RUNTIME_DIR/pulse/native` if PulseAudio socket exists
  - Add `--ro-bind $XDG_RUNTIME_DIR/pipewire-0 $XDG_RUNTIME_DIR/pipewire-0` if PipeWire socket exists
- [x] Update `generate_bwrap_argv` to accept GUI/audio flags and build appropriate bind mounts
- [x] Add `--dry-run` test to verify Wayland/X11/DRI binds appear when GUI enabled

### T1.14 — macOS GUI/Audio Passthrough (`src/platform/macos.rs`)
- [x] When `enable_gui` is true (default):
  - Add `(allow iokit-open)` to Seatbelt profile for graphics/display access
  - Add `(allow device*)` for input devices
- [x] When `enable_audio` is true (default):
  - Add `(allow device*)` to Seatbelt profile for audio device access
- [x] Update `generate_seatbelt_profile` to conditionally include these rules
- [x] Avoid duplicate `(allow device*)` when both GUI and audio enabled
- [x] Documented in `macos_notes.md`

### T1.15 — Windows GUI/Audio Support (`src/platform/windows.rs`)
- [ ] Accept `enable_gui` and `enable_audio` in policy (no-op implementation - per user request)
- [ ] Add documentation comment explaining Windows inherently supports GUI/audio, flags are for config compatibility
- [ ] Update `generate_windows_sandbox_config` to log when these flags are set (for visibility in `--dry-run`)

### T1.16 — Refine macOS Seatbelt sandbox rules
- [ ] Review and refine Seatbelt profile to use exact operations instead of wildcards where possible
- [ ] Reference Codex Seatbelt implementation: `openai/codex/codex-rs/core/src/seatbelt.rs`

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

### T2.8 — Linux: Seccomp Syscall Blocking (General Security)
- [ ] Build BPF filter via `seccompiler` to block dangerous syscalls (all others → `SECCOMP_RET_ALLOW`):
  - `mount`, `umount`, `umount2`, `pivot_root`, `chroot` - Filesystem escape
  - `unshare`, `setns` - Namespace switching
  - `add_key`, `keyctl`, `request_key` - Kernel keyring access
  - `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `mount_setattr` - New mount APIs (CVE-2021-41133)
  - `ioctl` with `TIOCSTI`, `TIOCLINUX` - Terminal injection attacks (CVE-2017-5226, CVE-2023-28100)
- [ ] Block non-standard socket families: `AF_BLUETOOTH`, `AF_CAN`, etc. (allow `AF_UNIX`, `AF_INET`, `AF_INET6`)
- [ ] Apply filter via `seccomp(SECCOMP_SET_MODE_FILTER)` before execing bwrap
- [ ] Log blocked syscall attempts at `-v` level
- [ ] Test: attempt `mount` inside sandbox → should get EPERM

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

### T3.4 — MCP socket passthrough (moved from Phase 1)
- [ ] Read `MCP_SOCKET` environment variable (and agent-specific variants) per SPEC §7
- [ ] Linux: add each socket path as `--bind <path> <path>` to bwrap argv
- [ ] macOS: `(allow network-outbound (remote unix-socket))` already present in `localhost`/`full` network profile; also ensure socket's directory is readable (covered by `(allow default)`)
- [ ] Windows: named pipe access via restricted token
- [ ] If `MCP_SOCKET` is unset, skip passthrough silently

---

## Phase 3 — Advanced (Future)

> These are tracked here for completeness but are not scheduled. See SPEC §11.

- [ ] Linux: Landlock backend as fallback for systems without user namespaces (no `write_restricted_paths` support)
- [ ] Network proxy mode (`network = "proxy"`) — domain-filtering HTTP proxy for outbound allowlists
- [ ] macOS Containerization (macOS 26+): Linux container mode
- [ ] VM mode (`--isolation=vm`): Firecracker microVM
- [ ] Sandbox escape hatch (`escape_bash`, `escape_bash_ask` MCP tools)
