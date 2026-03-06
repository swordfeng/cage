# `sandbox` — Cross-Platform AI Agent Sandbox CLI

**Version:** 0.1 (draft)
**Status:** Design spec

---

## 1. Overview

`sandbox` is a CLI wrapper that runs AI coding agents (Codex, Claude Code, opencode, aider, etc.) in OS-native sandboxes. It restricts filesystem writes, controls network access, and isolates agent configuration — all without containers or VMs, preserving the host toolchain.

```
sandbox opencode
sandbox claude --policy strict
sandbox codex --allow-network
sandbox aider --policy build
```

### Goals

- Mount the current project directory read-write; restrict everything else
- Pass through only explicitly declared configs (SSH keys, gitconfig, agent settings)
- Expose MCP sockets into the sandbox
- Prevent writes outside the project and reads of sensitive host paths
- Preserve the full host toolchain (compiler, SDK, language runtimes)
- Work on Linux, macOS, and Windows
- Sub-second startup overhead

### Non-goals

- Container/VM-level isolation (use Docker or Firecracker if you need a kernel boundary)
- Protecting against hostile, kernel-exploit-capable agents
- Replacing agents' own approval/permission systems

---

## 2. Threat Model

The target threat is an **AI agent that is confused, buggy, or prompt-injected** — not a sophisticated attacker with kernel-exploit capability.

| Threat | Linux | macOS | Windows |
|---|---|---|---|
| Agent writes outside project | ✅ Landlock | ✅ Seatbelt | ✅ ACLs (with caveats) |
| Agent reads `~/.ssh` private keys | ✅ | ⚠️ read-only passthrough only | ✅ |
| Agent exfiltrates data over network | ✅ seccomp | ✅ Seatbelt | ✅ WFP firewall rules |
| Agent modifies shell config / crontab | ✅ | ✅ | ✅ |
| Agent installs persistent malware | ✅ | ✅ | ⚠️ `%TEMP%` gap (see §5.3) |

**What this does NOT protect against:**

- Kernel exploits (all OS-native sandboxes share the host kernel)
- Side-channel or timing attacks
- Social engineering (agent asking the user to run commands outside the sandbox)
- MCP server compromise (out of scope)
- macOS Seatbelt silent degradation on future OS versions

---

## 3. Architecture

### 3.1 Repository layout

```
sandbox/
├── src/
│   ├── main.rs               # CLI entry point, arg parsing
│   ├── config.rs             # Policy loading and merging
│   ├── agents/               # Per-agent config knowledge
│   │   ├── mod.rs
│   │   ├── codex.rs
│   │   ├── claude.rs
│   │   ├── opencode.rs
│   │   └── aider.rs
│   └── platform/
│       ├── mod.rs            # Platform detection, dispatch
│       ├── linux.rs          # Landlock + seccomp launcher
│       ├── macos.rs          # Seatbelt profile generator + sandbox-exec
│       └── windows.rs        # Restricted Token + ACL + WFP firewall
├── config/
│   └── sandbox.toml          # Bundled defaults
└── Cargo.toml
```

### 3.2 Execution flow

```
$ sandbox opencode

1.  Detect OS and kernel capabilities (Landlock ABI version, bwrap availability)
2.  Load and merge policy:
      ~/.config/sandbox/sandbox.toml    (user config)
      .sandbox.toml                     (project override, if present)
      CLI flags                         (highest precedence)
3.  Resolve agent config (see §6):
      - Create temp dir: /tmp/sandbox-$PID/
      - Prepare synthetic agent config pointing to temp dir
      - Copy/symlink declared passthrough configs (read-only)
4.  Platform-specific sandbox setup:
      Linux:   apply Landlock rules + seccomp BPF filter
      macOS:   generate Seatbelt profile string → write to temp file
      Windows: create restricted token, set ACLs, install WFP rules
5.  exec(agent) with:
      CWD            = current project directory (read-write)
      HOME           = temp dir (or agent config env var pointing there)
      Filtered env   = only declared passthrough vars + API keys
      MCP socket     = passed through (Unix socket / named pipe)
6.  On exit:
      Linux/macOS: temp dir cleaned up, seccomp/Landlock auto-released on process exit
      Windows:     WFP rules removed, ACLs restored, temp dir cleaned
```

---

## 4. Platform Implementations

### 4.1 Linux: Landlock + seccomp-BPF (default)

**Requirements:** Linux kernel ≥ 5.13 for Landlock v1. Kernel ≥ 5.19 for v2 (truncate rules). Kernel ≥ 6.7 for TCP port restrictions.

**What it does:**

1. Open Landlock ruleset with `LANDLOCK_CREATE_RULESET`
2. Add rules:
   - `REFER + READ_FILE + READ_DIR` on `/` (read-anywhere by default)
   - `WRITE_FILE + MAKE_*` only on whitelisted writable roots
3. `landlock_restrict_self()` — restrictions apply to this process and all children, cannot be removed
4. Apply seccomp-BPF filter:
   - Allow all syscalls except: `connect(AF_INET)`, `connect(AF_INET6)` → return `EACCES`
   - Allow `connect(AF_UNIX)` (MCP sockets)
5. `execvp(agent)`

**Crate:** use the published [`landlock`](https://crates.io/crates/landlock) crate (canonical Rust binding). For seccomp, use [`seccompiler`](https://crates.io/crates/seccompiler) (AWS Firecracker's library, also published).

Do **not** depend on Codex's internal `codex-core` or `linux-sandbox` crates — they are not published to crates.io, have no stable API, and couple you to OpenAI's internal `SandboxPolicy` type.

**Degradation:** If kernel < 5.13, log a warning and optionally fall back to bubblewrap (`--backend bwrap`) or run unsandboxed with `--no-sandbox`.

#### Alternative: bubblewrap (`--backend bwrap`)

Bubblewrap uses user namespaces to fully hide paths (not just deny access). It also supports **bind-mount remapping** — presenting a path inside the sandbox at a different location than on the host. This is the only mechanism in the entire stack that supports path remapping.

```sh
bwrap \
  --unshare-all \
  --share-net \                  # (omit to block network)
  --bind $CWD /project \         # remap project to /project
  --ro-bind /usr /usr \
  --ro-bind /nix/store /nix/store \
  --ro-bind $REAL_AGENT_CONFIG /home/user/.config/agent \   # remap config
  --tmpfs /home/user \
  --tmpfs /tmp \
  -- agent
```

Use bubblewrap when:
- You need to present a clean synthetic `HOME` at a completely different path
- You need stronger isolation (entire path trees invisible, not just access-denied)
- The project's security posture demands it

Bubblewrap requires either a setuid binary or unprivileged user namespaces (enabled in most desktop Linux distros, sometimes disabled in enterprise/container environments).

### 4.2 macOS: Seatbelt (`sandbox-exec`)

**Status:** `sandbox-exec` is marked deprecated in the man page since macOS 10.12, but the underlying kernel subsystem ("Seatbelt") powers all Apple system software and all major browsers. Claude Code, Codex CLI, and Cursor all use it in production as of 2025–2026. The SBPL profile language is the only viable lightweight option for macOS processes today.

**How it works:** Generate an SBPL profile string at runtime based on `$CWD` and declared policy, then exec the agent via `sandbox-exec -p "$PROFILE" agent`.

**Profile template (generated at runtime):**

```scheme
(version 1)
(allow default)

; ── Filesystem write restrictions ──────────────────────────────────────────
(deny file-write* (subpath "/"))
(allow file-write*
  (subpath "/path/to/project")          ; $CWD
  (subpath "/private/tmp")
  (subpath "/tmp"))

; Passthrough config dirs (read-only — deny writes explicitly)
; NOTE: (allow default) already grants reads; only writes need to be blocked.
; Writable agent config dirs (if declared):
; (allow file-write* (subpath "/path/to/agent/config"))

; ── Network restrictions ────────────────────────────────────────────────────
(deny network-outbound)
(allow network-outbound
  (remote unix-socket)                   ; MCP sockets
  (remote ip "localhost:*"))             ; localhost only (MCP HTTP, git over local proxy)

; ── For --allow-network mode, replace above with: ──────────────────────────
; (allow network*)
```

**Key constraints:**
- The profile **must be generated at runtime**. Static profiles don't work because writable paths include `$CWD` which is only known at invocation time.
- Seatbelt rules on specific paths (especially `/private/var` and Homebrew paths) can break across macOS versions. Build a runtime check: if `sandbox-exec` exits with a sandbox-violation error before the agent produces output, log it clearly and optionally retry with a relaxed profile or `--no-sandbox`.
- The `(allow default)` at the top means reads are allowed everywhere by default. To restrict reads you must invert to `(deny default)` and enumerate all allowed read paths — which breaks practically every agent. The practical posture is: restrict writes, allow reads.

**Alternatives evaluated and rejected:**

| Option | Verdict |
|---|---|
| App Sandbox (entitlements) | Requires code signing + notarization. Not applicable to arbitrary CLI wrappers. |
| Apple Containerization (`apple/container`, macOS 26) | Runs **Linux** containers only. Cannot sandbox macOS-native processes (Xcode, Metal, etc.). |
| Virtualization.framework (Tart, Lume) | Full macOS VM, 5–30s startup, high RAM. Breaks host toolchain. |
| Alcoholless (separate macOS user) | User-level isolation only, weaker guarantees, complex setup. |

### 4.3 Windows: Restricted Token + ACLs + WFP Firewall

Based on the approach OpenAI open-sourced in `codex-rs/windows-sandbox-rs/` (merged March 2026, PR #4905). This is the first production-validated, open-source Windows agent sandbox.

**Three-layer mechanism:**

**Layer 1 — Restricted Token**
- `CreateRestrictedToken()` strips dangerous SIDs and privileges from the current token
- The agent process runs with a reduced identity
- Cannot access resources requiring the user's standard SID

**Layer 2 — NTFS ACLs**
- Explicit ACEs grant write access to `$CWD` for the sandbox SID
- Rest of the filesystem implicitly denies writes (restricted token cannot authenticate)
- Caveat: directories where `Everyone` has write access (e.g., `%TEMP%`, some shared folders) cannot be blocked this way
- Mitigation: inject stub executables for dangerous tools (`ssh`, `curl`, `powershell`) into `PATH` ahead of real executables

**Layer 3 — Windows Filtering Platform (WFP) Firewall Rules**
- Outbound network blocked via WFP rules scoped to the sandbox user SID
- Localhost still reachable (MCP sockets, local git proxy)

**One-time setup (requires admin, run once at install time):**
```
sandbox-setup.exe
  Creates: SandboxUsers local group
  Creates: Dedicated sandbox user account
  Configures: Baseline WFP rules
```

**Runtime (no admin needed):**
```
CreateRestrictedToken(current_token, strip=[dangerous SIDs])
Set ACLs: GRANT SandboxSID full-control on $CWD
Add WFP rule: BLOCK outbound for SandboxSID
Inject stub executables into $PATH
CreateProcessWithToken(restricted_token, "agent.exe ...")
[on exit]: Remove WFP rule, clean up ACLs
```

**Vendoring:** `windows-sandbox-rs/src/lib.rs` exports `pub fn run_windows_sandbox_capture(...)` as a library entry point. Vendor this file, replace the `SandboxPolicy` type parameter with your own struct. The file is ~500 lines. Do not take a git dependency on the whole Codex workspace.

**Alternatives rejected:**

| Option | Verdict |
|---|---|
| Windows Sandbox (WSB) | Full Hyper-V VM with a separate Windows install. Cannot use host MSVC/Win32 SDK. |
| AppContainer | Requires app to declare capabilities via manifest. Cannot wrap arbitrary CLI tools. |
| WSL2 | Different kernel, different filesystem view. Breaks Windows-native toolchains. |

---

## 5. Policy System

### 5.1 Policy config format

```toml
# ~/.config/sandbox/sandbox.toml

# ── Named policies ──────────────────────────────────────────────────────────

[policies.strict]
writable_roots = ["$CWD"]
readable_roots = { type = "restricted", paths = ["$CWD", "/usr", "/nix/store"] }
network = "none"
env_passthrough = ["PATH"]

[policies.build]
writable_roots = ["$CWD", "~/.cache/cargo", "~/.gradle", "~/.cache/pip"]
readable_roots = { type = "full" }
network = "localhost"           # MCP sockets + package registry proxy
env_passthrough = ["PATH", "CARGO_HOME", "JAVA_HOME", "GOPATH"]

[policies.deploy]
writable_roots = ["$CWD"]
readable_roots = { type = "full" }
network = "full"
env_passthrough = ["PATH", "AWS_PROFILE", "KUBECONFIG", "GOOGLE_APPLICATION_CREDENTIALS"]

# ── Agent-specific defaults ──────────────────────────────────────────────────

[agents.opencode]
default_policy = "build"
config_env = "OPENCODE_CONFIG"
config_file = "~/.config/opencode/opencode.json"
extra_writable = ["~/.config/opencode"]

[agents.codex]
default_policy = "build"
config_env = "CODEX_HOME"
config_dir = "~/.codex"
extra_writable = []

[agents.claude]
default_policy = "build"
config_env = "CLAUDE_CONFIG_DIR"
config_dir = "~/.claude"
extra_writable = []             # note: writes .claude/settings.local.json in $CWD regardless

[agents.aider]
default_policy = "strict"
config_env = ""                 # aider has no config dir env var; use --config flag
extra_writable = []

# ── Platform-specific overrides ──────────────────────────────────────────────

[platform.linux]
default_backend = "landlock"    # "landlock" | "bwrap"
fail_on_sandbox_error = true

[platform.macos]
fail_on_sandbox_error = true    # set false to warn-and-continue if Seatbelt profile breaks

[platform.windows]
sandbox_group = "SandboxUsers"
stub_executables = ["ssh", "scp", "curl", "wget", "powershell"]
```

### 5.2 Policy merge semantics

Multiple named policies can be composed with `+`:

```
sandbox opencode --policy build+strict-net
```

Merge rules:
- `writable_roots`: **union** (most permissive)
- `readable_roots`: **intersection** (most restrictive)
- `network`: **most restrictive wins** (`none` > `localhost` > `proxy` > `full`)
- `env_passthrough`: **union**

### 5.3 Network policy levels

| Level | What's allowed |
|---|---|
| `none` | No outbound connections of any kind |
| `localhost` | `127.0.0.1`, `::1`, Unix domain sockets (MCP) |
| `proxy` | Localhost + outbound routed through a declared allowlist proxy (see §7) |
| `full` | Unrestricted outbound |

### 5.4 Policy type definitions (Rust)

```rust
pub struct SandboxPolicy {
    pub name: String,
    pub writable_roots: Vec<PathBuf>,
    pub readable_roots: ReadAccess,
    pub network: NetworkPolicy,
    pub env: EnvPolicy,
    pub extra_blocked_execs: Vec<PathBuf>,
}

pub enum ReadAccess {
    Full,
    Restricted(Vec<PathBuf>),
}

pub enum NetworkPolicy {
    None,
    Localhost,
    Proxy { url: String },
    Full,
}

pub struct EnvPolicy {
    pub passthrough: Vec<String>,      // glob patterns
    pub set: HashMap<String, String>,  // forced overrides
}

pub enum MultiPolicy {
    Single(SandboxPolicy),
    Merged(Vec<SandboxPolicy>),
}

impl MultiPolicy {
    pub fn resolve(&self) -> SandboxPolicy { /* merge per §5.2 */ }
}
```

---

## 6. Agent Config Isolation

Each agent uses an environment variable to redirect its config directory. The sandbox creates a per-session temp directory, populates it with the necessary files, sets the env var, and cleans up on exit.

### 6.1 Per-agent env var reference

| Agent | Env var | Points to | Notes |
|---|---|---|---|
| **Codex** | `CODEX_HOME` | Directory (`~/.codex/`) | Fully supported, stable. Also: `CODEX_SQLITE_HOME` for state DB. |
| **Claude Code** | `CLAUDE_CONFIG_DIR` | Directory (`~/.claude/`) | Undocumented but widely used. Still writes `settings.local.json` into `$CWD/.claude/` regardless. |
| **opencode** | `OPENCODE_CONFIG` | Specific JSON **file** | Agent markdown (`.opencode/agent/*.md`) does **not** load from the custom path — known limitation. Workaround: define agents inline in JSON, or use `XDG_CONFIG_HOME` instead. |
| **opencode** | `XDG_CONFIG_HOME` | Directory (replaces `~/.config/`) | Redirects entire XDG config tree. Coarser than `OPENCODE_CONFIG` but picks up agent markdown. |
| **aider** | `--config` CLI flag | Specific config file | No directory-level env var. Pass via CLI. |

### 6.2 Session temp dir layout

```
/tmp/sandbox-$PID/
├── codex/                      # (if running codex)
│   └── config.toml             # copied + stripped from ~/.codex/config.toml
├── claude/                     # (if running claude)
│   ├── .claude.json            # credentials passthrough
│   └── settings.json           # copied from ~/.claude/settings.json
├── opencode.json               # (if running opencode) — patched config file
└── ssh/                        # read-only bind of ~/.ssh (or symlink)
    ├── config                  # (read-only)
    └── known_hosts             # (read-only)
    # private keys: NOT passed through by default
```

Private SSH keys are not passed through by default. Use `--passthrough-ssh-keys` explicitly if the agent needs to push to remote repos.

### 6.3 Config patching

When creating the temp config, the sandbox may patch out settings that conflict with the sandbox policy. For example:
- `sandbox_mode = "danger-full-access"` in `CODEX_HOME/config.toml` → rewritten to `"workspace-write"`
- MCP server entries referencing absolute paths outside the sandbox → kept (sockets are passed through)
- Network-requiring MCP servers → warn if `network = "none"`

---

## 7. MCP Socket Passthrough

MCP servers communicate over Unix domain sockets (Linux/macOS) or named pipes (Windows). These must be accessible from inside the sandbox.

**Linux (Landlock):** Unix sockets are not subject to Landlock filesystem rules. The seccomp filter explicitly allows `AF_UNIX`. No special configuration needed.

**Linux (bubblewrap):** Bind-mount the socket path:
```sh
--bind /run/mcp/server.sock /run/mcp/server.sock
```

**macOS (Seatbelt):** The profile includes `(allow network-outbound (remote unix-socket))`. The socket path must also be readable (allowed by `(allow default)`).

**Windows:** Named pipes are accessible by SID. The restricted token retains access to named pipes created by the parent process. No special configuration needed for in-process MCP.

---

## 8. Path Remapping

Path remapping (presenting a host path at a different sandbox-internal path) is only possible with bubblewrap on Linux. All other sandbox mechanisms (Landlock, Seatbelt, Windows ACLs) operate on real host paths only.

| Mechanism | Path remapping? |
|---|---|
| Landlock + seccomp | ❌ |
| bubblewrap | ✅ full bind-mount |
| Seatbelt (macOS) | ❌ |
| Windows restricted token + ACLs | ❌ |

For cross-platform config isolation without path remapping, use the agent config env vars (§6) to point the agent at a temp directory. This achieves the same practical outcome — the agent sees only the files you've explicitly placed there — without needing namespace support.

---

## 9. CLI Interface

```
USAGE:
    sandbox [OPTIONS] <AGENT> [-- <AGENT_ARGS>...]

ARGS:
    <AGENT>          Agent to run: codex, claude, opencode, aider, or an arbitrary binary

OPTIONS:
    -p, --policy <NAME[+NAME...]>   Named policy or merged set (default: agent's default)
        --allow-network             Shorthand for --policy <current>+full-network
        --no-sandbox                Run agent unsandboxed (logs a warning)
        --backend <BACKEND>         Linux only: landlock (default) | bwrap
        --passthrough-ssh-keys      Include ~/.ssh private keys (read-only)
        --passthrough <PATH>        Add an extra read-only passthrough path (repeatable)
        --writable <PATH>           Add an extra writable root (repeatable)
    -v, --verbose                   Show sandbox configuration before exec
        --dry-run                   Print the sandbox config and generated profile, don't exec

EXAMPLES:
    sandbox opencode
    sandbox claude --allow-network
    sandbox codex --policy strict
    sandbox opencode --policy build+deploy
    sandbox --backend bwrap opencode
    sandbox --no-sandbox aider -- --model gpt-4o
```

---

## 10. Implementation Roadmap

### Phase 1 — Core (implement first)

- [ ] Policy config loading and merging
- [ ] Agent config detection and temp dir setup (§6)
- [ ] Linux: Landlock + seccomp using published `landlock` + `seccompiler` crates
- [ ] macOS: Seatbelt profile generator + `sandbox-exec` exec
- [ ] MCP socket passthrough (all platforms)
- [ ] Cleanup on exit (temp dirs, Windows firewall rules)

### Phase 2 — Completeness

- [ ] Linux: bubblewrap backend (`--backend bwrap`)
- [ ] Windows: port `codex-rs/windows-sandbox-rs/src/lib.rs` (vendor, replace `SandboxPolicy`)
- [ ] Windows: one-time `sandbox-setup` installer
- [ ] Policy composition (`--policy a+b`)
- [ ] Config patching (strip conflicting agent sandbox settings)
- [ ] Structured audit log of denied accesses

### Phase 3 — Advanced

- [ ] Linux kernel ≥ 6.7: Landlock TCP port restrictions for surgical network policy
- [ ] Network allowlist proxy mode (`network = "proxy"`) — route outbound through a domain-filtering HTTP proxy, similar to Claude Code's approach
- [ ] macOS Containerization (macOS 26+): Linux container mode for agents that only need Linux toolchain (Node/Python/Go/Rust); not suitable for Xcode/iOS work
- [ ] VM mode (`--isolation=vm`): Firecracker microVM for highest assurance; ~1–2s startup; suitable for CI

---

## 11. Dependency Strategy

### Use published crates (do not vendor from Codex)

```toml
[target.'cfg(target_os = "linux")'.dependencies]
landlock    = "0.4"      # canonical Rust Landlock binding — crates.io
seccompiler = "0.4"      # AWS Firecracker seccomp-BPF — crates.io

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.58", features = [
    "Win32_Security",
    "Win32_System_Threading",
    "Win32_NetworkManagement_WindowsFilteringPlatform",
]}
```

macOS requires no crate — Seatbelt is just `std::process::Command::new("sandbox-exec")`.

### Vendor selectively (Windows only)

Vendor `codex-rs/windows-sandbox-rs/src/lib.rs` (~500 lines) with your own `SandboxPolicy` struct substituted. Do not take the whole Codex workspace as a dependency.

### Why not use Codex crates directly

- `codex-linux-sandbox`: binary-only crate, no `[lib]` target, not published
- `codex-core` (contains Landlock + Seatbelt code): not published to crates.io, internal API, couples you to OpenAI's `SandboxPolicy` type
- `codex-windows-sandbox`: has a `pub fn run_windows_sandbox_capture` but is not published; git dependency is fragile as OpenAI refactors internals

---

## 12. Security Notes

### macOS Seatbelt degradation

Seatbelt profile rules can silently stop working after OS updates. Mitigation:
- On startup, run a probe: attempt a write to a path that should be denied; if it succeeds, the profile is broken
- If `fail_on_sandbox_error = true` (default), abort with a clear error
- If `fail_on_sandbox_error = false`, warn and run unsandboxed

### CODEX_HOME injection vulnerability

A fixed CVE (Codex 0.23.0): a repo's `.env` file could set `CODEX_HOME` to `./.codex`, causing Codex to load attacker-controlled MCP server configs. The fix prevents `.env` files from overriding `CODEX_HOME`. For `sandbox`, the mitigation is: set `CODEX_HOME` to the temp dir explicitly in the spawned environment, which cannot be overridden by the agent reading `.env` files because the process environment is already set before exec.

### Windows `%TEMP%` gap

Directories where `Everyone` has write access (notably `%TEMP%` and some shared folders) cannot be blocked by the restricted token + ACL approach because the write permission is granted independently of SID. Mitigation: inject stub executables for tools that could exfiltrate via temp files. This is a known limitation of the Windows approach (shared with Codex's implementation).

### Credential passthrough hygiene

- SSH private keys: not passed through by default; opt-in with `--passthrough-ssh-keys`
- API keys: passed through only for vars explicitly listed in `env_passthrough`
- Agent credentials files (`.claude.json`, `~/.codex/auth.json`): copied read-only into temp dir, never the originals made writable

---

## 13. References

- Codex Linux sandbox: `openai/codex` → `codex-rs/linux-sandbox/` and `codex-rs/core/src/landlock.rs`
- Codex macOS Seatbelt: `openai/codex` → `codex-rs/core/src/seatbelt.rs`
- Codex Windows sandbox: `openai/codex` → `codex-rs/windows-sandbox-rs/src/lib.rs` (PR #4905, merged Mar 2026)
- Landlock kernel docs: https://docs.kernel.org/userspace-api/landlock.html
- `landlock` crate: https://crates.io/crates/landlock
- `seccompiler` crate: https://crates.io/crates/seccompiler
- Apple Containerization (macOS 26, Linux containers only): https://github.com/apple/container
- bubblewrap: https://github.com/containers/bubblewrap
- Claude Code `CLAUDE_CONFIG_DIR` behavior: https://github.com/anthropics/claude-code/issues/3833
- opencode `OPENCODE_CONFIG` limitation (agents not loading): https://github.com/sst/opencode/issues/3432
- opencode XDG support: https://github.com/sst/opencode/issues/6669
- Codex `CODEX_HOME` injection CVE: https://www.csoonline.com/article/4100632/
