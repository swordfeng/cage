# `cage` — Cross-Platform AI Agent Sandbox CLI

**Version:** 0.1 (draft)
**Status:** Design spec

---

## 1. Overview

`cage` is a CLI wrapper that runs any command (AI coding agents, build tools, scripts, etc.) in OS-native sandboxes. It restricts filesystem reads/writes, controls network access, and isolates configuration — all without containers or VMs, preserving the host toolchain and filesystem layout.

```
cage opencode
cage --policy strict claude
cage --allow-network codex
cage --policy build aider
cage --policy strict ./build.sh
cage python script.py
```

### Goals

- Restrict reads/writes based on configurable policies; operate on the same filesystem as the host (no mounts)
- Pass through only explicitly declared configs (SSH keys, gitconfig, environment variables)
- Expose MCP sockets into the sandbox
- Prevent writes outside allowed paths and reads of sensitive host paths
- Preserve the full host toolchain (compiler, SDK, language runtimes)
- Work on Linux, macOS, and Windows
- Sub-second startup overhead

### Non-goals

- Container/VM-level isolation (use Docker or Firecracker if you need a kernel boundary)
- Protecting against hostile, kernel-exploit-capable attackers
- Replacing application-level approval/permission systems

---

## 2. Threat Model

The target threat is a **process that is confused, buggy, or misconfigured** — not a sophisticated attacker with kernel-exploit capability.

| Threat | Linux | macOS | Windows |
|---|---|---|---|
| Writes outside allowed paths | ✅ Landlock | ✅ Seatbelt | ✅ ACLs (with caveats) |
| Reads sensitive paths (e.g., `~/.ssh`) | ✅ Landlock | ✅ Seatbelt (see §5.2) | ✅ ACLs |
| Exfiltrates data over network | ✅ seccomp | ✅ Seatbelt | ✅ WFP firewall rules |
| Modifies shell config / crontab | ✅ | ✅ | ✅ |
| Installs persistent malware | ✅ | ✅ | ⚠️ `%TEMP%` gap (see §5.3) |

**What this does NOT protect against:**

- Kernel exploits (all OS-native sandboxes share the host kernel)
- Side-channel or timing attacks
- Social engineering (process asking the user to run commands outside the sandbox)
- MCP server compromise (out of scope)
- macOS Seatbelt silent degradation on future OS versions

---

## 3. Architecture

### 3.1 Repository layout

```
cage/
├── src/
│   ├── main.rs               # CLI entry point, arg parsing
│   ├── config.rs             # Policy loading and merging
│   ├── cli.rs                # CLI argument definitions
│   ├── policy/               # Policy definitions
│   │   ├── mod.rs
│   │   ├── types.rs          # Policy structs and enums
│   │   └── merge.rs          # Policy composition logic
│   └── platform/
│       ├── mod.rs            # Platform detection, dispatch
│       ├── linux.rs          # Landlock + seccomp launcher
│       ├── macos.rs          # Seatbelt profile generator + sandbox-exec
│       └── windows.rs        # Restricted Token + ACL + WFP firewall
├── config/
│   └── cage.toml             # Bundled defaults
└── Cargo.toml
```

### 3.2 Execution flow

```
$ cage opencode

1.  Detect OS and kernel capabilities (Landlock ABI version, bwrap availability)
2.  Load and merge policy:
      ~/.config/cage/cage.toml          (user config)
      .cage.toml                        (project override, if present)
      CLI flags                         (highest precedence)
      Policy selection:
        - If `--policy <name>` is specified, use that policy
        - Else if command matches a `command_policy` pattern, use mapped policy
        - Else use "default" policy (or fail if no default exists)
3.  Prepare environment:
      - Create temp dir: /tmp/cage-$PID/
      - Copy/symlink declared passthrough configs (read-only)
      - Set up environment variables based on policy
4.  Platform-specific sandbox setup:
      Linux:   apply Landlock rules + seccomp BPF filter
      macOS:   generate Seatbelt profile string → write to temp file
      Windows: create restricted token, set ACLs, install WFP rules
5.  exec(agent) with:
      CWD            = current working directory (read-write, if in policy)
      HOME           = user home directory (same as host)
      Environment    = filtered per policy (allowlist/blocklist mode + forced overrides)
      MCP socket     = passed through (Unix socket / named pipe)
6.  On exit:
      Linux/macOS: temp dir cleaned up, seccomp/Landlock auto-released on process exit
      Windows:     WFP rules removed, ACLs restored, temp dir cleaned
      Exit code     = forwarded from the sandboxed process
```

---

## 4. Policy System

### 4.1 Policy config format

```toml
# ~/.config/cage/cage.toml

# ── Named policies ──────────────────────────────────────────────────────────

[policies.default]
writable_roots = ["$CWD", "$TMPDIR", "$HOME/.cache"]
write_restricted_paths = ["$CWD/.git", "$CWD/.env", "$HOME/.ssh", "$HOME/.gnupg", "$HOME/.aws", "$HOME/.config"]
read_restricted_paths = []
network = "full"
[policies.default.env]
mode = "blocklist"
block = ["*_TOKEN", "*_SECRET", "*_PASSWORD", "*_API_KEY", "AWS_*", "GITHUB_*"]
set = { CAGE = "1" }

[policies.strict]
writable_roots = ["$CWD"]
write_restricted_paths = ["$CWD/.git", "$CWD/.env"]
read_restricted_paths = ["~/.ssh", "~/.aws", "~/.config", "~/.gnupg"]
network = "none"
[policies.strict.env]
mode = "allowlist"                    # "allowlist" | "blocklist"
allow = ["PATH"]                      # for allowlist mode: only these vars
# block = ["SECRET_*"]                # for blocklist mode: exclude these
set = { CAGE = "1" }                  # always set these

[policies.build]
writable_roots = ["$CWD", "~/.cache/cargo", "~/.gradle", "~/.cache/pip"]
write_restricted_paths = ["$CWD/.git"]  # protect git history
read_restricted_paths = []              # no read restrictions
network = "localhost"
[policies.build.env]
mode = "allowlist"
allow = ["PATH", "CARGO_HOME", "JAVA_HOME", "GOPATH", "TERM", "LANG"]
set = { CAGE = "1" }

[policies.deploy]
writable_roots = ["$CWD"]
write_restricted_paths = ["$CWD/.git"]
read_restricted_paths = ["~/.ssh", "~/.gnupg"]
network = "full"
[policies.deploy.env]
mode = "blocklist"                    # inherit most vars, exclude sensitive ones
block = ["GITHUB_TOKEN", "AWS_SECRET_*", "*_PASSWORD", "*_KEY"]
set = { CAGE = "1" }

# Phase 3: Domain-filtered network access (via built-in proxy)
# [policies.web-build]
# writable_roots = ["$CWD"]
# network = { type = "proxy", allowed_domains = ["github.com", "npmjs.com", "registry.npmjs.org"] }
# [policies.web-build.env]
# mode = "allowlist"
# allow = ["PATH", "NODE_ENV"]
# set = { CAGE = "1" }

#### Variable expansion

Path values in the config support variable expansion:

| Variable | Description |
|----------|-------------|
| `$CWD` | **Runtime-computed** - the current working directory where `cage` was invoked |
| `$VAR` | Environment variable lookup (platform-specific names) |
| `~` | Home directory (expanded via standard shell rules) |

**No cross-platform mapping:** Use platform-specific environment variable names. For example:

```toml
# Unix example
writable_roots = ["$CWD", "$HOME/.cache", "$TMPDIR", "$XDG_CACHE_HOME"]

# Windows example
writable_roots = ["$CWD", "$USERPROFILE\\.cache", "$TEMP", "$LOCALAPPDATA"]
```

Variables are resolved at policy application time. If an environment variable is not set, it expands to an empty string (which may cause errors if the path becomes invalid).

# ── Command to policy mappings ───────────────────────────────────────────────
# Map specific commands to default policies. The first matching pattern is used.
# Patterns are checked in order. If no match, the "default" policy is used.
#
# Pattern matching rules:
# - Matches against the basename (filename only, no directory)
# - Extension is stripped (.exe, .cmd, .bat on Windows; no extension elsewhere)
# - Supports glob wildcards: * matches any sequence, ? matches single char
#
# Examples:
#   pattern = "opencode"    matches: opencode, opencode.exe, /usr/bin/opencode, C:\tools\opencode.exe
#   pattern = "python*"     matches: python, python3, python.exe, python3.11.exe
#   pattern = "node"        matches: node, node.exe

[[command_policy]]
pattern = "opencode"
policy = "build"

[[command_policy]]
pattern = "codex"
policy = "build"

[[command_policy]]
pattern = "claude"
policy = "build"

[[command_policy]]
pattern = "aider"
policy = "strict"

[[command_policy]]
pattern = "npm"
policy = "build"

[[command_policy]]
pattern = "cargo"
policy = "build"

# ── Platform-specific overrides ──────────────────────────────────────────────

[platform.linux]
default_backend = "landlock"    # "landlock" | "bwrap"
fail_on_sandbox_error = true

[platform.macos]
fail_on_sandbox_error = true    # set false to warn-and-continue if Seatbelt profile breaks

[platform.windows]
cage_group = "CageUsers"
stub_executables = ["ssh", "scp", "curl", "wget", "powershell"]
```

### 4.2 Policy merge semantics

Multiple named policies can be composed with `+`:

```
cage --policy build+strict-net opencode
```

Merge rules:
- `writable_roots`: **union** (most permissive)
- `write_restricted_paths`: **union** (all blocked paths from merged policies)
- `read_restricted_paths`: **union** (all blocked paths from merged policies)
- `network`: **most restrictive wins** (`none` > `localhost` > `proxy` > `full`)
- `env.mode`: if any policy uses `allowlist`, result is `allowlist` (most restrictive); otherwise `blocklist`
- `env.allow`: **union** (all allowed vars from merged policies)
- `env.block`: **intersection** (only blocks vars all policies agree to block)
- `env.set`: **union** (later policies override earlier for same keys)

### 4.3 Network policy levels

| Level | What's allowed |
|---|---|
| `none` | No outbound connections of any kind |
| `localhost` | `127.0.0.1`, `::1`, Unix domain sockets (MCP) |
| `proxy` | Localhost + outbound to specific domains only (via built-in filtering proxy, Phase 3) |
| `full` | Unrestricted outbound |

### 4.4 Policy type definitions (Rust)

```rust
pub struct SandboxPolicy {
    pub name: String,
    pub writable_roots: Vec<PathBuf>,
    pub write_restricted_paths: Vec<PathBuf>,  // subpaths blocked from writing within writable roots
    pub read_restricted_paths: Vec<PathBuf>,   // paths blocked from reading
    pub network: NetworkPolicy,
    pub env: EnvPolicy,
    pub extra_blocked_execs: Vec<PathBuf>,
}

pub enum NetworkPolicy {
    None,
    Localhost,
    Proxy { allowed_domains: Vec<String> },  // Phase 3: domain filtering via built-in proxy
    Full,
}

pub enum EnvMode {
    Allowlist,   // Only vars in `allow` are passed through
    Blocklist,   // All vars except those in `block` are passed through
}

pub struct EnvPolicy {
    pub mode: EnvMode,
    pub allow: Vec<String>,            // glob patterns for allowlist mode
    pub block: Vec<String>,            // glob patterns for blocklist mode
    pub set: HashMap<String, String>,  // forced overrides, always applied
}

pub enum MultiPolicy {
    Single(SandboxPolicy),
    Merged(Vec<SandboxPolicy>),
}

impl MultiPolicy {
    pub fn resolve(&self) -> SandboxPolicy { /* merge per §4.2 */ }
}

pub struct CommandPolicy {
    pub pattern: String,     // command name or glob pattern to match
    pub policy: String,      // name of the policy to apply
}

pub struct Config {
    pub policies: HashMap<String, SandboxPolicy>,
    pub command_policy: Vec<CommandPolicy>,  // ordered list, first match wins
    pub platform: PlatformConfig,
}

impl Config {
    /// Find the default policy for a given command.
    /// Matches against basename (filename only) with extension stripped.
    /// Supports glob patterns (* and ?).
    pub fn default_policy_for(&self, command: &str) -> Option<&str> {
        let basename = std::path::Path::new(command)
            .file_stem()?  // Remove directory and extension (.exe, etc.)
            .to_str()?;
        self.command_policy
            .iter()
            .find(|cp| glob_match(&cp.pattern, basename))
            .map(|cp| cp.policy.as_str())
    }
}
}
```

---

## 5. Platform Implementations

### 5.1 Linux: Landlock + seccomp-BPF (default)

**Requirements:** Linux kernel ≥ 5.13 for Landlock v1. Kernel ≥ 5.19 for v2 (truncate rules). Kernel ≥ 6.7 for TCP port restrictions.

**What it does:**

1. Open Landlock ruleset with `LANDLOCK_CREATE_RULESET`
2. Add rules:
   - `READ_FILE + READ_DIR` on `/` (read-anywhere by default)
   - `REFER + WRITE_FILE + MAKE_*` only on whitelisted writable roots
3. `landlock_restrict_self()` — restrictions apply to this process and all children, cannot be removed
   
   **Note on `REFER`:** Hard links and cross-directory renames (e.g., `mv file /tmp/`) require the `REFER` right. We grant it only on writable roots (not globally on `/`) to prevent linking attacks. Add `/tmp` to `writable_roots` if you need cross-directory rename operations.
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

### 5.2 macOS: Seatbelt (`sandbox-exec`)

**Status:** `sandbox-exec` is marked deprecated in the man page since macOS 10.12, but the underlying kernel subsystem ("Seatbelt") powers all Apple system software and all major browsers. Claude Code, Codex CLI, and Cursor all use it in production as of 2025–2026. The SBPL profile language is the only viable lightweight option for macOS processes today.

**How it works:** Generate an SBPL profile string at runtime based on `$CWD` and declared policy, then exec the agent via `/usr/bin/sandbox-exec -p "$PROFILE" agent`.

**Security note:** Always use the hardcoded path `/usr/bin/sandbox-exec` (not just `sandbox-exec` from PATH). This defends against an attacker trying to inject a malicious version of the executable. If `/usr/bin/sandbox-exec` has been tampered with, the attacker already has root access.

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

; Read-restricted paths (deny read access to sensitive directories)
; (deny file-read* (subpath "/home/user/.ssh"))
; (deny file-read* (subpath "/home/user/.aws"))

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
- The `(allow default)` at the top means reads are allowed everywhere by default. Specific paths can be blocked with `(deny file-read*)` rules, which is how `read_restricted_paths` is implemented. This works well for blocking sensitive directories like `~/.ssh` while allowing general filesystem access.

**Alternatives evaluated and rejected:**

| Option | Verdict |
|---|---|
| App Sandbox (entitlements) | Requires code signing + notarization. Not applicable to arbitrary CLI wrappers. |
| Apple Containerization (`apple/container`, macOS 26) | Runs **Linux** containers only. Cannot sandbox macOS-native processes (Xcode, Metal, etc.). |
| Virtualization.framework (Tart, Lume) | Full macOS VM, 5–30s startup, high RAM. Breaks host toolchain. |
| Alcoholless (separate macOS user) | User-level isolation only, weaker guarantees, complex setup. |

### 5.3 Windows: Restricted Token + ACLs + WFP Firewall

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
cage-setup.exe
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

**Implementation approach:** Implement our own Windows sandbox module based on this approach. The `windows-sandbox-rs` crate depends on internal Codex workspace crates (`codex-protocol`, `codex-utils-absolute-path`, etc.) that are not published to crates.io, so we cannot vendor just `lib.rs`. Instead, write our own module using the Windows APIs directly:

- `windows` crate (v0.58) for `CreateRestrictedToken`, ACL functions, WFP APIs
- `windows-sys` crate (v0.52) for lower-level system calls
- Reference their implementation (~500 lines) for the approach, but use our own `SandboxPolicy` type

**Alternatives rejected:**

| Option | Verdict |
|---|---|
| Windows Sandbox (WSB) | Full Hyper-V VM with a separate Windows install. Cannot use host MSVC/Win32 SDK. |
| AppContainer | Requires app to declare capabilities via manifest. Cannot wrap arbitrary CLI tools. |
| WSL2 | Different kernel, different filesystem view. Breaks Windows-native toolchains. |

---

## 6. Environment Isolation

`cage` isolates the running command from the host environment by:
1. Filtering environment variables based on policy (allowlist/blocklist)
2. Creating a temporary directory for session state (logs, caches)
3. Respecting the user's actual `HOME` directory (not remapped)

### 6.1 Session temporary directory

Each `cage` session creates a temporary directory (`/tmp/cage-$PID/`) for session-specific state. This is **not** the `HOME` directory — the user's real home remains accessible at its normal path. The session directory can be used for:
- Audit logs of denied accesses
- Temporary caches that shouldn't persist
- Debug output

```
/tmp/cage-$PID/
├── audit.log                   # log of policy violations
├── cache/                      # ephemeral cache dir
└── ...                         # other session-specific files
```

**Note:** `HOME` environment variable remains pointing to the user's actual home directory. The sandbox restricts access via OS-level permissions (Landlock/Seatbelt/ACLs), not by remapping paths. Use `XDG_CONFIG_HOME` or application-specific env vars if you need to redirect config locations.

### 6.2 Environment variable handling

Environment variables are filtered using one of two modes:

| Mode | Behavior | Use case |
|---|---|---|
| `allowlist` | Only variables matching `env.allow` patterns are passed through | Maximum security - explicit opt-in |
| `blocklist` | All variables except those matching `env.block` are passed through | Convenient - only exclude sensitive vars |

To pass through all environment variables, use `mode = "blocklist"` with an empty `block` list.

In all modes, `env.set` variables are always applied after filtering and override any inherited values.

Example policies:
```toml
# Maximum security - only allow specific vars
[policies.strict.env]
mode = "allowlist"
allow = ["PATH", "TERM"]
set = { CAGE = "1" }

# Exclude sensitive credentials only
[policies.build.env]
mode = "blocklist"
block = ["*_TOKEN", "*_SECRET", "*_PASSWORD", "AWS_*"]
set = { CAGE = "1" }
```

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

## 8. Path Handling

`cage` operates on the host filesystem directly using OS-native permission mechanisms (Landlock, Seatbelt, Windows ACLs). There is no path remapping or bind mounting — all paths accessible inside the cage are at the same location as on the host.

| Mechanism | Same filesystem? | Path remapping? |
|---|---|---|
| Landlock + seccomp | ✅ Yes | ❌ No |
| bubblewrap | ✅ Yes | ✅ Yes (optional) |
| Seatbelt (macOS) | ✅ Yes | ❌ No |
| Windows restricted token + ACLs | ✅ Yes | ❌ No |

This design preserves the full host toolchain and ensures that:
- Absolute paths work identically inside and outside the cage
- No filesystem namespace setup is required (fast startup)
- Native platform toolchains (Xcode, MSVC, etc.) work without modification

---

## 9. CLI Interface

```
USAGE:
    cage [OPTIONS]... <COMMAND> [ARGS]...

ARGS:
    <COMMAND>        Command to run (any executable)
    [ARGS]...        Arguments to pass to the command

OPTIONS:
    -p, --policy <NAME[+NAME...]>   Named policy or merged set (default: "default")
        --allow-network             Shorthand for --policy <current>+full-network
        --no-sandbox                Run command unsandboxed (logs a warning)
        --backend <BACKEND>         Linux only: landlock (default) | bwrap
        --passthrough <PATH>        Add an extra read-only passthrough path (repeatable)
        --writable <PATH>           Add an extra writable root (repeatable)
        --write-restrict <PATH>     Add an extra write-restricted path (repeatable)
        --read-restrict <PATH>      Add an extra read-restricted path (repeatable)
    -v, --verbose                   Show sandbox configuration before exec
        --dry-run                   Print the sandbox config and generated profile, don't exec
    -h, --help                      Print help
    -V, --version                   Print version

EXAMPLES:
    cage opencode                       # Uses 'build' policy (from command_policy mapping)
    cage --allow-network claude         # Uses 'build' policy + adds network access
    cage --policy strict codex          # Overrides default, uses 'strict' policy
    cage --policy build+deploy ./build.sh
    cage --backend bwrap python script.py
    cage --no-sandbox npm test
```

---

## 10. Sandbox Escape Hatch (Phase 3)

**Use case:** Allow agents to request execution of commands outside the sandbox for global operations (system package installs, global tool configuration, accessing credentials outside the project directory).

**Two MCP tools:**
- `escape_bash` - Execute command outside sandbox; approval via pattern matching + agentic review (deferred design)
- `escape_bash_ask` - Always prompts user for approval; excluded from agent's default auto-approve rules

**Security:** All escape calls are logged. Each call is limited to a single command execution. No scope restrictions (full host access when approved).

---

## 11. Implementation Roadmap

### Phase 1 — Core (implement first)

- [ ] Policy config loading and merging
- [ ] Environment setup and temp dir isolation (§6)
- [ ] Linux: Landlock + seccomp using published `landlock` + `seccompiler` crates
- [ ] macOS: Seatbelt profile generator + `sandbox-exec` exec
- [ ] MCP socket passthrough (all platforms)
- [ ] Cleanup on exit (temp dirs, Windows firewall rules)

### Phase 2 — Completeness

- [ ] Windows: port `codex-rs/windows-sandbox-rs/src/lib.rs` (vendor, replace `SandboxPolicy`)
- [ ] Windows: one-time `cage-setup` installer
- [ ] Policy composition (`--policy a+b`)
- [ ] Command-to-policy mappings (`command_policy` in config)
- [ ] Config validation (detect conflicting settings)
- [ ] Structured audit log of denied accesses

### Phase 3 — Advanced

- [ ] Linux: bubblewrap backend (`--backend bwrap`) — stronger isolation with bind-mount remapping
- [ ] Linux kernel ≥ 6.7: Landlock TCP port restrictions for surgical network policy
- [ ] Network allowlist proxy mode (`network = "proxy"`) — route outbound through a domain-filtering HTTP proxy, similar to Claude Code's approach
- [ ] macOS Containerization (macOS 26+): Linux container mode for agents that only need Linux toolchain (Node/Python/Go/Rust); not suitable for Xcode/iOS work
- [ ] VM mode (`--isolation=vm`): Firecracker microVM for highest assurance; ~1–2s startup; suitable for CI
- [ ] Sandbox escape hatch (`escape_bash`, `escape_bash_ask` MCP tools) — allow agents to request command execution outside sandbox with approval

---

## 12. Dependency Strategy

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

### Windows implementation

Implement our own Windows sandbox module using the `windows` and `windows-sys` crates. Reference the approach in `codex-rs/windows-sandbox-rs/` for the three-layer mechanism (restricted token, ACLs, WFP), but write our own code rather than vendoring (the Codex crate depends on internal workspace crates not available on crates.io).

### Why not use Codex crates directly

- `codex-linux-sandbox`: binary-only crate, no `[lib]` target, not published
- `codex-core` (contains Landlock + Seatbelt code): not published to crates.io, internal API, couples you to OpenAI's `SandboxPolicy` type
- `codex-windows-sandbox`: has a `pub fn run_windows_sandbox_capture` but is not published; git dependency is fragile as OpenAI refactors internals

---

## 13. Security Notes

### macOS Seatbelt degradation

Seatbelt profile rules can silently stop working after OS updates. Mitigation:
- On startup, run a probe: attempt a write to a path that should be denied; if it succeeds, the profile is broken
- If `fail_on_sandbox_error = true` (default), abort with a clear error
- If `fail_on_sandbox_error = false`, warn and run unsandboxed

### Environment variable injection

Environment variables set via `.env` files or other mechanisms in the working directory cannot override the isolated environment that `cage` establishes. The cage sets `HOME` and other critical variables explicitly in the spawned process environment before exec, and these cannot be overridden by the command reading configuration files.

### Windows `%TEMP%` gap

Directories where `Everyone` has write access (notably `%TEMP%` and some shared folders) cannot be blocked by the restricted token + ACL approach because the write permission is granted independently of SID. Mitigation: inject stub executables for tools that could exfiltrate via temp files. This is a known limitation of the Windows approach (shared with Codex's implementation).

### Credential passthrough hygiene

- SSH private keys: not passed through by default
- API keys: in `allowlist` mode, only explicitly allowed vars are passed through; in `blocklist` mode, use `env.block` patterns to exclude sensitive credentials
- Config files: passed through read-only; originals are never made writable

**Recommended practice**: Use `allowlist` mode for production/CI, explicitly listing only required environment variables. Use `blocklist` mode for local development with convenient exclusion patterns like `["*_TOKEN", "*_SECRET", "AWS_*", "GITHUB_*"]`.

---

## 14. References

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
