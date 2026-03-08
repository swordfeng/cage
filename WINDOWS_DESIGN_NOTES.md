# Windows Sandbox Design Notes

Design decisions and analysis for `SPEC.md §5.3 — Windows sandbox`.

---

## Restricted Token Mechanics (Corrected Understanding)

Our earlier understanding of `CreateRestrictedToken` was inaccurate. Here is the corrected model, verified against Microsoft documentation and David LeBlanc's "Practical Windows Sandboxing" series.

### Dual Access Check

When a restricted token accesses a securable object, Windows performs **two** access checks:

1. **Normal check**: uses the token's enabled SIDs (user SID + enabled groups). Standard `AccessCheck()`.
2. **Restricting check**: uses ONLY the restricting SID list as if it were the token's SID list. Same `AccessCheck()` algorithm.

The final granted access = **intersection** (bitwise AND) of both checks. Both must independently grant the requested access.

**Critical: the restricting check is ANY-match, not ALL-match.** The system walks the DACL and checks if ANY restricting SID matches an Allow ACE. Multiple restricting SIDs can contribute different access bits. There is no requirement that all restricting SIDs match — it works exactly like a normal access check, just with a different SID list.

Example (from LeBlanc): file ACL = `Admins:F, You:F, Restricted:R`. First pass grants F (user SID matches). Second pass grants R (RESTRICTED SID matches). Intersection = R.

### SidsToRestrict — Can Be Arbitrary SIDs

Restricting SIDs do NOT need to be groups the token owner belongs to. They do not need to exist in AD or local SAM. LeBlanc: "you can actually make up completely different SIDs that don't map to any user and add those if you like."

**Mandatory inclusion:** The well-known `RESTRICTED` SID (S-1-5-12) MUST be in the restricting list. Many system objects (desktops, window stations) have ACEs for this SID. Without it, the process fails to initialize. Also include `Everyone` (S-1-1-0) and `Users` (S-1-5-32-545) for system path read access, and `LOGON_SID` for window station/desktop access.

### SidsToDisable (Deny-Only)

Adding a SID to `SidsToDisable` sets `SE_GROUP_USE_FOR_DENY_ONLY`: the SID matches only Deny ACEs, never Allow ACEs. Can be applied to any SID including the token's own user SID. Used to prevent privilege escalation through the user's own identity.

### CreateRestrictedToken Works on LogonUser Tokens

`CreateRestrictedToken` accepts any token handle, including one from `LogonUser`. LeBlanc explicitly lists `LogonUser` as a valid source. The resulting token retains the original user identity (e.g., CageOffline) in the normal SID list while adding restricting SIDs as a separate list.

### ACL Inheritance Propagation

`SetNamedSecurityInfoW` with inheritable ACEs (`CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE`) **automatically propagates to ALL existing children**, synchronously, during the API call. This is the "new model" (Windows 2000+) behavior confirmed by Raymond Chen and MSDN.

- Propagation is recursive to the full subtree
- Synchronous/blocking — completes before the call returns
- Existing explicit (non-inherited) ACEs on children are preserved
- Children with `SE_DACL_PROTECTED` block propagation at that point
- `TreeSetNamedSecurityInfo` provides the same propagation plus a progress callback

**For cage**: a single `SetNamedSecurityInfoW` call on `$CWD` with inheritable ACEs propagates to all existing files. This is O(n) in file count but requires no manual tree walk. `TreeSetNamedSecurityInfo` with `FN_PROGRESS` callback can report progress for large workspaces.

### User Profile Default ACLs

User profile directories are ACLed to `SYSTEM + Administrators + owner` only. `BUILTIN\Users` has NO ACE on `C:\Users\<username>\`. A separate user account (e.g., CageOffline) has **zero access** to the user's profile unless explicitly granted.

---

## Design: Hybrid Restricted Token + User Account Switching

Based on the corrected understanding, the design uses **both** mechanisms:

- **Restricted token** (SidsToRestrict) for filesystem write scoping
- **User account switching** (LogonUser) for WFP network policy enforcement
- **`full` policy**: current user's own token (no account switch), restricted with SidsToRestrict only

### Why the Hybrid

| Mechanism | Filesystem | Network (WFP) |
|---|---|---|
| SidsToRestrict only | Correct (second access check limits writes) | Impossible (WFP can't see restricting SIDs) |
| User account only | O(n) ACL cost, no fine-grained scoping | Correct (WFP matches user SID) |
| **Hybrid** | **Correct** (restricting SIDs scope writes) | **Correct** (user SID for WFP) |

The hybrid avoids the pure-account design's problem: with SidsToRestrict, the **normal check** can pass broadly (via group membership or broad ACEs), while the **restricting check** limits actual access to only paths with matching ACEs. This means we don't need per-file ACEs for every restricting SID — we only need ACEs for the restricting SIDs on paths we want to grant.

### Account Structure

**Static accounts** (created during elevated setup, per installing user):

| Account | Used for | WFP rule (static) |
|---|---|---|
| `<user>-CageOffline` | `none` network policy | BLOCK all outbound (V4+V6) |
| `<user>-CageLocalhostOnly` | `localhost` network policy | PERMIT 127.0.0.1/::1 + BLOCK rest |
| (current user) | `full` network policy | none |

**Static group:**
- `<user>-CageUsers` — contains both sandbox accounts. Used for:
  - Read ACE on user profile (normal check needs this)
  - Deny ACEs on `write_restricted_paths`

**Dynamic groups** (created per workspace, cached):
- `<user>-CageWS-<hash>` — one per workspace path. Write ACE placed on workspace directory with inheritance. Used as a restricting SID to scope writes.

**Policy group** (created per unique policy config, cached):
- `<user>-CagePolicy-<hash>` — write ACE on global writable paths (e.g., `%TEMP%`). Used as a restricting SID.

### Token Composition

For `none`/`localhost` policies:

```
LogonUser("<user>-CageOffline" or "<user>-CageLocalhostOnly")
  → base token (user SID = sandbox account)

CreateRestrictedToken(base_token,
  SidsToRestrict = [
    <user>-CageWS-<hash>,      // workspace write access
    <user>-CagePolicy-<hash>,  // global writable paths
    <user>-CageUsers,          // user profile read access
    BUILTIN\Users,             // system path read access
    Everyone,                  // broad read fallback
    RESTRICTED,                // MANDATORY - desktop/window station access
    LogonSID                   // window station/desktop access
  ],
  SidsToDisable = [
    // disable any unexpected groups to minimize normal check surface
  ]
)
```

For `full` policy:

```
OpenProcessToken(current_process)
  → base token (user SID = current user)

CreateRestrictedToken(base_token,
  SidsToRestrict = [same list as above],
  SidsToDisable = [
    BUILTIN\Administrators,    // if user is admin, prevent elevation
    // other dangerous groups
  ]
)
```

### How the Dual Access Check Works Per Path

**Key insight:** Sandbox accounts are added as **members** of each workspace group (`CageWS-<hash>`). This means the workspace group SID appears in both the normal SID list (via group membership) and the restricting SID list (via `SidsToRestrict`). One ACE on the workspace serves both checks.

**Workspace write** (`$CWD/src/main.rs`):

| Check | SIDs evaluated | ACE matched | Result |
|---|---|---|---|
| Normal | CageOffline, CageWS-<hash> (member), CageUsers, Users, ... | CageWS-<hash> write ACE (inherited from $CWD) | WRITE ✓ |
| Restricting | CageWS-<hash>, CagePolicy-<hash>, CageUsers, Users, Everyone, RESTRICTED | CageWS-<hash> write ACE (same ACE) | WRITE ✓ |
| **Result** | | Intersection | **WRITE ✓** |

**Cross-workspace isolation** (`other $CWD_B`):

| Check | SIDs evaluated | ACE matched | Result |
|---|---|---|---|
| Normal | CageOffline, CageWS-A (member), CageUsers, Users, ... | CageWS-B ACE? CageOffline is NOT a member of CageWS-B | WRITE ✗ |
| **Result** | Normal check fails — denied before restricting check | | **DENIED** |

**For `full` policy** (current user token): user owns the files → normal check passes via ownership. Restricting check: `CageWS-<hash>` in restricting list matches the ACE. No group membership needed.

**Access matrix:**

| Path | Normal check passes via | Restricting check passes via | Net result |
|---|---|---|---|
| `$CWD` (workspace) | CageWS-<hash> membership (sandbox) or owner (full) | CageWS-<hash> write ACE | WRITE |
| `%TEMP%`, global writable | Everyone/Users (typically writable) | CagePolicy-<hash> write ACE | WRITE |
| User profile (read) | CageUsers read ACE | CageUsers in restricting list | READ |
| System paths (read) | BUILTIN\Users (standard) | Users/Everyone in restricting list | READ |
| `.git/`, restricted paths | CageUsers deny ACE blocks | Deny ACE also blocks | DENIED |
| Other locations | Maybe read via Users/Everyone | No restricting SID has ACE | DENIED |

### ACL Setup Per Workspace (O(n), Cached)

**Triggered by `cage-setup --prepare <workspace_path> --policy <policy_name>`**:

1. Create group `<user>-CageWS-<hash>` for the workspace
2. Add both sandbox accounts (`CageOffline`, `CageLocalhostOnly`) as members of the group
3. `SetNamedSecurityInfoW` on `<workspace_path>`:
   - Single inheritable write ACE for `CageWS-<hash>` (serves both checks — normal via membership, restricting via SidsToRestrict)
   - Windows automatically propagates to all existing children (O(n), synchronous)
4. Cache workspace hash → group SID mapping in registry (`HKCU\Software\Cage\Workspaces\<hash>`)
5. Create policy group `<user>-CagePolicy-<hash>` if not cached
6. Apply inheritable write ACEs for policy group on each global writable path (`%TEMP%`, etc.)
7. Apply inheritable deny ACEs for `<user>-CageUsers` on each `write_restricted_path`

**At runtime:** Look up cached group SIDs from registry. If not found, error with "run `cage-setup --prepare <path> --policy <name>`".

**This amortizes the O(n) cost**: preparation is slow (one-time per workspace), runtime is instant. Codex's approach (broad home-dir grant) is O(n-home) once; our approach is O(n-workspace) per unique workspace, but correctly scoped.

**ACL modifications happen during `cage-setup --prepare`.** The `--prepare` command runs elevated to install WFP rules, then drops elevation for ACL modifications. `SetNamedSecurityInfoW` uses the user's token at that point. The user can only modify DACLs on objects they own or have `WRITE_DAC` on. This ensures sandbox groups/accounts never receive permissions beyond the user's own scope — no escalation to system paths. If a file in the workspace is owned by another user, the ACL propagation will skip it (correct behavior).

### WFP Rules (Static)

Installed once by `cage-setup.exe`:

```
Provider: CageWFP (GUID: ...)
Sublayer: CageSandbox (GUID: ...)

Filter 1: BLOCK outbound V4, condition: user == <user>-CageOffline SID
Filter 2: BLOCK outbound V6, condition: user == <user>-CageOffline SID
Filter 3: PERMIT outbound V4, condition: user == <user>-CageLocalhostOnly AND remote_ip == 127.0.0.0/8 (high weight)
Filter 4: PERMIT outbound V6, condition: user == <user>-CageLocalhostOnly AND remote_ip == ::1 (high weight)
Filter 5: BLOCK outbound V4, condition: user == <user>-CageLocalhostOnly (low weight)
Filter 6: BLOCK outbound V6, condition: user == <user>-CageLocalhostOnly (low weight)
```

No runtime WFP modifications. No cleanup on exit. Static rules keyed to account SIDs.

For `full` policy: process runs as current user — no WFP rule matches — unrestricted network.

### Concurrent Session Isolation

| Scenario | Network | Filesystem |
|---|---|---|
| `none` + `localhost` | Fully isolated (different accounts) | Fully isolated (different workspaces → account not member of other's CageWS group → normal check fails) |
| `none` + `full` | Fully isolated | Fully isolated |
| `localhost` + `full` | Fully isolated | Fully isolated |
| Two `none`, different workspaces | Same WFP rule (correct) | Fully isolated — CageOffline is member of CageWS-A but NOT CageWS-B; normal check fails for workspace B |
| Two `none`, same workspace | Same WFP rule (correct) | **Shared** — same account, same workspace group membership |

**Key improvement over previous designs**: by adding sandbox accounts as members of per-workspace groups (instead of using a broad CageUsers write ACE), cross-workspace isolation works at **both** check levels. The normal check itself blocks writes to workspaces the account is not a member of, before the restricting check is even evaluated.

**Remaining limitation**: Same-policy, same-workspace concurrent sessions share identity. Acceptable for Phase 1.

### Credential Management

- Setup (elevated): create accounts with random passwords
- Passwords encrypted with DPAPI (user-specific, machine-bound) and stored in `HKCU\Software\Cage\Credentials\`
- Runtime: decrypt password → `LogonUser(account, password, LOGON32_LOGON_BATCH)` → token

### Process Launch (TBD)

The `LogonUser` → `CreateRestrictedToken` → `CreateProcessAsUserW` flow requires `SeIncreaseQuotaPrivilege` (and possibly `SeAssignPrimaryTokenPrivilege` depending on token source). The exact mechanism is deferred to implementation:

**Option A:** Grant `SeIncreaseQuotaPrivilege` to installing user at setup time
**Option B:** Use `CreateProcessWithLogonW` (no privileges needed, but cannot use restricted tokens)
**Option C:** LocalSystem helper service to broker process creation (has all privileges)

Current design favors Option A or C. Decision pending implementation validation.

### Cleanup

**Per-session cleanup:** None needed for ACLs (workspace ACEs are persistent and cached). No WFP cleanup (static rules).

**Periodic maintenance** (`cage cleanup`): scan `HKCU\Software\Cage\Workspaces\` for stale entries (not used in N days). Remove ACEs from workspace, delete group, delete registry key.

**Uninstall** (`cage-setup --uninstall`): remove WFP rules, delete accounts, delete all groups, remove ACEs, delete registry keys.

---

## Previous Designs (Superseded)

### Pure three-account design (superseded by hybrid)

Used `CreateProcessAsUserW` with three fixed accounts (`CageOffline`, `CageLocalhostOnly`, `CageOnline`) without restricting SIDs. Required per-file ACEs for the sandbox account on every file in the workspace — O(n) per session with no caching benefit, because ACEs were removed on exit.

### Two-group restricting SID design (superseded — incorrect)

Used `CageFilesystem` and `CageNetwork` groups in `SidsToRestrict` without account switching. Failed because WFP cannot match restricting SIDs.

---

## Codex windows-sandbox-rs Reference

- Two accounts: `CodexSandboxOffline`, `CodexSandboxOnline`
- Uses `CreateProcessAsUserW` — pure account switching, no restricting SIDs
- Group: `CodexSandboxUsers` for ACL management
- Network: per-user WFP rule on `CodexSandboxOffline` SID
- `localhost` and `full` share `CodexSandboxOnline` — over-restriction when concurrent
- Filesystem: broad ACL grant on `C:\Users\<you>` (known bug — home dir pollution)
- ACLs never revoked on exit (accumulate, orphan SIDs after uninstall)
- 37/41 smoke tests pass; known gaps: browser launch bypass, world-writable dirs, `unified_exec` bypass

---

## Key Sources

- David LeBlanc, "Practical Windows Sandboxing" Parts 1-3 (Microsoft Learn Archive)
- Microsoft Learn: CreateRestrictedToken, Restricted Tokens, Automatic Propagation of Inheritable ACEs
- Raymond Chen: "Why doesn't RegSetKeySecurity propagate inheritable ACEs?" (The Old New Thing)
- MS-DTYP: Access Check Algorithm Pseudocode (EvaluateTokenAgainstDescriptor)
