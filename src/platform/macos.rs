use crate::policy::types::SandboxPolicy;
use std::path::Path;

/// Generate the Seatbelt profile for dry-run display
pub fn generate_seatbelt_profile(
    policy: &SandboxPolicy,
    _command: &str,
    _args: &[String],
    _session_tmpdir: &Path,
) -> String {
    let mut profile = String::new();
    profile.push_str("(version 1)\n");
    profile.push_str("(allow default)\n\n");

    // Deny all writes by default
    profile.push_str("(deny file-write* (subpath \"/\"))\n\n");

    // Allow writes to writable roots
    for path in &policy.writable_roots {
        let escaped = sbpl_escape_path(&path.to_string_lossy());
        profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", escaped));
    }

    // Deny writes to restricted paths (after allows - last rule wins)
    for path in &policy.write_restricted_paths {
        let escaped = sbpl_escape_path(&path.to_string_lossy());
        profile.push_str(&format!("(deny file-write* (subpath \"{}\"))\n", escaped));
    }

    // Deny reads to restricted paths
    for path in &policy.read_restricted_paths {
        let escaped = sbpl_escape_path(&path.to_string_lossy());
        profile.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", escaped));
    }

    // Network rules
    match policy.network() {
        crate::policy::types::NetworkPolicy::None => {
            profile.push_str("\n; Network: none\n");
            profile.push_str("(deny network*)\n");
        }
        crate::policy::types::NetworkPolicy::Localhost => {
            profile.push_str("\n; Network: localhost\n");
            profile.push_str("(allow network-inbound (local ip \"localhost\"))\n");
            profile.push_str("(allow network-outbound (remote ip \"localhost\"))\n");
            profile.push_str("(allow network-outbound (remote unix-socket))\n");
        }
        crate::policy::types::NetworkPolicy::Full => {
            profile.push_str("\n; Network: full\n");
            profile.push_str("(allow network*)\n");
        }
    }

    profile
}

/// Escape special characters in SBPL paths
fn sbpl_escape_path(path: &str) -> String {
    path.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn run_sandboxed(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> anyhow::Result<i32> {
    todo!("T1.8: Implement macOS Seatbelt launcher")
}
