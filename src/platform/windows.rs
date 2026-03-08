use crate::policy::types::SandboxPolicy;
use std::path::Path;

/// Generate Windows sandbox configuration for dry-run display
pub fn generate_windows_sandbox_config(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> String {
    let mut config = String::new();
    config.push_str("Windows Sandbox Configuration:\n");
    config.push_str("================================\n\n");

    config.push_str(&format!("Command: {}\n", command));
    config.push_str(&format!("Args: {:?}\n", args));
    config.push_str(&format!(
        "Session temp dir: {}\n\n",
        session_tmpdir.display()
    ));

    config.push_str(&format!("Network policy: {:?}\n", policy.network()));
    config.push_str("\nWritable roots:\n");
    for path in &policy.writable_roots {
        config.push_str(&format!("  - {}\n", path.display()));
    }

    config.push_str("\nWrite-restricted paths:\n");
    for path in &policy.write_restricted_paths {
        config.push_str(&format!("  - {}\n", path.display()));
    }

    config.push_str("\nRead-restricted paths:\n");
    for path in &policy.read_restricted_paths {
        config.push_str(&format!("  - {}\n", path.display()));
    }

    config.push_str("\n[Note: Windows sandbox uses restricted token + ACLs]\n");

    config
}

pub fn run_sandboxed(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> anyhow::Result<i32> {
    todo!("T2.4-T2.5: Implement Windows restricted token launcher")
}
