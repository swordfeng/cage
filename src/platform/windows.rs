use crate::policy::types::SandboxPolicy;
use std::path::Path;

/// Generate Windows sandbox configuration for dry-run display
///
/// # Note on GUI/Audio Support
/// Windows inherently supports GUI and audio passthrough for sandboxed processes.
/// The `enable_gui` and `enable_audio` flags are accepted for cross-platform
/// configuration compatibility (same config works on Linux/macOS/Windows).
/// On Windows, these flags have no effect as the sandbox accounts naturally
/// have access to the interactive desktop and audio APIs.
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

    // Log GUI/audio flags for visibility in dry-run (Windows has inherent support)
    config.push_str(&format!(
        "GUI enabled: {} (inherent on Windows)\n",
        policy.enable_gui()
    ));
    config.push_str(&format!(
        "Audio enabled: {} (inherent on Windows)\n",
        policy.enable_audio()
    ));

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
    config.push_str("[Note: GUI and audio access are inherent on Windows; no additional configuration needed]\n");

    config
}

/// Run a command in the Windows sandbox
///
/// # Note on GUI/Audio Support
/// Windows inherently supports GUI and audio passthrough for sandboxed processes.
/// The sandboxed process runs as a standard user account with access to the
/// interactive desktop and window station, enabling display and audio output
/// without additional configuration.
pub fn run_sandboxed(
    policy: &SandboxPolicy,
    _command: &str,
    _args: &[String],
    _session_tmpdir: &Path,
    verbose: bool,
) -> anyhow::Result<i32> {
    // Log GUI/audio flags for visibility (Windows has inherent support)
    if verbose {
        eprintln!("GUI enabled: {} (inherent on Windows)", policy.enable_gui());
        eprintln!(
            "Audio enabled: {} (inherent on Windows)",
            policy.enable_audio()
        );
    }

    todo!("T2.4-T2.5: Implement Windows restricted token launcher")
}
