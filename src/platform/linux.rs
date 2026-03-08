use crate::policy::types::SandboxPolicy;
use std::path::Path;

/// Generate the bubblewrap command line for dry-run display
pub fn generate_bwrap_argv(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> Vec<String> {
    let mut argv = vec!["bwrap".to_string()];

    // Basic sandbox setup
    argv.push("--ro-bind".to_string());
    argv.push("/".to_string());
    argv.push("/".to_string());

    argv.push("--dev".to_string());
    argv.push("/dev".to_string());

    argv.push("--proc".to_string());
    argv.push("/proc".to_string());

    // Writable roots
    for path in &policy.writable_roots {
        argv.push("--bind".to_string());
        argv.push(path.to_string_lossy().to_string());
        argv.push(path.to_string_lossy().to_string());
    }

    // Session temp dir
    argv.push("--bind".to_string());
    argv.push(session_tmpdir.to_string_lossy().to_string());
    argv.push(session_tmpdir.to_string_lossy().to_string());

    // Write-restricted paths (read-only overlays)
    for path in &policy.write_restricted_paths {
        argv.push("--ro-bind".to_string());
        argv.push(path.to_string_lossy().to_string());
        argv.push(path.to_string_lossy().to_string());
    }

    // Network policy
    match policy.network() {
        crate::policy::types::NetworkPolicy::None => {
            argv.push("--unshare-net".to_string());
        }
        _ => {} // Full and Localhost share network for now
    }

    // Unshare PID and die with parent
    argv.push("--unshare-pid".to_string());
    argv.push("--die-with-parent".to_string());

    // Command
    argv.push("--".to_string());
    argv.push(command.to_string());
    argv.extend(args.iter().cloned());

    argv
}

pub fn run_sandboxed(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> anyhow::Result<i32> {
    todo!("T1.7: Implement Linux bubblewrap launcher")
}
