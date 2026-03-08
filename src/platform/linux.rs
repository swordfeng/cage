use crate::policy::types::{EnvPolicy, NetworkPolicy, SandboxPolicy};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Check if bubblewrap is available and user namespaces are supported
fn check_bwrap_prerequisites() -> Result<()> {
    // Check bwrap availability
    let output = Command::new("bwrap")
        .arg("--version")
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "bubblewrap (bwrap) is not installed or not in PATH: {}. \
                 Please install bubblewrap (e.g., 'sudo apt install bubblewrap' on Debian/Ubuntu, \
                 'sudo dnf install bubblewrap' on Fedora, or 'sudo pacman -S bubblewrap' on Arch)",
                e
            )
        })?;

    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "bubblewrap (bwrap) returned an error when checking version"
        ));
    }

    // Check unprivileged user namespaces
    // Read /proc/sys/kernel/unprivileged_userns_clone if it exists
    let userns_path = "/proc/sys/kernel/unprivileged_userns_clone";
    if let Ok(content) = std::fs::read_to_string(userns_path) {
        let value: i32 = content.trim().parse().unwrap_or(1);
        if value == 0 {
            // Check if bwrap is setuid (which would work even without unprivileged userns)
            // Check common bwrap locations
            let bwrap_paths = ["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];
            let mut bwrap_path = None;
            for path in &bwrap_paths {
                if Path::new(path).exists() {
                    bwrap_path = Some(Path::new(path));
                    break;
                }
            }

            if let Some(path) = bwrap_path {
                let metadata =
                    std::fs::metadata(path).context("failed to check bwrap binary permissions")?;

                let permissions = metadata.permissions();
                let is_setuid = permissions.mode() & 0o4000 != 0;

                if !is_setuid {
                    return Err(anyhow::anyhow!(
                        "Unprivileged user namespaces are disabled on this system \
                         ({} = 0) and bwrap is not setuid. \
                         Either enable unprivileged user namespaces (echo 1 | sudo tee {}) \
                         or install a setuid bwrap binary.",
                        userns_path,
                        userns_path
                    ));
                }
            }
        }
    }

    Ok(())
}

/// Filter environment variables based on policy
fn filter_environment(env_policy: &EnvPolicy) -> HashMap<String, String> {
    // Build HashMap from current environment
    let env_vars: HashMap<String, String> = std::env::vars().collect();

    // Use the shared filter implementation from merge module
    env_policy.filter(&env_vars)
}

/// Simple glob matching supporting * and ? only
fn glob_match(pattern: &str, name: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let name_chars: Vec<char> = name.chars().collect();

    fn match_recursive(p: &[char], n: &[char], pi: usize, ni: usize) -> bool {
        let mut pi = pi;
        let mut ni = ni;

        while pi < p.len() {
            match p[pi] {
                '*' => {
                    // Try matching 0 or more characters
                    for skip in 0..=(n.len() - ni) {
                        if match_recursive(p, n, pi + 1, ni + skip) {
                            return true;
                        }
                    }
                    return false;
                }
                '?' => {
                    if ni >= n.len() {
                        return false;
                    }
                    pi += 1;
                    ni += 1;
                }
                c => {
                    if ni >= n.len() || c != n[ni] {
                        return false;
                    }
                    pi += 1;
                    ni += 1;
                }
            }
        }

        ni == n.len()
    }

    match_recursive(&pattern_chars, &name_chars, 0, 0)
}

/// Canonicalize a path, returning None if it doesn't exist
fn canonicalize_path(path: &Path) -> Option<std::path::PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// Generate the bubblewrap command line for dry-run display
pub fn generate_bwrap_argv(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> Vec<String> {
    let mut argv = vec!["bwrap".to_string()];

    // Basic sandbox setup: --ro-bind / / first
    argv.push("--ro-bind".to_string());
    argv.push("/".to_string());
    argv.push("/".to_string());

    // Device and proc filesystems
    argv.push("--dev".to_string());
    argv.push("/dev".to_string());

    argv.push("--proc".to_string());
    argv.push("/proc".to_string());

    // Writable roots (in order)
    for path in &policy.writable_roots {
        if let Some(canonical) = canonicalize_path(path) {
            argv.push("--bind".to_string());
            argv.push(canonical.to_string_lossy().to_string());
            argv.push(canonical.to_string_lossy().to_string());
        }
    }

    // Session temp dir
    if let Some(canonical) = canonicalize_path(session_tmpdir) {
        argv.push("--bind".to_string());
        argv.push(canonical.to_string_lossy().to_string());
        argv.push(canonical.to_string_lossy().to_string());
    }

    // Write-restricted paths (read-only overlays - applied after writable roots)
    for path in &policy.write_restricted_paths {
        if let Some(canonical) = canonicalize_path(path) {
            argv.push("--ro-bind".to_string());
            argv.push(canonical.to_string_lossy().to_string());
            argv.push(canonical.to_string_lossy().to_string());
        }
    }

    // Read-restricted paths (deny all access)
    // Directories: --perms 0000 --tmpfs mounts a new empty filesystem with no permission
    //   bits; --remount-ro prevents chmod from inside the sandbox bypassing the restriction.
    // Files: --ro-bind /dev/null masks the file with a character device; inside bwrap's
    //   user namespace the process lacks device access capabilities, so reads get EACCES.
    for path in &policy.read_restricted_paths {
        if let Some(canonical) = canonicalize_path(path) {
            let s = canonical.to_string_lossy().to_string();
            if canonical.is_dir() {
                argv.push("--perms".to_string());
                argv.push("0000".to_string());
                argv.push("--tmpfs".to_string());
                argv.push(s.clone());
                argv.push("--remount-ro".to_string());
                argv.push(s);
            } else {
                argv.push("--ro-bind".to_string());
                argv.push("/dev/null".to_string());
                argv.push(s);
            }
        }
    }

    // Network policy
    match policy.network() {
        NetworkPolicy::None => {
            argv.push("--unshare-net".to_string());
        }
        NetworkPolicy::Localhost => {
            // For localhost policy, we share network but will use seccomp in Phase 1b
            argv.push("--share-net".to_string());
        }
        NetworkPolicy::Full => {
            argv.push("--share-net".to_string());
        }
    }

    // Unshare PID and IPC namespaces; die with parent (always)
    // --unshare-ipc prevents sandbox from accessing host IPC (shared memory, semaphores)
    argv.push("--unshare-pid".to_string());
    argv.push("--unshare-ipc".to_string());
    argv.push("--die-with-parent".to_string());

    // Command separator and the actual command
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
) -> Result<i32> {
    // Check prerequisites (bwrap availability and user namespace support)
    check_bwrap_prerequisites().context("failed to verify bubblewrap prerequisites")?;

    // Filter environment according to policy
    let filtered_env = filter_environment(policy.env());

    // Build bwrap command
    let bwrap_argv = generate_bwrap_argv(policy, command, args, session_tmpdir);

    // Execute bwrap with filtered environment
    let mut cmd = Command::new(&bwrap_argv[0]);
    cmd.args(&bwrap_argv[1..]);

    // Clear environment and set filtered values
    cmd.env_clear();
    for (key, value) in filtered_env {
        cmd.env(key, value);
    }

    // Execute and wait for completion
    let status = cmd
        .status()
        .with_context(|| format!("failed to execute bwrap command: {:?}", bwrap_argv))?;

    // Return exit code
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_match() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("test*", "test123"));
        assert!(glob_match("*test", "mytest"));
        assert!(glob_match("*test*", "mytest123"));
        assert!(glob_match("test?", "test1"));
        assert!(glob_match("?test", "1test"));
        assert!(!glob_match("test?", "test"));
        assert!(!glob_match("test?", "test12"));
        assert!(glob_match("*_TOKEN", "API_TOKEN"));
        assert!(glob_match("*_TOKEN", "GITHUB_TOKEN"));
        assert!(!glob_match("*_TOKEN", "TOKEN_API"));
    }

    #[test]
    fn test_filter_environment_allowlist() {
        unsafe {
            std::env::set_var("CAGE_TEST_PATH", "/usr/bin");
            std::env::set_var("CAGE_TEST_HOME", "/home/user");
            std::env::set_var("CAGE_TEST_SECRET", "secret123");
        }

        // Parse policy from TOML to get proper filter ordering
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "allowlist"
allow = ["CAGE_TEST_PATH", "CAGE_TEST_H*"]
set = { CAGE_TEST_EXTRA = "extra_value" }
"#,
        )
        .unwrap();

        let filtered = filter_environment(&policy);

        assert!(filtered.contains_key("CAGE_TEST_PATH"));
        assert!(filtered.contains_key("CAGE_TEST_HOME")); // matches CAGE_TEST_H*
        assert!(!filtered.contains_key("CAGE_TEST_SECRET")); // does not match either pattern
        assert_eq!(
            filtered.get("CAGE_TEST_EXTRA"),
            Some(&"extra_value".to_string())
        );

        unsafe {
            std::env::remove_var("CAGE_TEST_PATH");
            std::env::remove_var("CAGE_TEST_HOME");
            std::env::remove_var("CAGE_TEST_SECRET");
        }
    }

    #[test]
    fn test_filter_environment_blocklist() {
        unsafe {
            std::env::set_var("CAGE_TEST_API_TOKEN", "secret123");
            std::env::set_var("CAGE_TEST_NORMAL", "normal_value");
        }

        // Parse policy from TOML to get proper filter ordering
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "blocklist"
block = ["*_TOKEN"]
"#,
        )
        .unwrap();

        let filtered = filter_environment(&policy);

        assert!(!filtered.contains_key("CAGE_TEST_API_TOKEN"));
        assert!(filtered.contains_key("CAGE_TEST_NORMAL"));

        unsafe {
            std::env::remove_var("CAGE_TEST_API_TOKEN");
            std::env::remove_var("CAGE_TEST_NORMAL");
        }
    }
}
