use crate::policy::types::{EnvPolicy, NetworkPolicy, SandboxPolicy};
use crate::verbose_warn;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::Write;
use std::os::fd::IntoRawFd;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::process::{Command, Stdio};

/// Path to the sandbox-exec binary (hardcoded for security)
const SANDBOX_EXEC_PATH: &str = "/usr/bin/sandbox-exec";

/// Run a command in a Seatbelt sandbox
pub fn run_sandboxed(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
    verbose: bool,
) -> Result<i32> {
    // 1. Check sandbox-exec availability
    check_sandbox_exec()?;

    // 2. Canonicalize session temp directory (critical for /tmp -> /private/tmp)
    let canonical_tmpdir =
        std::fs::canonicalize(session_tmpdir).unwrap_or_else(|_| session_tmpdir.to_path_buf());

    // 3. Generate the Seatbelt profile (profile passed via pipe, no file path needed)
    let profile = build_seatbelt_profile(policy, &canonical_tmpdir, command);

    // 4. Create a pipe for passing the profile to sandbox-exec
    let (read_fd, write_fd) =
        nix::unistd::pipe().context("failed to create pipe for Seatbelt profile")?;

    // Set CLOEXEC on write end so it doesn't leak to the inner program
    // (sandbox-exec will read the profile, then exec the child which shouldn't have it)
    nix::fcntl::fcntl(
        write_fd.as_raw_fd(),
        nix::fcntl::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )?;

    // Get raw fd numbers for formatting
    let read_fd_num = read_fd.as_raw_fd();

    // 5. Build filtered environment
    let filtered_env = filter_environment(policy.env());

    // 6. Execute with sandbox-exec using /dev/fd for the profile
    let mut cmd = Command::new(SANDBOX_EXEC_PATH);
    cmd.arg("-f")
        .arg(format!("/dev/fd/{}", read_fd_num))
        .arg("--")
        .arg(command)
        .args(args)
        .env_clear()
        .envs(&filtered_env)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Pass the read end of the pipe to the child process (don't close it in parent yet)
    // We need to spawn first, then close in parent
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to spawn sandbox-exec for command: {}", command))?;

    // Close the read end in the parent process after spawn
    // The fd is inherited by sandbox-exec via fork() (no CLOEXEC on read end - needed for reading)
    // Note: There's a minor fd leak to the inner program - the read-end fd may
    // remain open in the sandboxed process. Write end has CLOEXEC set. Low risk (read-only, EOF).
    drop(read_fd);

    // 7. Write profile to the pipe in a separate thread
    // This allows sandbox-exec to consume the profile as we write it
    std::thread::spawn(move || {
        let mut file = unsafe { std::fs::File::from_raw_fd(write_fd.into_raw_fd()) };
        // Write profile; ignore BrokenPipe errors (sandbox-exec may exit early)
        let _ = file.write_all(profile.as_bytes());
        // write_fd closes when file is dropped
    });

    if verbose {
        eprintln!(
            "Executing: {} -f /dev/fd/{} -- {} {:?}",
            SANDBOX_EXEC_PATH, read_fd_num, command, args
        );
    }

    // 8. Wait for sandbox-exec to finish
    let status = child
        .wait()
        .context("failed to wait for sandboxed process")?;

    // Return exit code (0-255), or 1 if no exit code available
    Ok(status.code().unwrap_or(1))
}

/// Check that sandbox-exec is available at the expected path
fn check_sandbox_exec() -> Result<()> {
    if !Path::new(SANDBOX_EXEC_PATH).exists() {
        anyhow::bail!(
            "sandbox-exec not found at {}. This tool is required for macOS sandboxing. \
             It should be pre-installed on macOS systems.",
            SANDBOX_EXEC_PATH
        );
    }
    Ok(())
}

/// Canonicalize a path and escape it for SBPL
fn canonicalize_and_escape(path: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("failed to canonicalize path: {}", path.display()))?;
    Ok(sbpl_escape_path(&canonical.to_string_lossy()))
}

/// Escape special characters in SBPL paths
/// SBPL uses C-style string escaping within quoted strings.
/// We must escape backslashes, quotes, and control characters to prevent
/// injection of arbitrary SBPL rules via crafted path names.
fn sbpl_escape_path(path: &str) -> String {
    let mut escaped = String::with_capacity(path.len());
    for ch in path.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\0' => escaped.push_str("\\0"),
            c if c.is_control() => {
                // Escape other control characters as hex
                escaped.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => escaped.push(c),
        }
    }
    escaped
}

/// Build the complete Seatbelt profile (internal implementation)
fn build_seatbelt_profile(policy: &SandboxPolicy, session_tmpdir: &Path, _command: &str) -> String {
    let mut profile = String::new();

    // Header
    profile.push_str("(version 1)\n");
    profile.push_str("(allow default)\n\n");

    // ============================================
    // Filesystem Write Restrictions
    // ============================================
    profile.push_str("; Filesystem write restrictions\n");
    profile.push_str("(deny file-write* (subpath \"/\"))\n");

    // Allow writes to session temp directory
    let tmpdir_escaped = sbpl_escape_path(&session_tmpdir.to_string_lossy());
    profile.push_str(&format!(
        "(allow file-write* (subpath \"{}\"))\n",
        tmpdir_escaped
    ));

    // Allow writes to writable roots
    for path in &policy.writable_roots {
        match canonicalize_and_escape(path) {
            Ok(escaped) => {
                profile.push_str(&format!("(allow file-write* (subpath \"{}\"))\n", escaped));
            }
            Err(e) => {
                // Log warning but continue
                verbose_warn!("{}", e);
            }
        }
    }

    // Deny writes to restricted paths (more specific subpath rules override less specific ones)
    for path in &policy.write_restricted_paths {
        let escaped = match canonicalize_and_escape(path) {
            Ok(escaped) => escaped,
            Err(e) => {
                // For deny rules, fail secure: use raw path rather than dropping the restriction
                verbose_warn!("{}; using raw path for deny rule", e);
                sbpl_escape_path(&path.to_string_lossy())
            }
        };
        profile.push_str(&format!("(deny file-write* (subpath \"{}\"))\n", escaped));
    }

    profile.push('\n');

    // ============================================
    // Read Restrictions
    // ============================================
    if !policy.read_restricted_paths.is_empty() {
        profile.push_str("; Read restrictions\n");
        for path in &policy.read_restricted_paths {
            let escaped = match canonicalize_and_escape(path) {
                Ok(escaped) => escaped,
                Err(e) => {
                    // For deny rules, fail secure: use raw path rather than dropping the restriction
                    verbose_warn!("{}; using raw path for deny rule", e);
                    sbpl_escape_path(&path.to_string_lossy())
                }
            };
            profile.push_str(&format!("(deny file-read* (subpath \"{}\"))\n", escaped));
        }
        profile.push('\n');
    }

    // ============================================
    // Network Restrictions
    // ============================================
    profile.push_str("; Network restrictions\n");
    match policy.network() {
        NetworkPolicy::None => {
            profile.push_str("(deny network*)\n");
        }
        NetworkPolicy::Localhost => {
            profile.push_str("(deny network-outbound)\n");
            profile.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
            profile.push_str("(allow network-outbound (remote unix-socket))\n");
        }
        NetworkPolicy::Full => {
            profile.push_str("(allow network*)\n");
        }
    }
    profile.push('\n');

    // ============================================
    // GUI Passthrough (T1.14)
    // ============================================
    if policy.enable_gui() {
        profile.push_str("; GUI passthrough\n");
        profile.push_str("(allow iokit-open)\n"); // GPU/display/Metal access
        profile.push_str("(allow device*)\n"); // Input devices
        profile.push('\n');
    }

    // ============================================
    // Audio Passthrough (T1.14)
    // ============================================
    // (allow device*) is needed for audio; if GUI is already enabled,
    // it was emitted above, so only add it when GUI is off.
    if policy.enable_audio() && !policy.enable_gui() {
        profile.push_str("; Audio passthrough\n");
        profile.push_str("(allow device*)\n");
        profile.push('\n');
    }

    profile
}

/// Filter environment variables based on policy
fn filter_environment(env_policy: &EnvPolicy) -> HashMap<String, String> {
    // Build HashMap from current environment
    let env_vars: HashMap<String, String> = std::env::vars().collect();

    // Use the shared filter implementation from merge module
    env_policy.filter(&env_vars)
}

/// Generate the Seatbelt profile for dry-run display
/// This is a public version that matches the signature expected by main.rs
pub fn generate_seatbelt_profile(
    policy: &SandboxPolicy,
    _command: &str,
    _args: &[String],
    session_tmpdir: &Path,
) -> String {
    // Canonicalize to match run_sandboxed behavior (e.g., /tmp -> /private/tmp)
    let canonical_tmpdir =
        std::fs::canonicalize(session_tmpdir).unwrap_or_else(|_| session_tmpdir.to_path_buf());
    build_seatbelt_profile(policy, &canonical_tmpdir, _command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_sbpl_escape_path() {
        // Normal paths pass through unchanged
        assert_eq!(sbpl_escape_path("/tmp/test"), "/tmp/test");

        // Backslash and quote escaping
        assert_eq!(sbpl_escape_path("/tmp/test\"quote"), "/tmp/test\\\"quote");
        assert_eq!(sbpl_escape_path("C:\\Windows"), "C:\\\\Windows");
        assert_eq!(
            sbpl_escape_path("/path/with\\backslash\"and\"quote"),
            "/path/with\\\\backslash\\\"and\\\"quote"
        );

        // Control character escaping (prevents SBPL injection)
        assert_eq!(
            sbpl_escape_path("/tmp/with\nnewline"),
            "/tmp/with\\nnewline"
        );
        assert_eq!(sbpl_escape_path("/tmp/with\0null"), "/tmp/with\\0null");
    }

    #[test]
    fn test_sbpl_escape_newline_injection() {
        // A path with a newline should not be able to inject SBPL rules
        let malicious = "/tmp/evil\n\")\n(allow file-write* (subpath \"/\"))";
        let escaped = sbpl_escape_path(malicious);

        // The escaped string must not contain unescaped newlines or quotes
        // that could break out of an SBPL string literal
        assert!(!escaped.contains('\n'));
        assert!(!escaped.contains('\r'));
        // Every quote in the output must be preceded by a backslash
        for (i, ch) in escaped.char_indices() {
            if ch == '"' {
                assert!(
                    i > 0 && escaped.as_bytes()[i - 1] == b'\\',
                    "unescaped quote at position {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_sbpl_escape_null_byte() {
        let with_null = "/tmp/test\0evil";
        let escaped = sbpl_escape_path(with_null);
        assert!(!escaped.contains('\0'));
        assert!(escaped.contains("\\0"));
    }

    #[test]
    fn test_sbpl_escape_control_chars() {
        // Tab, carriage return
        assert_eq!(sbpl_escape_path("/tmp/\t"), "/tmp/\\t");
        assert_eq!(sbpl_escape_path("/tmp/\r"), "/tmp/\\r");

        // Other control characters get hex-escaped
        let with_bell = "/tmp/\x07bell";
        let escaped = sbpl_escape_path(with_bell);
        assert_eq!(escaped, "/tmp/\\x07bell");
    }

    #[test]
    fn test_deny_rules_use_raw_path_on_canonicalize_failure() {
        // If a restricted path doesn't exist, the raw path should still appear as a deny rule
        let mut policy = SandboxPolicy::default();
        policy.write_restricted_paths = vec![PathBuf::from("/nonexistent/restricted/path")];
        policy.read_restricted_paths = vec![PathBuf::from("/nonexistent/secret/path")];

        let tmpdir = Path::new("/tmp/cage-test");
        let profile = build_seatbelt_profile(&policy, tmpdir, "/bin/sh");

        // Both deny rules should be present even though paths don't exist
        assert!(
            profile.contains("(deny file-write* (subpath \"/nonexistent/restricted/path\"))"),
            "write-restricted deny rule should use raw path as fallback"
        );
        assert!(
            profile.contains("(deny file-read* (subpath \"/nonexistent/secret/path\"))"),
            "read-restricted deny rule should use raw path as fallback"
        );
    }

    #[test]
    fn test_audio_only_emits_device_rule() {
        let mut policy = SandboxPolicy::default();
        policy.enable_audio = Some(true);
        policy.enable_gui = Some(false);

        let tmpdir = Path::new("/tmp/cage-test");
        let profile = build_seatbelt_profile(&policy, tmpdir, "/bin/sh");

        assert!(profile.contains("; Audio passthrough\n(allow device*)\n"));
        assert!(!profile.contains("; GUI passthrough"));
    }

    #[test]
    fn test_gui_and_audio_no_duplicate_device_rule() {
        let mut policy = SandboxPolicy::default();
        policy.enable_gui = Some(true);
        policy.enable_audio = Some(true);

        let tmpdir = Path::new("/tmp/cage-test");
        let profile = build_seatbelt_profile(&policy, tmpdir, "/bin/sh");

        // (allow device*) should appear exactly once (from GUI section)
        let count = profile.matches("(allow device*)").count();
        assert_eq!(count, 1, "device rule should appear exactly once");
        // Should not have an empty audio section
        assert!(!profile.contains("; Audio passthrough"));
    }

    #[test]
    fn test_glob_match() {
        use crate::policy::merge::glob_match;
        assert!(glob_match("*", "anything"));
        assert!(glob_match("test*", "testfile"));
        assert!(glob_match("*test", "mytest"));
        assert!(glob_match("*test*", "mytestfile"));
        assert!(glob_match("test?file", "test1file"));
        assert!(!glob_match("test?file", "test12file"));
        assert!(glob_match("PATH", "PATH"));
        assert!(!glob_match("PATH", "path")); // case-sensitive
        assert!(glob_match("*_TOKEN", "API_TOKEN"));
        assert!(glob_match("*_TOKEN", "SECRET_TOKEN"));
        assert!(!glob_match("*_TOKEN", "TOKEN_API"));
    }

    #[test]
    fn test_filter_environment_blocklist() {
        use crate::policy::types::FilterAction;

        // Set up a test environment variable
        unsafe {
            std::env::set_var("TEST_VAR", "test_value");
            std::env::set_var("SECRET_TOKEN", "secret123");
        }

        let env_policy = EnvPolicy {
            mode: Some(crate::policy::types::EnvMode::DefaultAllow),
            filters: vec![crate::policy::types::EnvFilter {
                pattern: "*_TOKEN".to_string(),
                action: FilterAction::Block,
            }],
            set: HashMap::new(),
        };

        let filtered = filter_environment(&env_policy);

        // TEST_VAR should be present
        assert!(filtered.contains_key("TEST_VAR"));
        // SECRET_TOKEN should be blocked
        assert!(!filtered.contains_key("SECRET_TOKEN"));

        // Cleanup
        unsafe {
            std::env::remove_var("TEST_VAR");
            std::env::remove_var("SECRET_TOKEN");
        }
    }

    #[test]
    fn test_filter_environment_allowlist() {
        use crate::policy::types::FilterAction;

        unsafe {
            std::env::set_var("KEEP_VAR", "keep_value");
            std::env::set_var("REMOVE_VAR", "remove_value");
        }

        let env_policy = EnvPolicy {
            mode: Some(crate::policy::types::EnvMode::DefaultBlock),
            filters: vec![crate::policy::types::EnvFilter {
                pattern: "KEEP_*".to_string(),
                action: FilterAction::Allow,
            }],
            set: HashMap::new(),
        };

        let filtered = filter_environment(&env_policy);

        // KEEP_VAR should be present
        assert!(filtered.contains_key("KEEP_VAR"));
        assert_eq!(filtered.get("KEEP_VAR").unwrap(), "keep_value");
        // REMOVE_VAR should be absent
        assert!(!filtered.contains_key("REMOVE_VAR"));

        // Cleanup
        unsafe {
            std::env::remove_var("KEEP_VAR");
            std::env::remove_var("REMOVE_VAR");
        }
    }
}
