use crate::policy::types::{EnvFilter, EnvPolicy, FilterAction, NetworkPolicy, SandboxPolicy};
use crate::verbose_warn;
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::RawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

/// System global install locations for bwrap, in order of preference
pub const BWRAP_GLOBAL_PATHS: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

/// Find bwrap binary in system global install locations
pub fn find_bwrap_binary() -> Option<PathBuf> {
    for path in BWRAP_GLOBAL_PATHS {
        let p = Path::new(path);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Check if bubblewrap is available and user namespaces are supported
/// Returns the full path to the bwrap binary
fn check_bwrap_prerequisites() -> Result<PathBuf> {
    // Find bwrap in system global locations (not PATH)
    let bwrap_path = find_bwrap_binary().ok_or_else(|| {
        anyhow::anyhow!(
            "bubblewrap (bwrap) is not installed in a system location. \
             Searched: {}. \
             Please install bubblewrap (e.g., 'sudo apt install bubblewrap' on Debian/Ubuntu, \
             'sudo dnf install bubblewrap' on Fedora, or 'sudo pacman -S bubblewrap' on Arch)",
            BWRAP_GLOBAL_PATHS.join(", ")
        )
    })?;

    // Check bwrap availability by running --version
    let output = Command::new(&bwrap_path)
        .arg("--version")
        .output()
        .map_err(|e| {
            anyhow::anyhow!(
                "bubblewrap (bwrap) is installed at {} but cannot be executed: {}. \
                 Please check permissions and installation.",
                bwrap_path.display(),
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
            let metadata = std::fs::metadata(&bwrap_path)
                .context("failed to check bwrap binary permissions")?;

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

    Ok(bwrap_path)
}

/// Filter environment variables based on policy
fn filter_environment(env_policy: &EnvPolicy) -> HashMap<String, String> {
    // Build HashMap from current environment
    let env_vars: HashMap<String, String> = std::env::vars().collect();

    // Use the shared filter implementation from merge module
    env_policy.filter(&env_vars)
}

/// Canonicalize a path, returning None if it doesn't exist
fn canonicalize_path(path: &Path) -> Option<std::path::PathBuf> {
    std::fs::canonicalize(path).ok()
}

/// Get XDG_RUNTIME_DIR path
/// Returns the environment variable if set, otherwise defaults to /run/user/<uid>
fn get_xdg_runtime_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        if !dir.is_empty() {
            let path = PathBuf::from(dir);
            return path;
        }
    }

    // Fallback to /run/user/<uid>
    let uid = nix::unistd::getuid().as_raw();
    let path = PathBuf::from(format!("/run/user/{}", uid));
    return path;
}

/// Probe directory for entries matching a prefix and return matching paths
fn probe_runtime_sockets(runtime_dir: &Path, prefix: &str) -> Vec<PathBuf> {
    let mut sockets = Vec::new();

    if let Ok(entries) = std::fs::read_dir(runtime_dir) {
        for entry in entries.flatten() {
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(prefix) {
                    sockets.push(entry.path());
                }
            }
        }
    }

    sockets
}

/// Create a memfd with null-separated bwrap arguments
fn create_args_memfd(args: &[String]) -> anyhow::Result<RawFd> {
    use nix::sys::memfd::{MemFdCreateFlag, memfd_create};
    use std::io::Seek;
    use std::os::unix::io::IntoRawFd;

    let fd = memfd_create(c"bwrap-args", MemFdCreateFlag::empty())
        .with_context(|| "failed to create memfd for bwrap arguments")?;

    // Convert to std::fs::File for easier manipulation
    let mut file = std::fs::File::from(fd);

    // Write null-separated arguments
    for arg in args {
        std::io::Write::write_all(&mut file, arg.as_bytes())
            .with_context(|| format!("failed to write argument to memfd: {}", arg))?;
        std::io::Write::write_all(&mut file, &[0])
            .with_context(|| "failed to write null separator to memfd")?;
    }

    // Seek back to start for reading
    file.seek(std::io::SeekFrom::Start(0))
        .with_context(|| "failed to seek memfd to start")?;

    Ok(file.into_raw_fd())
}

/// Generate bwrap options (without "bwrap" binary and without command)
fn generate_bwrap_options(policy: &SandboxPolicy, session_tmpdir: &Path) -> Vec<String> {
    let mut options = Vec::new();

    // Basic sandbox setup: --ro-bind / / first
    options.push("--ro-bind".to_string());
    options.push("/".to_string());
    options.push("/".to_string());

    // Device, proc and tmp filesystems
    options.push("--dev".to_string());
    options.push("/dev".to_string());

    options.push("--proc".to_string());
    options.push("/proc".to_string());

    options.push("--tmpfs".to_string());
    options.push("/tmp".to_string());

    // XDG_RUNTIME_DIR: mount as tmpfs (always, for isolation)
    let xdg_runtime_dir = get_xdg_runtime_dir();
    options.push("--tmpfs".to_string());
    options.push(xdg_runtime_dir.to_string_lossy().to_string());

    // Writable roots (in order)
    for path in &policy.writable_roots {
        if let Some(canonical) = canonicalize_path(path) {
            options.push("--bind".to_string());
            options.push(canonical.to_string_lossy().to_string());
            options.push(canonical.to_string_lossy().to_string());
        }
    }

    // Session temp dir
    if let Some(canonical) = canonicalize_path(session_tmpdir) {
        options.push("--bind".to_string());
        options.push(canonical.to_string_lossy().to_string());
        options.push(canonical.to_string_lossy().to_string());
    }

    // Write-restricted paths (read-only overlays - applied after writable roots)
    for path in &policy.write_restricted_paths {
        if let Some(canonical) = canonicalize_path(path) {
            options.push("--ro-bind".to_string());
            options.push(canonical.to_string_lossy().to_string());
            options.push(canonical.to_string_lossy().to_string());
        }
    }

    // Read-restricted paths (deny all access)
    for path in &policy.read_restricted_paths {
        if let Some(canonical) = canonicalize_path(path) {
            let s = canonical.to_string_lossy().to_string();
            if canonical.is_dir() {
                options.push("--perms".to_string());
                options.push("0000".to_string());
                options.push("--tmpfs".to_string());
                options.push(s.clone());
                options.push("--remount-ro".to_string());
                options.push(s);
            } else {
                options.push("--ro-bind".to_string());
                options.push("/dev/null".to_string());
                options.push(s);
            }
        }
    }

    // GUI access: DRI devices for GPU/hardware acceleration
    if policy.enable_gui() && Path::new("/dev/dri").exists() {
        options.push("--dev-bind".to_string());
        options.push("/dev/dri".to_string());
        options.push("/dev/dri".to_string());
    }

    // GUI access: Wayland sockets (probe wayland-* pattern)
    if policy.enable_gui() {
        for socket_path in probe_runtime_sockets(&xdg_runtime_dir, "wayland-") {
            options.push("--ro-bind".to_string());
            options.push(socket_path.to_string_lossy().to_string());
            options.push(socket_path.to_string_lossy().to_string());
        }

        // X11: bind /tmp/.X11-unix (sockets are writable in practice)
        if Path::new("/tmp/.X11-unix").exists() {
            options.push("--ro-bind".to_string());
            options.push("/tmp/.X11-unix".to_string());
            options.push("/tmp/.X11-unix".to_string());
        }
    }

    // Audio access: ALSA sound devices
    if policy.enable_audio() && Path::new("/dev/snd").exists() {
        options.push("--dev-bind".to_string());
        options.push("/dev/snd".to_string());
        options.push("/dev/snd".to_string());
    }

    // Audio access: PulseAudio socket
    if policy.enable_audio() {
        let pulse_socket = xdg_runtime_dir.join("pulse/native");
        if pulse_socket.exists() {
            options.push("--ro-bind".to_string());
            options.push(pulse_socket.to_string_lossy().to_string());
            options.push(pulse_socket.to_string_lossy().to_string());
        }

        // PipeWire sockets (probe pipewire-* pattern)
        for socket_path in probe_runtime_sockets(&xdg_runtime_dir, "pipewire-") {
            options.push("--ro-bind".to_string());
            options.push(socket_path.to_string_lossy().to_string());
            options.push(socket_path.to_string_lossy().to_string());
        }
    }

    // POSIX shared memory: always a private tmpfs so shm_open() works inside the
    // sandbox without sharing host memory. Isolated per-sandbox, no security impact.
    options.push("--tmpfs".to_string());
    options.push("/dev/shm".to_string());

    // Network policy
    match policy.network() {
        NetworkPolicy::None => {
            options.push("--unshare-net".to_string());
        }
        NetworkPolicy::Localhost => {
            verbose_warn!(concat!(
                "'localhost' network policy is not yet enforced; ",
                "sandboxed process has full network access (same as 'full'). ",
                "Seccomp-based filtering is planned for Phase 1b."
            ));
            options.push("--share-net".to_string());
        }
        NetworkPolicy::Full => {
            options.push("--share-net".to_string());
        }
    }

    // Unshare PID and IPC namespaces; die with parent (always)
    options.push("--unshare-pid".to_string());
    options.push("--unshare-ipc".to_string());
    options.push("--die-with-parent".to_string());

    options
}

/// Generate the bubblewrap command line for dry-run display
pub fn generate_bwrap_argv(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
    bwrap_path: &Path,
) -> Vec<String> {
    let mut argv = vec![bwrap_path.to_string_lossy().to_string()];
    argv.extend(generate_bwrap_options(policy, session_tmpdir));

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
    verbose: bool,
) -> Result<i32> {
    // Check prerequisites (bwrap availability and user namespace support)
    // Get the full path to bwrap binary from system global location
    let bwrap_path =
        check_bwrap_prerequisites().context("failed to verify bubblewrap prerequisites")?;

    // Get XDG_RUNTIME_DIR for use in env setup
    let xdg_runtime_dir = get_xdg_runtime_dir();

    // Filter environment according to policy, appending allow filters for GUI/audio vars.
    // Appended = lowest priority: explicit user filters earlier in the list still win.
    let mut ep = policy.env().clone();
    if policy.enable_gui() {
        for var in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
            "XCURSOR_THEME",
            "XCURSOR_SIZE",
        ] {
            ep.filters.push(EnvFilter {
                pattern: var.to_string(),
                action: FilterAction::Allow,
            });
        }
    }
    if policy.enable_audio() {
        for var in [
            "PULSE_SERVER",
            "PULSE_COOKIE",
            "PIPEWIRE_REMOTE",
            "XDG_RUNTIME_DIR",
        ] {
            ep.filters.push(EnvFilter {
                pattern: var.to_string(),
                action: FilterAction::Allow,
            });
        }
    }

    // Set TMPDIR to session_tmpdir if not explicitly configured in env policy
    if !ep.set.contains_key("TMPDIR") {
        if let Some(canonical) = canonicalize_path(session_tmpdir) {
            ep.set.insert(
                "TMPDIR".to_string(),
                canonical.to_string_lossy().to_string(),
            );
        }
    }

    // Set XDG_RUNTIME_DIR if not explicitly configured in env policy
    if !ep.set.contains_key("XDG_RUNTIME_DIR") {
        ep.set.insert(
            "XDG_RUNTIME_DIR".to_string(),
            xdg_runtime_dir.to_string_lossy().to_string(),
        );
    }

    let filtered_env = filter_environment(&ep);

    // Generate bwrap options (without bwrap binary and without command)
    let bwrap_options = generate_bwrap_options(policy, session_tmpdir);

    // Log full command for debugging if verbose mode
    if verbose {
        let full_argv = generate_bwrap_argv(policy, command, args, session_tmpdir, &bwrap_path);
        eprintln!("[verbose] bwrap command (what would be passed via memfd):");
        eprintln!("[verbose]   {}", full_argv.join(" "));
    }

    // Create memfd with bwrap arguments
    // The returned fd will be inherited by bwrap (not CLOEXEC)
    let args_fd = create_args_memfd(&bwrap_options)
        .with_context(|| "failed to create memfd for bwrap arguments")?;

    // Build command using full path to bwrap: <bwrap_path> --args <fd> -- <command> [args...]
    let mut cmd = Command::new(&bwrap_path);
    cmd.arg("--args").arg(args_fd.to_string()).arg("--");
    cmd.arg(command);
    cmd.args(args);

    // Clear environment and set filtered values
    cmd.env_clear();
    for (key, value) in filtered_env {
        cmd.env(key, value);
    }

    // Execute and wait for completion
    let status = cmd
        .status()
        .with_context(|| "failed to execute bwrap command with memfd arguments");

    // Close the memfd in the parent process after spawn
    let _ = nix::unistd::close(args_fd);

    // Return exit code
    Ok(status?.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

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
mode = "default_block"
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
mode = "default_allow"
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
