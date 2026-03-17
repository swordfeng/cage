use crate::policy::types::{EnvFilter, EnvPolicy, FilterAction, NetworkPolicy, SandboxPolicy};
use crate::verbose_warn;
use anyhow::{Context, Result};
use nix::unistd::{fork, ForkResult};
use std::collections::HashMap;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// System global install locations for bwrap, in order of preference
pub const BWRAP_GLOBAL_PATHS: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap", "/usr/local/bin/bwrap"];

/// Minimum kernel version required for seccomp user notification with
/// SECCOMP_USER_NOTIF_FLAG_CONTINUE (Linux 5.5)
const MIN_KERNEL_MAJOR_FOR_SECCOMP: u32 = 5;
const MIN_KERNEL_MINOR_FOR_SECCOMP: u32 = 5;

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

/// Check the Linux kernel version, returns (major, minor)
fn check_kernel_version() -> Result<(u32, u32)> {
    let content = std::fs::read_to_string("/proc/version")?;
    // Example: "Linux version 5.15.0-76-generic (buildd@lcy02-amd64-007) ..."
    let version_part = content.split_whitespace().nth(2)
        .ok_or_else(|| anyhow::anyhow!("Failed to parse kernel version from /proc/version"))?;

    let mut parts = version_part.split('.');
    let major: u32 = parts.next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse major kernel version"))?
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid major kernel version"))?;

    let minor_str = parts.next()
        .ok_or_else(|| anyhow::anyhow!("Failed to parse minor kernel version"))?;
    // Minor may contain non-numeric suffix (e.g. "15" from "5.15.0-76-generic")
    let minor: u32 = minor_str
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid minor kernel version"))?;

    Ok((major, minor))
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

/// Find xauth binary in standard system locations
fn find_xauth_binary() -> Option<PathBuf> {
    for path in &[
        "/usr/bin/xauth",
        "/bin/xauth",
        "/usr/X11R6/bin/xauth",
        "/usr/local/bin/xauth",
    ] {
        let p = Path::new(path);
        if p.exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

/// Try to generate a restricted (untrusted) X11 auth token using the X11 Security extension.
///
/// Uses `xauth generate <display> . untrusted timeout 3600` to create a token that
/// restricts key grabs, input sniffing, and other sensitive operations inside the sandbox.
/// Returns the path to the generated xauth file, or None if xauth is unavailable or the
/// X11 Security extension is not supported by the running X server.
fn try_generate_restricted_xauth(display: &str, session_tmpdir: &Path) -> Option<PathBuf> {
    let xauth_bin = find_xauth_binary()?;
    let xauth_file = session_tmpdir.join(".xauth");

    let output = Command::new(&xauth_bin)
        .arg("-f")
        .arg(&xauth_file)
        .arg("generate")
        .arg(display)
        .arg(".")
        .arg("untrusted")
        .arg("timeout")
        .arg("3600")
        .output()
        .ok()?;

    if output.status.success() && xauth_file.exists() {
        Some(xauth_file)
    } else {
        None
    }
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
///
/// `block_xauth` is the canonical path of the original XAUTHORITY file to mask
/// with /dev/null inside the sandbox (used when a restricted token was generated).
fn generate_bwrap_options(
    policy: &SandboxPolicy,
    session_tmpdir: &Path,
    block_xauth: Option<&Path>,
) -> Vec<String> {
    let mut options = Vec::new();
    
    // Unshare PID and IPC namespaces; die with parent (always)
    options.push("--unshare-pid".to_string());
    options.push("--unshare-ipc".to_string());
    options.push("--die-with-parent".to_string());

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

    options.push("--tmpfs".to_string());
    options.push("/run".to_string());

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

    // Block original XAUTHORITY file when a restricted token was generated,
    // preventing the sandboxed process from bypassing the restriction.
    if let Some(xauth_path) = block_xauth {
        if let Some(canonical) = canonicalize_path(xauth_path) {
            options.push("--ro-bind".to_string());
            options.push("/dev/null".to_string());
            options.push(canonical.to_string_lossy().to_string());
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
            // Host network shared; seccomp supervisor filters connect() to localhost only
            options.push("--share-net".to_string());
        }
        NetworkPolicy::Full => {
            options.push("--share-net".to_string());
        }
    }

    options
}

/// Generate the bubblewrap command line for dry-run display
pub fn generate_bwrap_argv(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
    bwrap_path: &Path,
    block_xauth: Option<&Path>,
) -> Vec<String> {
    let mut argv = vec![bwrap_path.to_string_lossy().to_string()];
    argv.extend(generate_bwrap_options(policy, session_tmpdir, block_xauth));

    // Command separator and the actual command
    argv.push("--".to_string());
    argv.push(command.to_string());
    argv.extend(args.iter().cloned());

    argv
}

fn prepare_sandbox(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
    bwrap_path: &Path,
) -> Result<(std::process::Command, RawFd)> {
    // Get XDG_RUNTIME_DIR for use in env setup
    let xdg_runtime_dir = get_xdg_runtime_dir();

    // Filter environment according to policy, appending allow filters for GUI/audio vars.
    let mut ep = policy.env().clone();
    let mut block_xauth: Option<PathBuf> = None;
    
    if policy.enable_gui() {
        for var in [
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XDG_RUNTIME_DIR",
            "XCURSOR_THEME",
            "XCURSOR_SIZE",
        ] {
            ep.filters.push(EnvFilter {
                pattern: var.to_string(),
                action: FilterAction::Allow,
            });
        }

        if !ep.set.contains_key("XAUTHORITY") {
            let display = std::env::var("DISPLAY").unwrap_or_default();
            if !display.is_empty() {
                match try_generate_restricted_xauth(&display, session_tmpdir) {
                    Some(xauth_path) => {
                        block_xauth = std::env::var("XAUTHORITY")
                            .ok()
                            .filter(|v| !v.is_empty())
                            .map(PathBuf::from)
                            .or_else(|| dirs::home_dir().map(|h| h.join(".Xauthority")));
                        ep.set.insert(
                            "XAUTHORITY".to_string(),
                            xauth_path.to_string_lossy().to_string(),
                        );
                    }
                    None => {
                        verbose_warn!(
                            "could not generate restricted X11 auth token \
                             (xauth unavailable or X11 Security extension not supported); \
                             falling back to original XAUTHORITY"
                        );
                        ep.filters.push(EnvFilter {
                            pattern: "XAUTHORITY".to_string(),
                            action: FilterAction::Allow,
                        });
                    }
                }
            } else {
                ep.filters.push(EnvFilter {
                    pattern: "XAUTHORITY".to_string(),
                    action: FilterAction::Allow,
                });
            }
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

    // Set TMPDIR to session_tmpdir if not explicitly configured
    if !ep.set.contains_key("TMPDIR") {
        if let Some(canonical) = canonicalize_path(session_tmpdir) {
            ep.set.insert(
                "TMPDIR".to_string(),
                canonical.to_string_lossy().to_string(),
            );
        }
    }

    // Set XDG_RUNTIME_DIR if not explicitly configured
    if !ep.set.contains_key("XDG_RUNTIME_DIR") {
        ep.set.insert(
            "XDG_RUNTIME_DIR".to_string(),
            xdg_runtime_dir.to_string_lossy().to_string(),
        );
    }

    let filtered_env = filter_environment(&ep);

    // Generate bwrap options
    let bwrap_options = generate_bwrap_options(policy, session_tmpdir, block_xauth.as_deref());

    // Create memfd with bwrap arguments
    let args_fd = create_args_memfd(&bwrap_options)
        .with_context(|| "failed to create memfd for bwrap arguments")?;

    // Build command
    let mut cmd = Command::new(bwrap_path);
    cmd.arg("--args").arg(args_fd.to_string()).arg("--");
    cmd.arg(command);
    cmd.args(args);

    // Clear environment and set filtered values
    cmd.env_clear();
    for (key, value) in filtered_env {
        cmd.env(key, value);
    }

    Ok((cmd, args_fd))
}

pub fn run_sandboxed(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
    verbose: bool,
) -> Result<i32> {
    // Check prerequisites
    let bwrap_path =
        check_bwrap_prerequisites().context("failed to verify bubblewrap prerequisites")?;

    // For localhost network policy, we need a different approach with seccomp
    if matches!(policy.network(), NetworkPolicy::Localhost) {
        // Check kernel version (need >= 5.5 for SECCOMP_USER_NOTIF_FLAG_CONTINUE)
        let (kmajor, kminor) = check_kernel_version()?;
        if kmajor < MIN_KERNEL_MAJOR_FOR_SECCOMP
            || (kmajor == MIN_KERNEL_MAJOR_FOR_SECCOMP && kminor < MIN_KERNEL_MINOR_FOR_SECCOMP)
        {
            return Err(anyhow::anyhow!(
                "Seccomp-based localhost networking requires Linux kernel {}.{} or later, \
                but running on kernel {}.{}",
                MIN_KERNEL_MAJOR_FOR_SECCOMP, MIN_KERNEL_MINOR_FOR_SECCOMP,
                kmajor, kminor
            ));
        }

        if verbose {
            eprintln!("[verbose] Using seccomp supervisor for localhost network policy");
        }

        // Create socketpair for parent-child communication
        let (parent_sock, child_sock) = crate::platform::seccomp::create_socketpair()
            .context("Failed to create socketpair for seccomp supervision")?;

        // Fork for seccomp supervision
        match unsafe { fork() } {
            Ok(ForkResult::Parent { child }) => {
                // Parent: close child socket, receive notify_fd, run supervisor
                drop(child_sock);
                
                let parent_fd = parent_sock.as_raw_fd();
                let notify_fd = crate::platform::seccomp::recv_fd(parent_fd)
                    .context("Failed to receive notification FD from child")?;
                drop(parent_sock);

                // Spawn supervisor thread
                let supervisor_handle = std::thread::spawn(move || {
                    if let Err(e) = crate::platform::seccomp::run_supervisor(notify_fd, child) {
                        eprintln!("[cage] Seccomp supervisor error: {}", e);
                    }
                });

                // Wait for child to complete
                let wait_result = nix::sys::wait::waitpid(child, None)?;
                
                // Wait for supervisor to finish
                supervisor_handle.join().ok();

                // Extract exit code
                let exit_code = match wait_result {
                    nix::sys::wait::WaitStatus::Exited(_, code) => code,
                    nix::sys::wait::WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
                    _ => 1,
                };

                return Ok(exit_code);
            }
            Ok(ForkResult::Child) => {
                // Child: close parent socket, install seccomp, send notify_fd, exec bwrap
                drop(parent_sock);
                
                let child_fd = child_sock.as_raw_fd();
                if let Err(e) = run_seccomp_child(policy, command, args, session_tmpdir, &bwrap_path, child_fd, verbose) {
                    eprintln!("[cage] Child process error: {}", e);
                    std::process::exit(1);
                }
                // run_seccomp_child calls exec(), which replaces the process
                // So if we get here, exec failed and we already returned Err
                std::process::exit(1);
            }
            Err(e) => {
                return Err(anyhow::anyhow!("Fork failed for seccomp supervision: {}", e));
            }
        }
    }

    // Standard execution without seccomp
    let (mut cmd, args_fd) = prepare_sandbox(policy, command, args, session_tmpdir, &bwrap_path)?;

    // Log full command for debugging if verbose mode
    if verbose {
        let full_argv =
            generate_bwrap_argv(policy, command, args, session_tmpdir, &bwrap_path, None);
        eprintln!("[verbose] bwrap command:");
        eprintln!("[verbose]   {}", full_argv.join(" "));
    }

    // Execute and wait for completion
    let status = cmd
        .status()
        .with_context(|| "failed to execute bwrap command with memfd arguments")?;

    // Close the memfd
    let _ = nix::unistd::close(args_fd);

    Ok(status.code().unwrap_or(1))
}

/// Run in child process with seccomp filter installed
fn run_seccomp_child(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
    bwrap_path: &Path,
    parent_sock_fd: RawFd,
    verbose: bool,
) -> Result<()> {
    use crate::platform::seccomp::{install_seccomp_filter, send_fd};

    // Install seccomp filter and get notification FD
    let notify_fd = install_seccomp_filter()
        .context("Failed to install seccomp filter")?;

    // Send notification FD to parent
    send_fd(parent_sock_fd, notify_fd)
        .context("Failed to send notification FD to parent")?;

    // Close the socket
    let _ = nix::unistd::close(parent_sock_fd);

    // Prepare and exec bwrap
    let (mut cmd, args_fd) = prepare_sandbox(policy, command, args, session_tmpdir, bwrap_path)?;

    if verbose {
        eprintln!("[verbose] Child: execing bwrap with seccomp filter");
    }

    // Exec bwrap - this replaces the current process
    let err = cmd.exec();
    
    // If we get here, exec failed
    let _ = nix::unistd::close(args_fd);
    Err(anyhow::anyhow!("Failed to exec bwrap: {}", err))
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
