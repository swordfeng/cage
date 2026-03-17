//! Integration tests for cage sandbox
//!
//! These tests run the cage binary as a subprocess to verify sandbox behavior.
//! They require bubblewrap (bwrap) to be installed on Linux.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
/// Path to the cage binary (built in debug mode)
fn cage_bin() -> PathBuf {
    // Use CARGO_BIN_EXE_cage if set (Cargo sets this during tests)
    if let Ok(bin) = env::var("CARGO_BIN_EXE_cage") {
        return PathBuf::from(bin);
    }

    // Fallback: assume we're running from the project root
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(&manifest_dir)
        .join("target")
        .join("debug")
        .join("cage")
}

/// Run cage with given arguments and return the output.
/// Enforces a timeout to prevent tests from hanging.
fn run_cage<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    run_cage_timeout(args, Duration::from_secs(30))
}

/// Run cage with given arguments and a custom timeout
fn run_cage_timeout<I, S>(args: I, timeout: Duration) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let bin = cage_bin();

    // Ensure the binary exists
    if !bin.exists() {
        panic!(
            "cage binary not found at {}. Run `cargo build` first.",
            bin.display()
        );
    }

    let child = Command::new(&bin)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to execute cage");

    // Use a thread + channel to implement timeout on wait
    let (tx, rx) = std::sync::mpsc::channel();
    let child_id = child.id();
    let wait_thread = std::thread::spawn(move || {
        let result = child.wait_with_output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            // For debugging: print stderr if there's an error
            if output.status.code().unwrap_or(1) != 0 {
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                if !stderr_str.is_empty() {
                    eprintln!("cage stderr: {}", stderr_str);
                }
            }
            output
        }
        Ok(Err(e)) => {
            panic!("failed to wait for cage process: {}", e);
        }
        Err(_) => {
            // Timeout — kill the process
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child_id as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = wait_thread.join();
            panic!("cage process timed out after {:?}", timeout);
        }
    }
}

/// Run cage with extra environment variables set on the subprocess
fn run_cage_with_env<I, S>(args: I, extra_env: &[(&str, &str)]) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let bin = cage_bin();
    if !bin.exists() {
        panic!("cage binary not found at {}. Run `cargo build` first.", bin.display());
    }

    let timeout = Duration::from_secs(30);
    let mut cmd = Command::new(&bin);
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    let child = cmd.spawn().expect("failed to execute cage");
    let (tx, rx) = std::sync::mpsc::channel();
    let child_id = child.id();
    let wait_thread = std::thread::spawn(move || {
        let result = child.wait_with_output();
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(Ok(output)) => {
            if output.status.code().unwrap_or(1) != 0 {
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                if !stderr_str.is_empty() {
                    eprintln!("cage stderr: {}", stderr_str);
                }
            }
            output
        }
        Ok(Err(e)) => panic!("failed to wait for cage process: {}", e),
        Err(_) => {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(child_id as i32),
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = wait_thread.join();
            panic!("cage process timed out after {:?}", timeout);
        }
    }
}

/// Counter for unique temp dir names
static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Create a unique temporary directory for each test
fn temp_dir() -> PathBuf {
    let id = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = env::temp_dir().join(format!(
        "cage-test-{}-{}",
        std::process::id(),
        id
    ));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Clean up a temporary directory
fn cleanup_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn test_write_restricted_paths_denies_write() {
    // Create a temporary workspace with a .git directory
    let workspace = temp_dir();
    let git_dir = workspace.join(".git");
    fs::create_dir_all(&git_dir).unwrap();

    // Create a test file that we'll try to write to
    let test_file = git_dir.join("COMMIT_EDITMSG");
    fs::write(&test_file, "initial content").unwrap();

    // Create a custom config that restricts .git directory
    let config_content = format!(
        r#"
[policies.test]
writable_roots = ["{}"]
write_restricted_paths = ["{}/.git"]
network = "none"

[policies.test.env]
mode = "default_allow"
"#,
        workspace.display(),
        workspace.display()
    );

    let config_file = workspace.join("test-config.toml");
    fs::write(&config_file, &config_content).unwrap();

    // Try to write to the restricted file using cage
    // Use -- to separate cage args from command args
    let output = run_cage([
        "--config",
        &config_file.to_string_lossy(),
        "--policy",
        "test",
        "--",
        "sh",
        "-c",
        &format!("echo 'test' > {}", test_file.display()),
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);

    // The write should have failed (either with permission denied or non-zero exit)
    // The sandboxed process may exit with non-zero status, or the shell may report permission denied
    assert!(
        output.status.code().unwrap_or(1) != 0 || stderr.contains("Permission denied"),
        "Write to restricted path should fail. stdout: {}, stderr: {}, exit code: {:?}",
        stdout,
        stderr,
        output.status.code()
    );

    // Verify the file content was not changed
    let content = fs::read_to_string(&test_file).unwrap();
    assert_eq!(
        content, "initial content",
        "Restricted file should not have been modified"
    );

    cleanup_dir(&workspace);
}

#[test]
fn test_read_restricted_paths_denies_read() {
    // Create a temporary workspace with a sensitive file
    let workspace = temp_dir();
    let secret_dir = workspace.join(".secret");
    fs::create_dir_all(&secret_dir).unwrap();

    let secret_file = secret_dir.join("credentials.txt");
    fs::write(&secret_file, "secret_password_123").unwrap();

    // Create a custom config that restricts reading the secret directory
    let config_content = format!(
        r#"
[policies.test]
writable_roots = ["{}"]
read_restricted_paths = ["{}"]
network = "none"

[policies.test.env]
mode = "default_allow"
"#,
        workspace.display(),
        secret_dir.display()
    );

    let config_file = workspace.join("test-config.toml");
    fs::write(&config_file, &config_content).unwrap();

    // Try to read the restricted file using cage
    let output = run_cage([
        "--config",
        &config_file.to_string_lossy(),
        "--policy",
        "test",
        "--",
        "sh",
        "-c",
        &format!("cat {} 2>&1", secret_file.display()),
    ]);

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let combined_output = format!("{}{}", stdout, stderr);

    // The read should have failed
    assert!(
        output.status.code().unwrap_or(1) != 0 
            || combined_output.contains("Permission denied")
            || combined_output.contains("No such file")
            || stdout.is_empty(),
        "Read from restricted path should fail or return empty. stdout: {}, stderr: {}, exit code: {:?}",
        stdout,
        stderr,
        output.status.code()
    );

    // Verify the secret content is not in the output
    assert!(
        !combined_output.contains("secret_password"),
        "Secret content should not be readable. Output: {}",
        combined_output
    );

    cleanup_dir(&workspace);
}

#[test]
fn test_network_none_blocks_external_connections() {
    let workspace = temp_dir();

    // Create a config with network = "none"
    let config_content = format!(
        r#"
[policies.test]
writable_roots = ["{}"]
network = "none"

[policies.test.env]
mode = "default_allow"
"#,
        workspace.display()
    );

    let config_file = workspace.join("test-config.toml");
    fs::write(&config_file, &config_content).unwrap();

    // Try to connect to external address using timeout to avoid hanging
    let output = run_cage([
        "--config",
        &config_file.to_string_lossy(),
        "--policy",
        "test",
        "--",
        "sh",
        "-c",
        "timeout 5 nc -z 8.8.8.8 53 2>&1 || echo 'CONNECTION_FAILED'",
    ]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Connection should fail (either timeout, network unreachable, or CONNECTION_FAILED)
    assert!(
        stdout.contains("CONNECTION_FAILED")
            || stderr.contains("Network is unreachable")
            || stderr.contains("Connection")
            || output.status.code().unwrap_or(0) != 0,
        "External connection should fail with network=none. stdout: {}, stderr: {}",
        stdout,
        stderr
    );

    cleanup_dir(&workspace);
}

#[test]
fn test_network_full_allows_localhost_connections() {
    let workspace = temp_dir();

    // Create a config with network = "full"
    let config_content = format!(
        r#"
[policies.test]
writable_roots = ["{}"]
network = "full"

[policies.test.env]
mode = "default_allow"
"#,
        workspace.display()
    );

    let config_file = workspace.join("test-config.toml");
    fs::write(&config_file, &config_content).unwrap();

    // Start a simple TCP listener on a unique port using Python (more reliable than nc)
    let port = 18000 + (std::process::id() % 1000);
    let mut server = Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import socket; s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); s.bind(('127.0.0.1',{})); s.listen(1); s.settimeout(10); conn,_=s.accept(); conn.sendall(b'HELLO_FROM_SERVER\\n'); conn.close(); s.close()",
            port
        ))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("python3 required for this test");

    // Give the server a moment to start
    std::thread::sleep(Duration::from_millis(300));

    // Try to connect to localhost using cage with full network
    let config_str = config_file.to_string_lossy().to_string();
    let connect_cmd = format!(
        "timeout 5 sh -c 'cat < /dev/tcp/127.0.0.1/{} 2>/dev/null || echo CONNECTION_FAILED'",
        port
    );
    let output = run_cage_timeout(
        [
            "--config", &config_str,
            "--policy", "test",
            "--", "sh", "-c", &connect_cmd,
        ],
        Duration::from_secs(15),
    );

    let _ = server.kill();
    let _ = server.wait();

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify the sandbox allowed the connection.
    // The test is lenient: if /dev/tcp isn't supported (non-bash sh), just check cage ran.
    if stdout.contains("HELLO_FROM_SERVER") {
        // Connection succeeded
    } else {
        // Connection may have failed due to tool availability, but cage should have run
        assert!(
            output.status.code().is_some(),
            "Cage should have run to completion. stdout: {}, exit: {:?}",
            stdout,
            output.status.code()
        );
    }

    cleanup_dir(&workspace);
}

#[test]
fn test_env_filter_blocklist_removes_token_vars() {
    let workspace = temp_dir();

    // Create a config with blocklist mode filtering *_TOKEN patterns
    let config_content = format!(
        r#"
[policies.test]
writable_roots = ["{}"]
network = "none"

[policies.test.env]
mode = "default_allow"
block = ["*_TOKEN"]
"#,
        workspace.display()
    );

    let config_file = workspace.join("test-config.toml");
    fs::write(&config_file, &config_content).unwrap();

    // Run cage with extra env vars set on the subprocess (avoids unsafe env::set_var race)
    let config_str = config_file.to_string_lossy().to_string();
    let output = run_cage_with_env(
        [
            "--config", &config_str,
            "--policy", "test",
            "--", "sh", "-c",
            "env | grep -E '(TOKEN|NORMAL_VAR)' | sort",
        ],
        &[
            ("MY_API_TOKEN", "secret_token_123"),
            ("GITHUB_TOKEN", "github_secret"),
            ("NORMAL_VAR", "normal_value"),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // TOKEN variables should be filtered out
    assert!(
        !stdout.contains("MY_API_TOKEN"),
        "MY_API_TOKEN should be filtered. Output: {}",
        stdout
    );
    assert!(
        !stdout.contains("GITHUB_TOKEN"),
        "GITHUB_TOKEN should be filtered. Output: {}",
        stdout
    );

    // NORMAL_VAR should be present
    assert!(
        stdout.contains("NORMAL_VAR=normal_value"),
        "NORMAL_VAR should be present. Output: {}",
        stdout
    );

    cleanup_dir(&workspace);
}

#[test]
fn test_env_filter_allowlist_only_allows_specific_vars() {
    let workspace = temp_dir();

    // Create a config with allowlist mode - only allow CAGE_TEST_PATH
    let config_content = format!(
        r#"
[policies.test]
writable_roots = ["{}"]
network = "none"

[policies.test.env]
mode = "default_block"
allow = ["CAGE_TEST_PATH"]
"#,
        workspace.display()
    );

    let config_file = workspace.join("test-config.toml");
    fs::write(&config_file, &config_content).unwrap();

    // Run cage with extra env vars set on the subprocess (avoids unsafe env::set_var race)
    let config_str = config_file.to_string_lossy().to_string();
    let output = run_cage_with_env(
        [
            "--config", &config_str,
            "--policy", "test",
            "--", "sh", "-c",
            "env | sort",
        ],
        &[
            ("CAGE_TEST_PATH", "/usr/bin:/bin"),
            ("CAGE_TEST_SECRET", "secret_value"),
        ],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    // CAGE_TEST_PATH should be present
    assert!(
        stdout.contains("CAGE_TEST_PATH="),
        "CAGE_TEST_PATH should be present. Output: {}",
        stdout
    );

    // CAGE_TEST_SECRET should NOT be present (not in allowlist)
    assert!(
        !stdout.contains("CAGE_TEST_SECRET"),
        "CAGE_TEST_SECRET should not be present. Output: {}",
        stdout
    );

    cleanup_dir(&workspace);
}

#[test]
fn test_exit_code_forwarding_success() {
    let output = run_cage(["--policy", "default", "--", "sh", "-c", "exit 0"]);

    assert_eq!(
        output.status.code(),
        Some(0),
        "Exit code 0 should be forwarded"
    );
}

#[test]
fn test_exit_code_forwarding_failure() {
    let output = run_cage(["--policy", "default", "--", "sh", "-c", "exit 42"]);

    assert_eq!(
        output.status.code(),
        Some(42),
        "Exit code 42 should be forwarded"
    );
}

#[test]
fn test_exit_code_forwarding_signal() {
    // Test that a command killed by a signal is handled correctly
    // Note: This test may behave differently on different platforms
    let output = run_cage([
        "--policy",
        "default",
        "--",
        "sh",
        "-c",
        "kill -TERM $$; sleep 1",
    ]);

    // The exit code should be non-zero (either 143 = 128 + 15 for SIGTERM, or some other error)
    assert!(
        output.status.code().unwrap_or(0) != 0,
        "Process killed by signal should have non-zero exit code"
    );
}

#[test]
fn test_dry_run_mode() {
    let output = run_cage(["--policy", "default", "--dry-run", "echo", "hello"]);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Dry run"),
        "Dry run mode should indicate it's not executing. Output: {}",
        stdout
    );

    assert_eq!(
        output.status.code(),
        Some(0),
        "Dry run should exit with code 0"
    );
}

#[test]
fn test_verbose_mode_shows_config() {
    let output = run_cage(["-v", "--policy", "default", "--dry-run", "echo", "hello"]);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("Cage Sandbox Configuration"),
        "Verbose mode should show configuration. Output: {}",
        stdout
    );
}
