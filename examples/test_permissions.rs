use std::fs;
use std::path::{Path, PathBuf};

/// Test result for a single path check
#[derive(Debug)]
struct TestResult {
    description: String,
    path: String,
    tests: Vec<(String, bool, bool, bool, String)>, // (test_name, actual, expected, passed, error)
    passed: bool,
}

/// Test if directory listing is allowed
fn test_dir_listing(path: &Path) -> (bool, String) {
    if !path.exists() {
        return (false, "Path does not exist".to_string());
    }
    if !path.is_dir() {
        return (false, "Not a directory".to_string());
    }
    match fs::read_dir(path) {
        Ok(_) => (true, "".to_string()),
        Err(e) => (false, e.to_string()),
    }
}

/// Test if file content reading is allowed
/// For directories, reads the provided test_file if available, otherwise tries to find an existing file
fn test_file_read(path: &Path, test_file: Option<&Path>) -> (bool, String) {
    if !path.exists() {
        return (false, "Path does not exist".to_string());
    }

    if path.is_dir() {
        // For directories, first try to read the provided test file (if write succeeded)
        if let Some(test) = test_file {
            match fs::read(test) {
                Ok(_) => return (true, "".to_string()),
                Err(e) => return (false, e.to_string()),
            }
        }

        // Otherwise, try to read a file inside it
        match fs::read_dir(path) {
            Ok(entries) => {
                for entry in entries.flatten() {
                    if entry.path().is_file() {
                        match fs::read(&entry.path()) {
                            Ok(_) => return (true, "".to_string()),
                            Err(e) => return (false, e.to_string()),
                        }
                    }
                }
                (false, "No files found in directory to test".to_string())
            }
            Err(e) => (false, e.to_string()),
        }
    } else {
        // For files, try to read directly (into buffer, not assuming text)
        match fs::read(path) {
            Ok(_) => (true, "".to_string()),
            Err(e) => (false, e.to_string()),
        }
    }
}

/// Non-destructive test of write permission (creates temp file)
/// Returns (success, error_message, test_file_path) where test_file_path is Some if a file was created
fn test_write_permission(path: &Path) -> (bool, String, Option<PathBuf>) {
    if path.is_dir() {
        let test_file = path.join(format!(".cage_test_{}", std::process::id()));
        match fs::write(&test_file, b"test") {
            Ok(_) => (true, "".to_string(), Some(test_file)),
            Err(e) => (false, e.to_string(), None),
        }
    } else if path.is_file() {
        match fs::OpenOptions::new().write(true).append(true).open(path) {
            Ok(_) => (true, "".to_string(), None),
            Err(e) => (false, e.to_string(), None),
        }
    } else if let Some(parent) = path.parent() {
        if parent.exists() {
            match fs::write(path, b"test") {
                Ok(_) => (true, "".to_string(), Some(path.to_path_buf())),
                Err(e) => (false, e.to_string(), None),
            }
        } else {
            (false, "Parent directory does not exist".to_string(), None)
        }
    } else {
        (false, "Path does not exist".to_string(), None)
    }
}

fn run_test(
    description: &str,
    path: &Path,
    expect_list: Option<bool>,
    expect_read_content: Option<bool>,
    expect_write: Option<bool>,
) -> TestResult {
    println!("\n{}", "=".repeat(60));
    println!("Test: {}", description);
    println!("Path: {}", path.display());

    let exists = path.exists();
    let is_dir = exists && path.is_dir();
    println!("Exists: {}, Is directory: {}", exists, is_dir);

    let mut tests = Vec::new();
    let mut all_passed = true;
    let mut created_test_file: Option<PathBuf> = None;

    // Test write permission FIRST
    // This creates a test file we can use for read testing
    if let Some(expected) = expect_write {
        let (can_write, error, test_file) = test_write_permission(path);
        created_test_file = test_file;
        let passed = can_write == expected;
        tests.push((
            "write".to_string(),
            can_write,
            expected,
            passed,
            error.clone(),
        ));
        println!(
            "Write: {} {}",
            if can_write { "ALLOWED" } else { "DENIED" },
            if passed { "✓ PASS" } else { "✗ FAIL" }
        );
        if !passed && !error.is_empty() {
            println!("  Error: {}", error);
        }
        all_passed = all_passed && passed;
    }

    // Test file content reading
    // If write succeeded and created a test file, use it for reading
    if let Some(expected) = expect_read_content {
        let (can_read, error) = test_file_read(path, created_test_file.as_deref());
        let passed = can_read == expected;
        tests.push((
            "read_content".to_string(),
            can_read,
            expected,
            passed,
            error.clone(),
        ));
        println!(
            "File content read: {} {}",
            if can_read { "ALLOWED" } else { "DENIED" },
            if passed { "✓ PASS" } else { "✗ FAIL" }
        );
        if !passed && !error.is_empty() {
            println!("  Error: {}", error);
        }
        all_passed = all_passed && passed;
    }

    // Clean up test file after read test is done
    if let Some(test_file) = created_test_file {
        let _ = fs::remove_file(&test_file);
    }

    // Test directory listing (for directories)
    if is_dir {
        let (can_list, error) = test_dir_listing(path);
        if let Some(expected) = expect_list {
            // We have an expectation - check it
            let passed = can_list == expected;
            tests.push((
                "list".to_string(),
                can_list,
                expected,
                passed,
                error.clone(),
            ));
            println!(
                "Directory listing: {} {}",
                if can_list { "ALLOWED" } else { "DENIED" },
                if passed { "✓ PASS" } else { "✗ FAIL" }
            );
            if !passed && !error.is_empty() {
                println!("  Error: {}", error);
            }
            all_passed = all_passed && passed;
        } else {
            // No expectation - just report the result
            tests.push((
                "list".to_string(),
                can_list,
                false, // dummy expected value
                true,  // always passed when no expectation
                error.clone(),
            ));
            println!(
                "Directory listing: {} (no expectation)",
                if can_list { "ALLOWED" } else { "DENIED" }
            );
            if !error.is_empty() {
                println!("  Note: {}", error);
            }
        }
    }

    TestResult {
        description: description.to_string(),
        path: path.display().to_string(),
        tests,
        passed: all_passed,
    }
}

#[cfg(windows)]
fn get_system_hosts_file() -> &'static Path {
    Path::new(r"C:\Windows\System32\drivers\etc\hosts")
}

#[cfg(not(windows))]
fn get_system_hosts_file() -> &'static Path {
    Path::new("/etc/hosts")
}

#[cfg(windows)]
fn get_temp_dir() -> PathBuf {
    std::env::var("TEMP")
        .or_else(|_| std::env::var("TMP"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Windows\Temp"))
}

#[cfg(not(windows))]
fn get_temp_dir() -> PathBuf {
    std::env::var("TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

#[cfg(windows)]
fn get_home_dir() -> Option<PathBuf> {
    std::env::var("USERPROFILE").ok().map(PathBuf::from)
}

#[cfg(not(windows))]
fn get_home_dir() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(windows)]
fn get_system_path() -> PathBuf {
    PathBuf::from(r"C:\Windows")
}

#[cfg(not(windows))]
fn get_system_path() -> PathBuf {
    PathBuf::from("/bin")
}

#[cfg(windows)]
fn get_platform_name() -> &'static str {
    "Windows"
}

#[cfg(target_os = "macos")]
fn get_platform_name() -> &'static str {
    "macOS"
}

#[cfg(target_os = "linux")]
fn get_platform_name() -> &'static str {
    "Linux"
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn get_platform_name() -> &'static str {
    "Unknown"
}

fn main() {
    println!("{}", "=".repeat(60));
    println!("CAGE SANDBOX PERMISSION TEST (Rust)");
    println!("Platform: {}", get_platform_name());
    println!("{}", "=".repeat(60));
    println!("Running as PID {}", std::process::id());

    let cwd = std::env::current_dir().expect("Failed to get current directory");
    let home = get_home_dir().expect("Failed to get home directory");

    println!("Current directory: {}", cwd.display());
    println!("Home directory: {}", home.display());

    let mut results = Vec::new();

    // Test 1: CWD root - fully writable
    results.push(run_test(
        "CWD root (fully writable)",
        &cwd,
        Some(true), // expect list
        Some(true), // expect read content
        Some(true), // expect write
    ));

    // Test 2: CWD/.git - write blocked, read allowed
    results.push(run_test(
        "CWD/.git directory (write blocked)",
        &cwd.join(".git"),
        Some(true),  // expect list
        Some(true),  // expect read content
        Some(false), // expect write blocked
    ));

    // Test 3: CWD/.env - write blocked
    results.push(run_test(
        "CWD/.env file (write blocked)",
        &cwd.join(".env"),
        None,        // not a directory
        Some(true),  // expect read if exists
        Some(false), // expect write blocked
    ));

    // Test 4: ~/.ssh - read blocked (content), write blocked
    // Note: Directory listing may be allowed or disallowed - we accept either
    results.push(run_test(
        "~/.ssh directory (read blocked, list: any)",
        &home.join(".ssh"),
        None,        // expect list: any (either allowed or denied is acceptable)
        Some(false), // expect read content blocked
        Some(false), // expect write blocked
    ));

    // Test 5: ~/.aws - read blocked (content), write blocked
    results.push(run_test(
        "~/.aws directory (read blocked, list: any)",
        &home.join(".aws"),
        None,        // expect list: any (either allowed or denied is acceptable)
        Some(false), // expect read content blocked
        Some(false), // expect write blocked
    ));

    // Test 6: ~/.gnupg - read blocked (content), write blocked
    results.push(run_test(
        "~/.gnupg directory (read blocked, list: any)",
        &home.join(".gnupg"),
        None,        // expect list: any (either allowed or denied is acceptable)
        Some(false), // expect read content blocked
        Some(false), // expect write blocked
    ));

    // Test 7: System hosts file - read-only
    results.push(run_test(
        "System hosts file (read-only)",
        get_system_hosts_file(),
        None,        // not a directory
        Some(true),  // expect read
        Some(false), // expect write blocked
    ));

    // Test 8: Temp directory - writable
    results.push(run_test(
        "Temp directory (should be writable)",
        &get_temp_dir(),
        Some(true), // expect list
        Some(true), // expect read
        Some(true), // expect write
    ));

    // Test 9: User home - readable, not writable
    results.push(run_test(
        "Home directory (readable, not writable)",
        &home,
        Some(true),  // expect list
        Some(true),  // expect read
        Some(false), // expect write blocked
    ));

    // Test 10: System root directory
    #[cfg(windows)]
    let system_desc = "C:\\Windows directory (system, read-only)";
    #[cfg(not(windows))]
    let system_desc = "/bin directory (system, read-only)";

    results.push(run_test(
        system_desc,
        &get_system_path(),
        Some(true),  // expect list
        Some(true),  // expect read
        Some(false), // expect write blocked
    ));

    // Summary
    println!("\n{}", "=".repeat(60));
    println!("SUMMARY");
    println!("{}", "=".repeat(60));

    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();

    println!("Tests passed: {}/{}", passed, total);

    // Print failed tests
    let failed: Vec<_> = results.iter().filter(|r| !r.passed).collect();
    if !failed.is_empty() {
        println!("\nFailed tests:");
        for result in &failed {
            println!("\n✗ {}", result.description);
            println!("  Path: {}", result.path);
            for (test_name, actual, expected, _, error) in &result.tests {
                if actual != expected {
                    println!(
                        "  {}: expected {}, got {}",
                        test_name,
                        if *expected { "ALLOWED" } else { "DENIED" },
                        if *actual { "ALLOWED" } else { "DENIED" }
                    );
                    if !error.is_empty() {
                        println!("    Error: {}", error);
                    }
                }
            }
        }
    }

    if passed == total {
        println!("\n✓ All tests passed!");
        std::process::exit(0);
    } else {
        println!("\n✗ {} test(s) failed", failed.len());
        std::process::exit(1);
    }
}
