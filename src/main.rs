use anyhow::Context;
use clap::Parser;
use scopeguard::defer;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

mod cli;
mod config;
mod platform;
mod policy;

fn main() {
    let args = cli::Args::parse();

    if let Err(e) = run(args) {
        eprintln!("cage error: {}", e);
        process::exit(1);
    }
}

fn run(args: cli::Args) -> anyhow::Result<()> {
    // Load and merge configuration
    let cfg = config::load_config(&args)?;

    // Resolve the policy name first (for verbose output)
    let policy_name = config::resolve_policy_name(&cfg, &args)?;

    // Resolve the policy (applies CLI overrides and variable expansion)
    let policy = config::resolve_policy(&cfg, &args, args.verbose)?;

    // Create session temp directory early for verbose/dry-run display
    let session_tmpdir = create_session_tmpdir()?;

    // Register cleanup for temp directory
    let tmpdir_path = session_tmpdir.clone();
    defer! {
        let _ = fs::remove_dir_all(&tmpdir_path);
    }

    // Determine platform backend
    let platform_backend = if cfg!(target_os = "linux") {
        "bubblewrap (Linux)"
    } else if cfg!(target_os = "macos") {
        "Seatbelt (macOS)"
    } else if cfg!(target_os = "windows") {
        "Restricted Token (Windows)"
    } else {
        "unknown"
    };

    // Print debug info if verbose or dry-run
    let is_dry_run = args.dry_run;
    if args.verbose || is_dry_run {
        print_debug_info(
            &policy,
            &policy_name,
            &session_tmpdir,
            platform_backend,
            &args.command,
            &args.args,
            is_dry_run,
        );
    }

    // Handle dry-run: exit without executing
    if is_dry_run {
        println!("\n(Dry run - not executing)");
        return Ok(());
    }

    // Handle no-sandbox mode
    if args.no_sandbox {
        eprintln!("Warning: Running without sandbox (--no-sandbox)");
        // Execute command directly without sandboxing
        let status = process::Command::new(&args.command)
            .args(&args.args)
            .status()
            .map_err(|e| anyhow::anyhow!("failed to execute command: {}", e))?;

        let code = status.code().unwrap_or(1);
        process::exit(code);
    }

    // Run command in sandbox
    let exit_code = platform::run_sandboxed(&policy, &args.command, &args.args, &session_tmpdir, args.verbose)?;

    process::exit(exit_code);
}

/// Print structured debug information for verbose/dry-run modes
fn print_debug_info(
    policy: &policy::types::SandboxPolicy,
    policy_name: &str,
    session_tmpdir: &PathBuf,
    platform_backend: &str,
    command: &str,
    args: &[String],
    use_stdout: bool,
) {
    let print = |msg: &str| {
        if use_stdout {
            println!("{}", msg);
        } else {
            eprintln!("{}", msg);
        }
    };

    print("========================================");
    print("Cage Sandbox Configuration");
    print("========================================");
    print(&format!("Policy name:        {}", policy_name));
    print(&format!("Session temp dir:   {}", session_tmpdir.display()));
    print(&format!("Platform backend:   {}", platform_backend));
    print(&format!("Command:            {}", command));
    if !args.is_empty() {
        print(&format!("Arguments:          {:?}", args));
    }
    print("");

    print("----------------------------------------");
    print("Resolved Policy");
    print("----------------------------------------");

    // Network policy
    print(&format!("network:            {:?}", policy.network()));
    print("");

    // Writable roots
    print("writable_roots:");
    if policy.writable_roots.is_empty() {
        print("  (none)");
    } else {
        for path in &policy.writable_roots {
            print(&format!("  - {}", path.display()));
        }
    }
    print("");

    // Write-restricted paths
    print("write_restricted_paths:");
    if policy.write_restricted_paths.is_empty() {
        print("  (none)");
    } else {
        for path in &policy.write_restricted_paths {
            print(&format!("  - {}", path.display()));
        }
    }
    print("");

    // Read-restricted paths
    print("read_restricted_paths:");
    if policy.read_restricted_paths.is_empty() {
        print("  (none)");
    } else {
        for path in &policy.read_restricted_paths {
            print(&format!("  - {}", path.display()));
        }
    }
    print("");

    // Environment policy
    let env = policy.env();
    print(&format!("env.mode:           {:?}", env.mode()));

    // Print filters in precedence order (as stored in the Vec)
    if !env.filters.is_empty() {
        print("env.filters:");
        for filter in &env.filters {
            let action_str = match filter.action {
                policy::types::FilterAction::Allow => "allow",
                policy::types::FilterAction::Block => "block",
            };
            print(&format!("  - [{}] {}", action_str, filter.pattern));
        }
    }

    if !env.set.is_empty() {
        print("env.set:");
        for (key, value) in &env.set {
            print(&format!("  {}={}", key, value));
        }
    }
    print("");

    // Platform-specific generated configuration
    print("----------------------------------------");
    print("Generated Sandbox Command/Profile");
    print("----------------------------------------");

    #[cfg(target_os = "linux")]
    {
        let argv = platform::linux::generate_bwrap_argv(policy, command, args, session_tmpdir);
        print("bwrap command:");
        print(&format!("  bwrap --args <memfd> -- {} {}", command, args.join(" ")));
        print("");
        print("Arguments passed via memfd:");
        print(&format!("  {}", argv[1..].join(" ")));
    }
    #[cfg(target_os = "macos")]
    {
        let profile =
            platform::macos::generate_seatbelt_profile(policy, command, args, session_tmpdir);
        print("Seatbelt profile:");
        for line in profile.lines() {
            print(&format!("  {}", line));
        }
    }
    #[cfg(target_os = "windows")]
    {
        let config = platform::windows::generate_windows_sandbox_config(
            policy,
            command,
            args,
            session_tmpdir,
        );
        for line in config.lines() {
            print(&format!("  {}", line));
        }
    }

    print("");
    print("========================================");
}

/// Create session temp directory with unique name
/// Format: /tmp/cage-{PID}-{RAND}/ (Linux/macOS) or %TEMP%\cage-{PID}-{RAND}\ (Windows)
fn create_session_tmpdir() -> anyhow::Result<PathBuf> {
    let pid = process::id();
    // Use timestamp nanos as random component (good enough for this use case)
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let rand_component = nanos % 10000;

    let tmpdir = std::env::temp_dir().join(format!("cage-{}-{}", pid, rand_component));
    fs::create_dir_all(&tmpdir).with_context(|| {
        format!(
            "failed to create session temp directory: {}",
            tmpdir.display()
        )
    })?;

    Ok(tmpdir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundled_config_embedded() {
        // Verify bundled config is embedded by loading it
        let args = cli::Args::parse_from(["cage", "test"]);
        let cfg = config::load_config(&args).unwrap();
        assert!(cfg.policies.contains_key("default"));
    }

    #[test]
    fn test_session_tmpdir_creation() {
        let tmpdir = create_session_tmpdir().unwrap();

        // Should exist
        assert!(tmpdir.exists());

        // Should be in temp directory
        assert!(tmpdir.starts_with(std::env::temp_dir()));

        // Should contain cage prefix and PID
        let name = tmpdir.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with("cage-"));
        assert!(name.contains(&process::id().to_string()));

        // Cleanup test directory
        let _ = fs::remove_dir_all(&tmpdir);
    }
}
