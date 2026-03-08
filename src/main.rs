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

const BUNDLED_CONFIG: &str = include_str!("../config/cage.toml");

fn main() {
    let args = cli::Args::parse();

    if let Err(e) = run(args) {
        eprintln!("cage error: {}", e);
        process::exit(1);
    }
}

fn run(args: cli::Args) -> anyhow::Result<()> {
    // Load and merge configuration
    let merged_config = config::load_config(&args)?;

    // Resolve the policy name first (for verbose output)
    let policy_name = merged_config.resolve_policy_name(&args)?;

    // Resolve the policy (applies CLI overrides and variable expansion)
    let policy = merged_config.resolve_policy(&args, args.verbose)?;

    // Handle verbose output
    if args.verbose {
        eprintln!("Policy name: {}", policy_name);
        eprintln!("Policy config: {:?}", policy);
    }

    // Handle dry-run: print config and exit
    if args.dry_run {
        println!("Sandbox configuration:");
        println!("  Policy name: {}", policy_name);
        println!("  Writable roots: {:?}", policy.writable_roots);
        println!("  Write restricted: {:?}", policy.write_restricted_paths);
        println!("  Read restricted: {:?}", policy.read_restricted_paths);
        println!("  Network: {:?}", policy.network());
        println!("  Command: {}", args.command);
        println!("  Args: {:?}", args.args);
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

    // Create session temp directory
    // TODO: T1.6 - Use proper /tmp/cage-{PID}-{RAND}/ format with cleanup
    let session_tmpdir = create_session_tmpdir()?;

    // Register cleanup for temp directory
    let tmpdir_path = session_tmpdir.clone();
    defer! {
        let _ = fs::remove_dir_all(&tmpdir_path);
    }

    // Run command in sandbox
    let exit_code = platform::run_sandboxed(&policy, &args.command, &args.args, &session_tmpdir)?;

    process::exit(exit_code);
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
        // Verify bundled config is embedded
        assert!(BUNDLED_CONFIG.contains("[policies.default]"));
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
