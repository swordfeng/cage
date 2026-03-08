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

    // Handle verbose output
    if args.verbose {
        eprintln!("Policy name: {}", policy_name);
        eprintln!("Session temp dir: {}", session_tmpdir.display());
        eprintln!("Platform backend: {}", platform_backend);
        eprintln!("\nResolved policy:");
        eprintln!("  Writable roots:");
        for path in &policy.writable_roots {
            eprintln!("    - {}", path.display());
        }
        eprintln!("  Write-restricted paths:");
        for path in &policy.write_restricted_paths {
            eprintln!("    - {}", path.display());
        }
        eprintln!("  Read-restricted paths:");
        for path in &policy.read_restricted_paths {
            eprintln!("    - {}", path.display());
        }
        eprintln!("  Network: {:?}", policy.network());
        eprintln!("  Environment mode: {:?}", policy.env().mode());
    }

    // Handle dry-run: print generated command/profile and exit
    if args.dry_run {
        println!("Sandbox configuration:");
        println!("  Policy name: {}", policy_name);
        println!("  Session temp dir: {}", session_tmpdir.display());
        println!("  Platform backend: {}", platform_backend);
        println!("  Writable roots: {:?}", policy.writable_roots);
        println!("  Write restricted: {:?}", policy.write_restricted_paths);
        println!("  Read restricted: {:?}", policy.read_restricted_paths);
        println!("  Network: {:?}", policy.network());
        println!("  Command: {}", args.command);
        println!("  Args: {:?}", args.args);

        // Show generated command/profile for the platform
        println!("\nGenerated sandbox configuration:");
        #[cfg(target_os = "linux")]
        {
            let argv = platform::linux::generate_bwrap_argv(
                &policy,
                &args.command,
                &args.args,
                &session_tmpdir,
            );
            println!("\nbwrap command:");
            println!("  {}", argv.join(" "));
        }
        #[cfg(target_os = "macos")]
        {
            let profile = platform::macos::generate_seatbelt_profile(
                &policy,
                &args.command,
                &args.args,
                &session_tmpdir,
            );
            println!("\nSeatbelt profile:");
            println!("{}", profile);
        }
        #[cfg(target_os = "windows")]
        {
            let config = platform::windows::generate_windows_sandbox_config(
                &policy,
                &args.command,
                &args.args,
                &session_tmpdir,
            );
            println!("\n{}", config);
        }

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
