use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cage")]
#[command(about = "Cross-Platform AI Agent Sandbox CLI")]
#[command(version)]
pub struct Args {
    /// Policy name to apply (use '+' for composition in Phase 2)
    #[arg(short, long, value_name = "NAME")]
    pub policy: Option<String>,

    /// Shorthand: use current policy but override network to 'full'
    #[arg(long)]
    pub allow_network: bool,

    /// Run command unsandboxed (logs a warning)
    #[arg(long)]
    pub no_sandbox: bool,

    /// Path to config file
    #[arg(short, long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Additional writable paths
    #[arg(long, value_name = "PATH")]
    pub writable: Vec<PathBuf>,

    /// Paths to restrict writing
    #[arg(long, value_name = "PATH")]
    pub write_restrict: Vec<PathBuf>,

    /// Paths to restrict reading
    #[arg(long, value_name = "PATH")]
    pub read_restrict: Vec<PathBuf>,

    /// Show sandbox configuration before exec
    #[arg(short, long)]
    pub verbose: bool,

    /// Print the sandbox config and generated profile, don't exec
    #[arg(long)]
    pub dry_run: bool,

    /// Command to run
    #[arg(value_name = "COMMAND")]
    pub command: String,

    /// Arguments to pass to the command
    #[arg(
        value_name = "ARGS",
        trailing_var_arg = true,
        allow_hyphen_values = true
    )]
    pub args: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parses() {
        // Verify Args struct generates a valid clap command
        Args::command().debug_assert();
    }

    #[test]
    fn test_cli_basic_parsing() {
        let args = Args::parse_from(["cage", "--verbose", "echo", "hello"]);
        assert_eq!(args.command, "echo");
        assert_eq!(args.args, vec!["hello"]);
        assert!(args.verbose);
        assert!(!args.dry_run);
        assert!(!args.no_sandbox);
        assert!(!args.allow_network);
    }

    #[test]
    fn test_cli_with_policy() {
        let args = Args::parse_from(["cage", "--policy", "strict", "ls"]);
        assert_eq!(args.policy, Some("strict".to_string()));
        assert_eq!(args.command, "ls");
        assert!(args.args.is_empty());
    }

    #[test]
    fn test_cli_all_flags() {
        let args = Args::parse_from([
            "cage",
            "--policy",
            "default",
            "--allow-network",
            "--no-sandbox",
            "--config",
            "/path/to/config.toml",
            "--verbose",
            "--dry-run",
            "python",
            "script.py",
        ]);

        assert_eq!(args.policy, Some("default".to_string()));
        assert!(args.allow_network);
        assert!(args.no_sandbox);
        assert_eq!(args.config, Some(PathBuf::from("/path/to/config.toml")));
        assert!(args.verbose);
        assert!(args.dry_run);
        assert_eq!(args.command, "python");
        assert_eq!(args.args, vec!["script.py"]);
    }

    #[test]
    fn test_cli_path_overrides() {
        // Note: using 'cat' instead of 'sh -c' because '-c' conflicts with --config short flag
        let args = Args::parse_from([
            "cage",
            "--writable",
            "/workspace",
            "--write-restrict",
            ".git",
            "--read-restrict",
            "/etc/passwd",
            "cat",
            "file.txt",
        ]);

        assert_eq!(args.writable, vec![PathBuf::from("/workspace")]);
        assert_eq!(args.write_restrict, vec![PathBuf::from(".git")]);
        assert_eq!(args.read_restrict, vec![PathBuf::from("/etc/passwd")]);
        assert_eq!(args.command, "cat");
        assert_eq!(args.args, vec!["file.txt"]);
    }

    #[test]
    fn test_cli_multiple_path_args() {
        let args = Args::parse_from([
            "cage",
            "--writable",
            "/path1",
            "--writable",
            "/path2",
            "--write-restrict",
            ".git",
            "--write-restrict",
            ".env",
            "cmd",
        ]);

        assert_eq!(args.writable.len(), 2);
        assert_eq!(args.write_restrict.len(), 2);
    }

    #[test]
    fn test_cli_trailing_args() {
        // trailing_var_arg should consume all remaining arguments
        let args = Args::parse_from(["cage", "python", "-m", "http.server", "8080"]);

        assert_eq!(args.command, "python");
        assert_eq!(args.args, vec!["-m", "http.server", "8080"]);
    }

    #[test]
    fn test_cli_empty_args() {
        let args = Args::parse_from(["cage", "ls"]);
        assert_eq!(args.command, "ls");
        assert!(args.args.is_empty());
        assert!(!args.verbose);
        assert!(!args.dry_run);
        assert!(!args.no_sandbox);
        assert!(!args.allow_network);
    }

    #[test]
    fn test_cli_short_flags() {
        let args = Args::parse_from(["cage", "-p", "strict", "-c", "config.toml", "-v", "cmd"]);
        assert_eq!(args.policy, Some("strict".to_string()));
        assert_eq!(args.config, Some(PathBuf::from("config.toml")));
        assert!(args.verbose);
        assert_eq!(args.command, "cmd");
    }
}
