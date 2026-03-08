use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cage")]
#[command(about = "Cross-Platform AI Agent Sandbox CLI")]
#[command(version)]
pub struct Args {
    #[arg(short, long, value_name = "NAME")]
    pub policy: Option<String>,

    #[arg(
        long,
        help = "Shorthand: use current policy but override network to 'full'"
    )]
    pub allow_network: bool,

    #[arg(long, help = "Run command unsandboxed (logs a warning)")]
    pub no_sandbox: bool,

    #[arg(short, long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub passthrough: Vec<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub writable: Vec<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub write_restrict: Vec<PathBuf>,

    #[arg(long, value_name = "PATH")]
    pub read_restrict: Vec<PathBuf>,

    #[arg(short, long, help = "Show sandbox configuration before exec")]
    pub verbose: bool,

    #[arg(
        long,
        help = "Print the sandbox config and generated profile, don't exec"
    )]
    pub dry_run: bool,

    #[arg(value_name = "COMMAND")]
    pub command: String,

    #[arg(value_name = "ARGS")]
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
    }

    #[test]
    fn test_cli_with_policy() {
        let args = Args::parse_from(["cage", "--policy", "strict", "ls"]);
        assert_eq!(args.policy, Some("strict".to_string()));
        assert_eq!(args.command, "ls");
    }
}
