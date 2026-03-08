use crate::cli::Args;
use crate::policy::merge::glob_match;
use crate::policy::types::{Config, SandboxPolicy};
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

const BUNDLED_CONFIG: &str = include_str!("../config/cage.toml");

/// Loads and merges configuration from multiple sources:
/// 1. User config (~/.config/cage/cage.toml) - created from bundled if missing
/// 2. Project config (.cage.toml, walking up from CWD)
/// 3. CLI config file (--config)
/// 4. CLI flag overrides (--writable, --write-restrict, etc.)
pub fn load_config(args: &Args) -> Result<MergedConfig> {
    load_config_internal(args, true)
}

/// Internal implementation with option to skip user config initialization.
/// Set `initialize_user` to false in tests to avoid side effects.
fn load_config_internal(args: &Args, initialize_user: bool) -> Result<MergedConfig> {
    // Initialize user config if it doesn't exist (only in production)
    if initialize_user {
        initialize_user_config()?;
    }

    // Start with user config (or bundled if user config missing)
    let mut config = load_user_or_bundled_config()?;

    // Layer 2: Project config (walk up from CWD)
    if let Some(project_config) = find_and_load_project_config()? {
        merge_config(&mut config, project_config);
    }

    // Layer 3: CLI config file
    if let Some(ref cli_config_path) = args.config {
        let cli_config = load_config_file(cli_config_path)?;
        merge_config(&mut config, cli_config);
    }

    Ok(MergedConfig { inner: config })
}

/// Initialize user config directory and file if they don't exist.
/// If the user config file doesn't exist, create it from bundled defaults.
fn initialize_user_config() -> Result<()> {
    let user_config_path = match user_config_path() {
        Some(path) => path,
        None => return Ok(()), // Can't determine config path on this platform
    };

    // If user config already exists, nothing to do
    if user_config_path.exists() {
        return Ok(());
    }

    // Create the config directory if it doesn't exist
    if let Some(parent) = user_config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create config directory: {}", parent.display()))?;
    }

    // Write bundled config as the initial user config
    fs::write(&user_config_path, BUNDLED_CONFIG).with_context(|| {
        format!(
            "failed to write initial user config: {}",
            user_config_path.display()
        )
    })?;

    Ok(())
}

/// Load user config if it exists, otherwise fall back to bundled config.
fn load_user_or_bundled_config() -> Result<Config> {
    let user_config_path = match user_config_path() {
        Some(path) => path,
        None => {
            // No user config path on this platform, use bundled
            return toml::from_str(BUNDLED_CONFIG).context("failed to parse bundled config");
        }
    };

    if user_config_path.exists() {
        // Load user config as the base
        load_config_file(&user_config_path)
    } else {
        // Fall back to bundled config (shouldn't happen after initialization)
        toml::from_str(BUNDLED_CONFIG).context("failed to parse bundled config")
    }
}

/// Configuration after all merging is complete
pub struct MergedConfig {
    inner: Config,
}

impl MergedConfig {
    /// Get a policy by name
    pub fn get_policy(&self, name: &str) -> Result<&SandboxPolicy> {
        self.inner
            .policies
            .get(name)
            .with_context(|| format!("policy '{}' not found", name))
    }

    /// Resolve the final policy, applying CLI overrides on top.
    /// This is the primary API for callers that need a ready-to-use policy.
    pub fn resolve_policy(&self, args: &Args) -> Result<SandboxPolicy> {
        let name = self.resolve_policy_name(args)?;
        let mut policy = self.get_policy(&name)?.clone();

        // Apply CLI path overrides to the resolved policy
        policy.writable_roots.extend(args.writable.iter().cloned());
        policy
            .write_restricted_paths
            .extend(args.write_restrict.iter().cloned());
        policy
            .read_restricted_paths
            .extend(args.read_restrict.iter().cloned());

        if args.allow_network {
            policy.network = Some(crate::policy::types::NetworkPolicy::Full);
        }

        Ok(policy)
    }

    /// Find the default policy for a command using command_policy matching
    pub fn default_policy_for(&self, command: &str) -> Option<&str> {
        let command_name = Path::new(command)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(command);

        for cmd_policy in &self.inner.command_policy {
            if glob_match(&cmd_policy.pattern, command_name) {
                return Some(&cmd_policy.policy);
            }
        }

        None
    }

    /// Resolve the final policy name based on:
    /// 1. --policy flag (explicit user choice)
    /// 2. command_policy match (pattern-based)
    /// 3. "default" policy
    pub fn resolve_policy_name(&self, args: &Args) -> Result<String> {
        // Priority 1: --policy flag
        if let Some(ref policy_name) = args.policy {
            // Validate the policy exists
            if !self.inner.policies.contains_key(policy_name) {
                bail!("policy '{}' not found", policy_name);
            }
            return Ok(policy_name.clone());
        }

        // Priority 2: command_policy match
        if let Some(policy_name) = self.default_policy_for(&args.command) {
            return Ok(policy_name.to_string());
        }

        // Priority 3: "default" policy
        if self.inner.policies.contains_key("default") {
            return Ok("default".to_string());
        }

        bail!("no policy specified and no 'default' policy found")
    }

    /// Get the underlying config (for tests/debugging)
    pub fn config(&self) -> &Config {
        &self.inner
    }
}

/// Load a single config file from disk
fn load_config_file(path: &Path) -> Result<Config> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read config file: {}", path.display()))?;

    toml::from_str(&contents)
        .with_context(|| format!("failed to parse config file: {}", path.display()))
}

/// Get the path to the user config file
fn user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("cage").join("cage.toml"))
}

/// Load .cage.toml from the current working directory, if present.
fn find_and_load_project_config() -> Result<Option<Config>> {
    let config_path = std::env::current_dir()?.join(".cage.toml");
    if config_path.exists() {
        load_config_file(&config_path).map(Some)
    } else {
        Ok(None)
    }
}

/// Merge `other` into `base`, with `other` taking precedence.
/// Merge semantics:
/// - Policies: merge by name, with proper field-level merging
/// - Path lists (writable_roots, etc.): Union (extend)
/// - Network: Override (last wins)
/// - Env: Deep merge
///   - mode: Override
///   - allow/block lists: Union
///   - set: Merge maps (later values win)
fn merge_config(base: &mut Config, other: Config) {
    // Merge policies: merge fields for same policy names
    for (name, other_policy) in other.policies {
        base.policies
            .entry(name)
            .and_modify(|base_policy| base_policy.merge(&other_policy))
            .or_insert(other_policy);
    }

    // Merge command_policy: prepend other's entries so higher-priority patterns are checked first
    let mut merged = other.command_policy;
    merged.extend(std::mem::take(&mut base.command_policy));
    base.command_policy = merged;

    // Merge platform config
    // Note: PlatformConfig uses Default, so we just use other's values directly
    base.platform = other.platform;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::NetworkPolicy;

    fn create_test_args(command: &str) -> Args {
        Args {
            policy: None,
            allow_network: false,
            no_sandbox: false,
            config: None,
            writable: vec![],
            write_restrict: vec![],
            read_restrict: vec![],
            verbose: false,
            dry_run: false,
            command: command.to_string(),
            args: vec![],
        }
    }

    /// Load config for tests without initializing user config (to avoid side effects)
    fn load_test_config(args: &Args) -> Result<MergedConfig> {
        load_config_internal(args, false)
    }

    #[test]
    fn test_resolve_policy_explicit() {
        let args = Args {
            policy: Some("strict".to_string()),
            ..create_test_args("test")
        };

        let config = load_test_config(&args).unwrap();
        let policy_name = config.resolve_policy_name(&args).unwrap();
        assert_eq!(policy_name, "strict".to_string());
    }

    #[test]
    fn test_resolve_policy_command_match() {
        // "opencode" should match the default policy per bundled config
        let args = create_test_args("opencode");
        let config = load_test_config(&args).unwrap();
        let policy_name = config.resolve_policy_name(&args).unwrap();
        assert_eq!(policy_name, "default".to_string());
    }

    #[test]
    fn test_resolve_policy_aider_strict() {
        // "aider" should match "strict" policy per bundled config
        let args = create_test_args("aider");
        let config = load_test_config(&args).unwrap();
        let policy_name = config.resolve_policy_name(&args).unwrap();
        assert_eq!(policy_name, "strict".to_string());
    }

    #[test]
    fn test_resolve_policy_default_fallback() {
        // Unknown command should fall back to "default"
        let args = create_test_args("unknown-cmd");
        let config = load_test_config(&args).unwrap();
        let policy_name = config.resolve_policy_name(&args).unwrap();
        assert_eq!(policy_name, "default".to_string());
    }

    #[test]
    fn test_resolve_policy_missing() {
        // Create args with non-existent policy
        let args = Args {
            policy: Some("nonexistent".to_string()),
            ..create_test_args("test")
        };

        let config = load_test_config(&args).unwrap();
        let result = config.resolve_policy_name(&args);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_command_policy_matching() {
        let args = create_test_args("/usr/bin/opencode");
        let config = load_test_config(&args).unwrap();

        // Should match on file_stem "opencode"
        let policy_name = config.default_policy_for("/usr/bin/opencode").unwrap();
        assert_eq!(policy_name, "default");
    }

    #[test]
    fn test_cli_writable_override() {
        let args = Args {
            writable: vec![PathBuf::from("/extra/path")],
            ..create_test_args("test")
        };

        let config = load_test_config(&args).unwrap();
        let policy = config.resolve_policy(&args).unwrap();

        // Should include the extra writable path
        assert!(policy
            .writable_roots
            .iter()
            .any(|p| p.to_string_lossy().contains("/extra/path")));
    }

    #[test]
    fn test_cli_network_override() {
        // This test requires a policy with non-Full network to verify override
        // The bundled "strict" policy has network = "none"
        let args = Args {
            policy: Some("strict".to_string()),
            allow_network: true,
            ..create_test_args("test")
        };

        let config = load_test_config(&args).unwrap();
        let policy = config.resolve_policy(&args).unwrap();

        // allow_network should override to Full
        assert!(matches!(policy.network, Some(NetworkPolicy::Full)));
    }

    #[test]
    fn test_cli_writable_override_respects_command_policy() {
        // "aider" matches "strict" via command_policy; --writable should apply to strict, not default
        let args = Args {
            writable: vec![PathBuf::from("/extra/path")],
            ..create_test_args("aider")
        };

        let config = load_test_config(&args).unwrap();
        let policy = config.resolve_policy(&args).unwrap();

        assert!(policy
            .writable_roots
            .iter()
            .any(|p| p.to_string_lossy().contains("/extra/path")));
        // Also confirm we got the strict policy (network = none)
        assert!(matches!(policy.network, Some(NetworkPolicy::None)));
    }

    #[test]
    fn test_bundled_config_loaded() {
        let args = create_test_args("test");
        let config = load_test_config(&args).unwrap();

        // Should have default and strict policies
        assert!(config.get_policy("default").is_ok());
        assert!(config.get_policy("strict").is_ok());

        // Should have command_policy entries
        let cfg = config.config();
        assert!(!cfg.command_policy.is_empty());
    }
}
