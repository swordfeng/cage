use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct SandboxPolicy {
    #[serde(default)]
    pub name: String,
    pub writable_roots: Vec<PathBuf>,
    pub write_restricted_paths: Vec<PathBuf>,
    pub read_restricted_paths: Vec<PathBuf>,
    pub network: NetworkPolicy,
    pub env: EnvPolicy,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    None,
    Localhost,
    Full,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvMode {
    Allowlist,
    Blocklist,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvPolicy {
    pub mode: EnvMode,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub set: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandPolicy {
    pub pattern: String,
    pub policy: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct PlatformConfig {
    #[serde(default)]
    pub linux: LinuxPlatformConfig,
    #[serde(default)]
    pub macos: MacosPlatformConfig,
    #[serde(default)]
    pub windows: WindowsPlatformConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct LinuxPlatformConfig {
    #[serde(default = "default_true")]
    pub fail_on_sandbox_error: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MacosPlatformConfig {
    #[serde(default = "default_true")]
    pub fail_on_sandbox_error: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WindowsPlatformConfig {
    #[serde(default = "default_cage_group")]
    pub cage_group: String,
}

fn default_true() -> bool {
    true
}

fn default_cage_group() -> String {
    "CageUsers".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub policies: HashMap<String, SandboxPolicy>,
    #[serde(default)]
    pub command_policy: Vec<CommandPolicy>,
    #[serde(default)]
    pub platform: PlatformConfig,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BUNDLED_CONFIG: &str = include_str!("../../config/cage.toml");

    #[test]
    fn test_bundled_config_parses() {
        let config: Config = toml::from_str(BUNDLED_CONFIG).expect("bundled config should parse");
        assert!(config.policies.contains_key("default"));
        assert!(config.policies.contains_key("strict"));
        assert_eq!(config.command_policy.len(), 4);
    }

    #[test]
    fn test_default_policy_values() {
        // Verify the default policy has expected values
        let config: Config = toml::from_str(BUNDLED_CONFIG).unwrap();
        let default = config.policies.get("default").unwrap();
        assert!(matches!(default.network, NetworkPolicy::Full));

        let strict = config.policies.get("strict").unwrap();
        assert!(matches!(strict.network, NetworkPolicy::None));
    }
}
