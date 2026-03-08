use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct SandboxPolicy {
    #[serde(default)]
    pub writable_roots: Vec<PathBuf>,
    #[serde(default)]
    pub write_restricted_paths: Vec<PathBuf>,
    #[serde(default)]
    pub read_restricted_paths: Vec<PathBuf>,
    /// Network policy - if None, use base value during merge
    pub(crate) network: Option<NetworkPolicy>,
    /// Environment policy - if None, use base value during merge
    pub(crate) env: Option<EnvPolicy>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            writable_roots: Vec::new(),
            write_restricted_paths: Vec::new(),
            read_restricted_paths: Vec::new(),
            network: None,
            env: None,
        }
    }
}

impl SandboxPolicy {
    /// Merge another policy into this one.
    /// - Path lists: Union (extend with other)
    /// - Network: Override only if other is Some
    /// - Env: Deep merge only if other is Some
    pub fn merge(&mut self, other: &Self) {
        // Path lists: union (always, since missing = empty Vec via default)
        self.writable_roots
            .extend(other.writable_roots.iter().cloned());
        self.write_restricted_paths
            .extend(other.write_restricted_paths.iter().cloned());
        self.read_restricted_paths
            .extend(other.read_restricted_paths.iter().cloned());

        // Network: override only if explicitly set
        if let Some(ref network) = other.network {
            self.network = Some(network.clone());
        }

        // Env: deep merge only if explicitly set
        if let Some(ref other_env) = other.env {
            if let Some(ref mut self_env) = self.env {
                self_env.merge(other_env);
            } else {
                self.env = Some(other_env.clone());
            }
        }
    }

    /// Get network policy, using default if not set
    pub fn network(&self) -> &NetworkPolicy {
        self.network.as_ref().unwrap_or(&NetworkPolicy::Full)
    }

    /// Get env policy, using default if not set
    pub fn env(&self) -> &EnvPolicy {
        static DEFAULT_ENV: std::sync::OnceLock<EnvPolicy> = std::sync::OnceLock::new();
        self.env.as_ref().unwrap_or_else(|| {
            DEFAULT_ENV.get_or_init(|| EnvPolicy {
                mode: Some(EnvMode::Blocklist),
                allow: Vec::new(),
                block: Vec::new(),
                set: HashMap::new(),
            })
        })
    }
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
    /// Environment filter mode - if None, use base value during merge
    pub(crate) mode: Option<EnvMode>,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub block: Vec<String>,
    #[serde(default)]
    pub set: HashMap<String, String>,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self {
            mode: None,
            allow: Vec::new(),
            block: Vec::new(),
            set: HashMap::new(),
        }
    }
}

impl EnvPolicy {
    /// Merge another env policy into this one.
    /// - mode: Override only if other is Some
    /// - allow/block lists: Union (extend)
    /// - set: Merge maps (other values win on conflict)
    pub fn merge(&mut self, other: &Self) {
        // Mode: override only if explicitly set
        if let Some(ref mode) = other.mode {
            self.mode = Some(mode.clone());
        }

        // Allow/block lists: union (always, since missing = empty via default)
        self.allow.extend(other.allow.iter().cloned());
        self.block.extend(other.block.iter().cloned());

        // Set: merge maps, other wins on conflict
        for (key, value) in &other.set {
            self.set.insert(key.clone(), value.clone());
        }
    }

    /// Get mode, using Blocklist as default if not set
    pub fn mode(&self) -> EnvMode {
        self.mode.clone().unwrap_or(EnvMode::Blocklist)
    }
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

#[derive(Debug, Clone, Deserialize)]
pub struct LinuxPlatformConfig {
    #[serde(default = "default_true")]
    pub fail_on_sandbox_error: bool,
}

impl Default for LinuxPlatformConfig {
    fn default() -> Self {
        Self {
            fail_on_sandbox_error: true,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct MacosPlatformConfig {
    #[serde(default = "default_true")]
    pub fail_on_sandbox_error: bool,
}

impl Default for MacosPlatformConfig {
    fn default() -> Self {
        Self {
            fail_on_sandbox_error: true,
        }
    }
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

    #[cfg(target_os = "linux")]
    const BUNDLED_CONFIG: &str = include_str!("../../config/cage-linux.toml");

    #[cfg(target_os = "macos")]
    const BUNDLED_CONFIG: &str = include_str!("../../config/cage-macos.toml");

    #[cfg(target_os = "windows")]
    const BUNDLED_CONFIG: &str = include_str!("../../config/cage-windows.toml");

    #[test]
    fn test_bundled_config_parses() {
        let config: Config = toml::from_str(BUNDLED_CONFIG).expect("bundled config should parse");
        assert!(config.policies.contains_key("default"));
        assert!(config.policies.contains_key("strict"));
        assert_eq!(config.command_policy.len(), 4);
    }

    #[test]
    fn test_platform_defaults() {
        // Default trait must give fail_on_sandbox_error = true,
        // matching the serde default, so missing TOML sections behave correctly.
        let linux = LinuxPlatformConfig::default();
        assert!(linux.fail_on_sandbox_error);
        let macos = MacosPlatformConfig::default();
        assert!(macos.fail_on_sandbox_error);

        // PlatformConfig::default() should propagate
        let platform = PlatformConfig::default();
        assert!(platform.linux.fail_on_sandbox_error);
        assert!(platform.macos.fail_on_sandbox_error);
    }

    #[test]
    fn test_default_policy_values() {
        // Verify the default policy has expected values
        let config: Config = toml::from_str(BUNDLED_CONFIG).unwrap();
        let default = config.policies.get("default").unwrap();
        assert!(matches!(default.network, Some(NetworkPolicy::Full)));

        let strict = config.policies.get("strict").unwrap();
        assert!(matches!(strict.network, Some(NetworkPolicy::None)));
    }

    #[test]
    fn test_env_policy_merge() {
        let mut base = EnvPolicy {
            mode: Some(EnvMode::Blocklist),
            allow: vec!["PATH".to_string()],
            block: vec!["SECRET".to_string()],
            set: [("BASE".to_string(), "1".to_string())]
                .into_iter()
                .collect(),
        };

        let other = EnvPolicy {
            mode: Some(EnvMode::Allowlist),
            allow: vec!["HOME".to_string()],
            block: vec!["TOKEN".to_string()],
            set: [
                ("OTHER".to_string(), "2".to_string()),
                ("BASE".to_string(), "overridden".to_string()),
            ]
            .into_iter()
            .collect(),
        };

        base.merge(&other);

        // Mode should be overridden
        assert!(matches!(base.mode, Some(EnvMode::Allowlist)));

        // Lists should be unioned
        assert!(base.allow.contains(&"PATH".to_string()));
        assert!(base.allow.contains(&"HOME".to_string()));
        assert!(base.block.contains(&"SECRET".to_string()));
        assert!(base.block.contains(&"TOKEN".to_string()));

        // Set should be merged, other wins on conflict
        assert_eq!(base.set.get("BASE"), Some(&"overridden".to_string()));
        assert_eq!(base.set.get("OTHER"), Some(&"2".to_string()));
    }

    #[test]
    fn test_env_policy_merge_preserves_base_mode() {
        // If other doesn't set mode, base mode should be preserved
        let mut base = EnvPolicy {
            mode: Some(EnvMode::Allowlist),
            allow: vec!["PATH".to_string()],
            block: vec![],
            set: HashMap::new(),
        };

        let other = EnvPolicy {
            mode: None, // Not set
            allow: vec!["HOME".to_string()],
            block: vec![],
            set: HashMap::new(),
        };

        base.merge(&other);

        // Mode should still be Allowlist from base
        assert!(matches!(base.mode, Some(EnvMode::Allowlist)));
        // But allow list should be merged
        assert!(base.allow.contains(&"PATH".to_string()));
        assert!(base.allow.contains(&"HOME".to_string()));
    }

    #[test]
    fn test_sandbox_policy_merge() {
        let mut base = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/base")],
            write_restricted_paths: vec![PathBuf::from("/base/.git")],
            read_restricted_paths: vec![PathBuf::from("/secret")],
            network: Some(NetworkPolicy::None),
            env: Some(EnvPolicy {
                mode: Some(EnvMode::Blocklist),
                allow: vec![],
                block: vec!["OLD".to_string()],
                set: HashMap::new(),
            }),
        };

        let other = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/other")],
            write_restricted_paths: vec![PathBuf::from("/other/.env")],
            read_restricted_paths: vec![PathBuf::from("/other/secret")],
            network: Some(NetworkPolicy::Full),
            env: Some(EnvPolicy {
                mode: Some(EnvMode::Allowlist),
                allow: vec!["PATH".to_string()],
                block: vec!["NEW".to_string()],
                set: [("KEY".to_string(), "value".to_string())]
                    .into_iter()
                    .collect(),
            }),
        };

        base.merge(&other);

        // Path lists should be unioned
        assert_eq!(base.writable_roots.len(), 2);
        assert!(base.writable_roots.contains(&PathBuf::from("/base")));
        assert!(base.writable_roots.contains(&PathBuf::from("/other")));

        assert_eq!(base.write_restricted_paths.len(), 2);
        assert_eq!(base.read_restricted_paths.len(), 2);

        // Network should be overridden
        assert!(matches!(base.network, Some(NetworkPolicy::Full)));

        // Env should be deep merged
        let env = base.env.as_ref().unwrap();
        assert!(matches!(env.mode, Some(EnvMode::Allowlist)));
        assert!(env.block.contains(&"OLD".to_string()));
        assert!(env.block.contains(&"NEW".to_string()));
    }

    #[test]
    fn test_sandbox_policy_merge_preserves_base_network() {
        // If other doesn't set network, base network should be preserved
        let mut base = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/base")],
            write_restricted_paths: vec![],
            read_restricted_paths: vec![],
            network: Some(NetworkPolicy::None),
            env: None,
        };

        let other = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/other")],
            write_restricted_paths: vec![],
            read_restricted_paths: vec![],
            network: None, // Not set
            env: None,
        };

        base.merge(&other);

        // Network should still be None from base
        assert!(matches!(base.network, Some(NetworkPolicy::None)));
        // But paths should still be merged
        assert_eq!(base.writable_roots.len(), 2);
    }

    #[test]
    fn test_sandbox_policy_merge_empty_other() {
        let mut base = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/base")],
            write_restricted_paths: vec![],
            read_restricted_paths: vec![],
            network: Some(NetworkPolicy::Full),
            env: Some(EnvPolicy {
                mode: Some(EnvMode::Blocklist),
                allow: vec!["PATH".to_string()],
                block: vec![],
                set: HashMap::new(),
            }),
        };

        let other = SandboxPolicy {
            writable_roots: vec![],
            write_restricted_paths: vec![],
            read_restricted_paths: vec![],
            network: Some(NetworkPolicy::None),
            env: Some(EnvPolicy {
                mode: Some(EnvMode::Allowlist),
                allow: vec![],
                block: vec![],
                set: HashMap::new(),
            }),
        };

        base.merge(&other);

        // Original paths should remain
        assert_eq!(base.writable_roots.len(), 1);
        assert!(base.writable_roots.contains(&PathBuf::from("/base")));

        // Network should still be overridden (explicitly set to None)
        assert!(matches!(base.network, Some(NetworkPolicy::None)));

        // Mode should be overridden
        let env = base.env.as_ref().unwrap();
        assert!(matches!(env.mode, Some(EnvMode::Allowlist)));
    }
}
