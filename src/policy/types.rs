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
    /// Allow GUI access (X11/Wayland sockets, DRI devices) - if None, use base value during merge
    pub(crate) enable_gui: Option<bool>,
    /// Allow audio access (ALSA/PulseAudio/PipeWire) - if None, use base value during merge
    pub(crate) enable_audio: Option<bool>,
}

impl Default for SandboxPolicy {
    fn default() -> Self {
        Self {
            writable_roots: Vec::new(),
            write_restricted_paths: Vec::new(),
            read_restricted_paths: Vec::new(),
            network: None,
            env: None,
            enable_gui: None,
            enable_audio: None,
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

        // enable_gui / enable_audio: override only if explicitly set
        if let Some(v) = other.enable_gui {
            self.enable_gui = Some(v);
        }
        if let Some(v) = other.enable_audio {
            self.enable_audio = Some(v);
        }
    }

    /// Get network policy, using default if not set
    pub fn network(&self) -> &NetworkPolicy {
        self.network.as_ref().unwrap_or(&NetworkPolicy::None)
    }

    /// Get enable_gui, defaulting to false (secure default)
    pub fn enable_gui(&self) -> bool {
        self.enable_gui.unwrap_or(false)
    }

    /// Get enable_audio, defaulting to false (secure default)
    pub fn enable_audio(&self) -> bool {
        self.enable_audio.unwrap_or(false)
    }

    /// Get env policy, using default if not set
    pub fn env(&self) -> &EnvPolicy {
        static DEFAULT_ENV: std::sync::OnceLock<EnvPolicy> = std::sync::OnceLock::new();
        self.env.as_ref().unwrap_or_else(|| {
            DEFAULT_ENV.get_or_init(|| EnvPolicy {
                mode: Some(EnvMode::DefaultAllow),
                filters: Vec::new(),
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
    /// Default to allowing environment variables (pass through by default)
    DefaultAllow,
    /// Default to blocking environment variables (filter by default)
    DefaultBlock,
}

/// A single environment variable filter with pattern and action
#[derive(Debug, Clone, Deserialize)]
pub struct EnvFilter {
    pub pattern: String,
    pub action: FilterAction,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilterAction {
    Allow,
    Block,
}

/// Intermediate representation for deserializing env policy from TOML
/// Block patterns come before allow patterns in the filter list
#[derive(Debug, Clone, Deserialize)]
struct EnvPolicyRaw {
    #[serde(default)]
    mode: Option<EnvMode>,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    block: Vec<String>,
    #[serde(default)]
    set: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct EnvPolicy {
    /// Environment filter mode - default action when no filter matches
    pub(crate) mode: Option<EnvMode>,
    /// Ordered list of filters: block patterns come before allow patterns within one file
    /// When merging, upper layer filters are prepended to lower layer filters
    pub(crate) filters: Vec<EnvFilter>,
    /// Forced overrides, always applied after filtering
    pub(crate) set: HashMap<String, String>,
}

impl Default for EnvPolicy {
    fn default() -> Self {
        Self {
            mode: None,
            filters: Vec::new(),
            set: HashMap::new(),
        }
    }
}

impl<'de> Deserialize<'de> for EnvPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = EnvPolicyRaw::deserialize(deserializer)?;

        // Build filters list: block patterns first, then allow patterns
        let mut filters = Vec::new();

        // Add block filters first
        for pattern in raw.block {
            filters.push(EnvFilter {
                pattern,
                action: FilterAction::Block,
            });
        }

        // Add allow filters after block filters
        for pattern in raw.allow {
            filters.push(EnvFilter {
                pattern,
                action: FilterAction::Allow,
            });
        }

        Ok(EnvPolicy {
            mode: raw.mode,
            filters,
            set: raw.set,
        })
    }
}

impl EnvPolicy {
    /// Merge another env policy into this one.
    /// - mode: Override only if other is Some
    /// - filters: Prepend other's filters (upper layer takes precedence)
    /// - set: Merge maps (other values win on conflict)
    pub fn merge(&mut self, other: &Self) {
        // Mode: override only if explicitly set
        if let Some(ref mode) = other.mode {
            self.mode = Some(mode.clone());
        }

        // Filters: prepend other's filters (upper layer takes precedence)
        // Other's filters are checked first, then our existing filters
        let mut new_filters = other.filters.clone();
        new_filters.extend(self.filters.iter().cloned());
        self.filters = new_filters;

        // Set: merge maps, other wins on conflict
        for (key, value) in &other.set {
            self.set.insert(key.clone(), value.clone());
        }
    }

    /// Get mode, using Allowlist as default if not set
    pub fn mode(&self) -> EnvMode {
        self.mode.clone().unwrap_or(EnvMode::DefaultAllow)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandPolicy {
    pub pattern: String,
    pub policy: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub policies: HashMap<String, SandboxPolicy>,
    #[serde(default)]
    pub command_policy: Vec<CommandPolicy>,
}

impl Config {
    /// Get a policy by name
    pub fn get_policy(&self, name: &str) -> anyhow::Result<&SandboxPolicy> {
        self.policies
            .get(name)
            .ok_or_else(|| anyhow::anyhow!("policy '{}' not found", name))
    }

    /// Find the default policy for a command using command_policy matching
    pub fn default_policy_for(&self, command: &str) -> Option<&str> {
        use crate::policy::merge::glob_match;

        let command_name = std::path::Path::new(command)
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or(command);

        for cmd_policy in &self.command_policy {
            if glob_match(&cmd_policy.pattern, command_name) {
                return Some(&cmd_policy.policy);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bundled_config_parses() {
        let config: Config =
            toml::from_str(crate::config::BUNDLED_CONFIG).expect("bundled config should parse");
        assert!(config.policies.contains_key("default"));
        assert!(config.policies.contains_key("strict"));
        assert_eq!(config.command_policy.len(), 4);
    }

    #[test]
    fn test_default_policy_values() {
        // Verify the default policy has expected values
        let config: Config = toml::from_str(crate::config::BUNDLED_CONFIG).unwrap();
        let default = config.policies.get("default").unwrap();
        assert!(matches!(default.network, Some(NetworkPolicy::Full)));

        let strict = config.policies.get("strict").unwrap();
        assert!(matches!(strict.network, Some(NetworkPolicy::None)));
    }

    #[test]
    fn test_env_policy_merge() {
        // Base policy: block SECRET, allow PATH
        let mut base: EnvPolicy = toml::from_str(
            r#"
mode = "default_allow"
block = ["SECRET"]
allow = ["PATH"]
set = { BASE = "1" }
"#,
        )
        .unwrap();

        // Other policy: block TOKEN, allow HOME
        let other: EnvPolicy = toml::from_str(
            r#"
mode = "default_block"
block = ["TOKEN"]
allow = ["HOME"]
set = { OTHER = "2", BASE = "overridden" }
"#,
        )
        .unwrap();

        base.merge(&other);

        // Mode should be overridden to default_block (DefaultBlock)
        assert!(matches!(base.mode, Some(EnvMode::DefaultBlock)));

        // Filters should be prepended: other.filters come first, then base.filters
        // So: TOKEN(block), HOME(allow), SECRET(block), PATH(allow)
        assert_eq!(base.filters.len(), 4);
        assert_eq!(base.filters[0].pattern, "TOKEN");
        assert!(matches!(base.filters[0].action, FilterAction::Block));
        assert_eq!(base.filters[1].pattern, "HOME");
        assert!(matches!(base.filters[1].action, FilterAction::Allow));
        assert_eq!(base.filters[2].pattern, "SECRET");
        assert!(matches!(base.filters[2].action, FilterAction::Block));
        assert_eq!(base.filters[3].pattern, "PATH");
        assert!(matches!(base.filters[3].action, FilterAction::Allow));

        // Set should be merged, other wins on conflict
        assert_eq!(base.set.get("BASE"), Some(&"overridden".to_string()));
        assert_eq!(base.set.get("OTHER"), Some(&"2".to_string()));
    }

    #[test]
    fn test_env_policy_merge_preserves_base_mode() {
        // If other doesn't set mode, base mode should be preserved
        let mut base: EnvPolicy = toml::from_str(
            r#"
mode = "default_block"
allow = ["PATH"]
"#,
        )
        .unwrap();

        let other: EnvPolicy = toml::from_str(
            r#"
allow = ["HOME"]
"#,
        )
        .unwrap();

        base.merge(&other);

        // Mode should still be default_block (DefaultBlock) from base
        assert!(matches!(base.mode, Some(EnvMode::DefaultBlock)));
        // Filters should be prepended: HOME, PATH
        assert_eq!(base.filters.len(), 2);
        assert_eq!(base.filters[0].pattern, "HOME");
        assert_eq!(base.filters[1].pattern, "PATH");
    }

    #[test]
    fn test_env_policy_parsing() {
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_allow"
block = ["*_TOKEN", "SECRET"]
allow = ["PATH", "HOME"]
set = { CAGE = "1" }
"#,
        )
        .unwrap();

        assert!(matches!(policy.mode, Some(EnvMode::DefaultAllow)));
        assert_eq!(policy.filters.len(), 4);
        // Block patterns come first
        assert_eq!(policy.filters[0].pattern, "*_TOKEN");
        assert!(matches!(policy.filters[0].action, FilterAction::Block));
        assert_eq!(policy.filters[1].pattern, "SECRET");
        assert!(matches!(policy.filters[1].action, FilterAction::Block));
        // Then allow patterns
        assert_eq!(policy.filters[2].pattern, "PATH");
        assert!(matches!(policy.filters[2].action, FilterAction::Allow));
        assert_eq!(policy.filters[3].pattern, "HOME");
        assert!(matches!(policy.filters[3].action, FilterAction::Allow));
        // Set
        assert_eq!(policy.set.get("CAGE"), Some(&"1".to_string()));
    }

    #[test]
    fn test_sandbox_policy_merge() {
        let mut base = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/base")],
            write_restricted_paths: vec![PathBuf::from("/base/.git")],
            read_restricted_paths: vec![PathBuf::from("/secret")],
            network: Some(NetworkPolicy::None),
            env: Some(
                toml::from_str::<EnvPolicy>(
                    r#"
mode = "default_allow"
block = ["OLD"]
"#,
                )
                .unwrap(),
            ),
            enable_gui: None,
            enable_audio: None,
        };

        let other = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/other")],
            write_restricted_paths: vec![PathBuf::from("/other/.env")],
            read_restricted_paths: vec![PathBuf::from("/other/secret")],
            network: Some(NetworkPolicy::Full),
            env: Some(
                toml::from_str::<EnvPolicy>(
                    r#"
mode = "default_block"
allow = ["PATH"]
block = ["NEW"]
set = { KEY = "value" }
"#,
                )
                .unwrap(),
            ),
            enable_gui: None,
            enable_audio: None,
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
        assert!(matches!(env.mode, Some(EnvMode::DefaultBlock)));
        // Filters should be prepended: NEW(block), PATH(allow), OLD(block)
        assert_eq!(env.filters.len(), 3);
        assert_eq!(env.filters[0].pattern, "NEW");
        assert_eq!(env.filters[1].pattern, "PATH");
        assert_eq!(env.filters[2].pattern, "OLD");
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
            enable_gui: None,
            enable_audio: None,
        };

        let other = SandboxPolicy {
            writable_roots: vec![PathBuf::from("/other")],
            write_restricted_paths: vec![],
            read_restricted_paths: vec![],
            network: None, // Not set
            env: None,
            enable_gui: None,
            enable_audio: None,
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
            env: Some(
                toml::from_str::<EnvPolicy>(
                    r#"
mode = "default_allow"
allow = ["PATH"]
"#,
                )
                .unwrap(),
            ),
            enable_gui: None,
            enable_audio: None,
        };

        let other = SandboxPolicy {
            writable_roots: vec![],
            write_restricted_paths: vec![],
            read_restricted_paths: vec![],
            network: Some(NetworkPolicy::None),
            env: Some(
                toml::from_str::<EnvPolicy>(
                    r#"
mode = "default_block"
"#,
                )
                .unwrap(),
            ),
            enable_gui: None,
            enable_audio: None,
        };

        base.merge(&other);

        // Original paths should remain
        assert_eq!(base.writable_roots.len(), 1);
        assert!(base.writable_roots.contains(&PathBuf::from("/base")));

        // Network should still be overridden (explicitly set to None)
        assert!(matches!(base.network, Some(NetworkPolicy::None)));

        // Mode should be overridden to default_block (DefaultBlock)
        let env = base.env.as_ref().unwrap();
        assert!(matches!(env.mode, Some(EnvMode::DefaultBlock)));
    }
}
