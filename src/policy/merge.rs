use crate::policy::types::{EnvMode, EnvPolicy};
use std::collections::HashMap;
use std::path::PathBuf;

pub fn expand_path(template: &str, cwd: &std::path::Path) -> Option<PathBuf> {
    todo!("T1.5: Implement variable expansion for paths")
}

impl EnvPolicy {
    pub fn filter(&self, env: &HashMap<String, String>) -> HashMap<String, String> {
        let mut result = HashMap::new();

        match self.mode() {
            EnvMode::Allowlist => {
                // Only allow vars matching any pattern in self.allow
                for (key, value) in env {
                    if self.allow.iter().any(|pattern| glob_match(pattern, key)) {
                        result.insert(key.clone(), value.clone());
                    }
                }
            }
            EnvMode::Blocklist => {
                // Allow all vars except those matching any pattern in self.block
                for (key, value) in env {
                    if !self.block.iter().any(|pattern| glob_match(pattern, key)) {
                        result.insert(key.clone(), value.clone());
                    }
                }
            }
        }

        // Apply set overrides (always last, overwrites any existing values)
        for (key, value) in &self.set {
            result.insert(key.clone(), value.clone());
        }

        result
    }
}

/// Matches a glob pattern against a name.
/// Supports:
/// - `*` - matches any sequence of characters (including empty)
/// - `?` - matches exactly one character
///
/// Uses a greedy two-pointer algorithm: O(n*m) time, O(1) space.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p = pattern.as_bytes();
    let n = name.as_bytes();
    let (plen, nlen) = (p.len(), n.len());

    let mut pi = 0; // pattern index
    let mut ni = 0; // name index
    let mut star_pi = usize::MAX; // pattern index after last '*'
    let mut star_ni = 0; // name index when last '*' was hit

    while ni < nlen {
        if pi < plen && (p[pi] == b'?' || p[pi] == n[ni]) {
            pi += 1;
            ni += 1;
        } else if pi < plen && p[pi] == b'*' {
            star_pi = pi + 1;
            star_ni = ni;
            pi += 1;
        } else if star_pi != usize::MAX {
            // Backtrack: let the last '*' consume one more character
            star_ni += 1;
            pi = star_pi;
            ni = star_ni;
        } else {
            return false;
        }
    }

    // Consume trailing '*'s in pattern
    while pi < plen && p[pi] == b'*' {
        pi += 1;
    }

    pi == plen
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::types::EnvMode;

    #[test]
    fn test_glob_match_star() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("prefix*", "prefix123"));
        assert!(glob_match("*suffix", "123suffix"));
        assert!(glob_match("*middle*", "abcmiddledef"));
        assert!(!glob_match("prefix*", "different"));
    }

    #[test]
    fn test_glob_match_question() {
        assert!(glob_match("?", "a"));
        assert!(!glob_match("?", ""));
        assert!(!glob_match("?", "ab"));
        assert!(glob_match("a?c", "abc"));
        assert!(glob_match("???", "xyz"));
        assert!(!glob_match("???", "xy"));
    }

    #[test]
    fn test_glob_match_combined() {
        assert!(glob_match("*?", "a"));
        assert!(glob_match("?*", "a"));
        assert!(glob_match("*_*", "MY_TOKEN"));
        assert!(glob_match("AWS_*", "AWS_SECRET_KEY"));
        assert!(!glob_match("AWS_*", "GITHUB_TOKEN"));
        assert!(glob_match("*_TOKEN", "API_TOKEN"));
        assert!(glob_match("*_TOKEN", "MY_SECRET_TOKEN"));
        assert!(!glob_match("*_TOKEN", "TOKEN_VALUE"));
    }

    #[test]
    fn test_glob_match_exact() {
        assert!(glob_match("PATH", "PATH"));
        assert!(!glob_match("PATH", "path")); // case sensitive
        assert!(!glob_match("PATH", "PATH_EXTRA"));
    }

    #[test]
    fn test_env_filter_allowlist() {
        let env: HashMap<String, String> = [
            ("PATH".to_string(), "/bin:/usr/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("SECRET".to_string(), "hidden".to_string()),
        ]
        .into_iter()
        .collect();

        let policy = EnvPolicy {
            mode: Some(EnvMode::Allowlist),
            allow: vec!["PATH".to_string()],
            block: vec![],
            set: HashMap::new(),
        };

        let filtered = policy.filter(&env);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("PATH"));
        assert!(!filtered.contains_key("HOME"));
        assert!(!filtered.contains_key("SECRET"));
    }

    #[test]
    fn test_env_filter_blocklist() {
        let env: HashMap<String, String> = [
            ("PATH".to_string(), "/bin".to_string()),
            ("MY_TOKEN".to_string(), "secret".to_string()),
            ("API_KEY".to_string(), "key".to_string()),
            ("GITHUB_TOKEN".to_string(), "gh_token".to_string()),
        ]
        .into_iter()
        .collect();

        let policy = EnvPolicy {
            mode: Some(EnvMode::Blocklist),
            allow: vec![],
            block: vec!["*_TOKEN".to_string(), "*KEY".to_string()],
            set: HashMap::new(),
        };

        let filtered = policy.filter(&env);
        assert_eq!(filtered.len(), 1);
        assert!(filtered.contains_key("PATH"));
        assert!(!filtered.contains_key("MY_TOKEN"));
        assert!(!filtered.contains_key("API_KEY"));
        assert!(!filtered.contains_key("GITHUB_TOKEN"));
    }

    #[test]
    fn test_env_filter_set_overrides() {
        let env: HashMap<String, String> = [("PATH".to_string(), "/old".to_string())]
            .into_iter()
            .collect();

        let mut set = HashMap::new();
        set.insert("PATH".to_string(), "/new".to_string());
        set.insert("CAGE".to_string(), "1".to_string());

        let policy = EnvPolicy {
            mode: Some(EnvMode::Allowlist),
            allow: vec!["PATH".to_string()],
            block: vec![],
            set,
        };

        let filtered = policy.filter(&env);
        assert_eq!(filtered.get("PATH"), Some(&"/new".to_string()));
        assert_eq!(filtered.get("CAGE"), Some(&"1".to_string()));
    }

    #[test]
    fn test_env_filter_blocklist_with_set() {
        let env: HashMap<String, String> = [
            ("PATH".to_string(), "/bin".to_string()),
            ("SECRET".to_string(), "hidden".to_string()),
        ]
        .into_iter()
        .collect();

        let mut set = HashMap::new();
        set.insert("CAGE".to_string(), "1".to_string());

        let policy = EnvPolicy {
            mode: Some(EnvMode::Blocklist),
            allow: vec![],
            block: vec!["SECRET".to_string()],
            set,
        };

        let filtered = policy.filter(&env);
        assert!(filtered.contains_key("PATH"));
        assert!(!filtered.contains_key("SECRET"));
        assert_eq!(filtered.get("CAGE"), Some(&"1".to_string()));
    }

    #[test]
    fn test_real_world_default_policy() {
        // Simulate the default policy from config/cage.toml
        let env: HashMap<String, String> = [
            ("PATH".to_string(), "/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("MY_API_TOKEN".to_string(), "secret".to_string()),
            ("AWS_ACCESS_KEY".to_string(), "key".to_string()),
            ("GITHUB_TOKEN".to_string(), "gh".to_string()),
            ("USER_PASSWORD".to_string(), "pass".to_string()),
        ]
        .into_iter()
        .collect();

        let mut set = HashMap::new();
        set.insert("CAGE".to_string(), "1".to_string());

        let policy = EnvPolicy {
            mode: Some(EnvMode::Blocklist),
            allow: vec![],
            block: vec![
                "*_TOKEN".to_string(),
                "*_SECRET".to_string(),
                "*_PASSWORD".to_string(),
                "*_API_KEY".to_string(),
                "AWS_*".to_string(),
                "GITHUB_*".to_string(),
            ],
            set,
        };

        let filtered = policy.filter(&env);
        assert!(filtered.contains_key("PATH"));
        assert!(filtered.contains_key("HOME"));
        assert!(!filtered.contains_key("MY_API_TOKEN"));
        assert!(!filtered.contains_key("AWS_ACCESS_KEY"));
        assert!(!filtered.contains_key("GITHUB_TOKEN"));
        assert!(!filtered.contains_key("USER_PASSWORD"));
        assert_eq!(filtered.get("CAGE"), Some(&"1".to_string()));
    }

    #[test]
    fn test_real_world_strict_policy() {
        // Simulate the strict policy from config/cage.toml
        let env: HashMap<String, String> = [
            ("PATH".to_string(), "/bin".to_string()),
            ("HOME".to_string(), "/home/user".to_string()),
            ("SECRET".to_string(), "hidden".to_string()),
        ]
        .into_iter()
        .collect();

        let mut set = HashMap::new();
        set.insert("CAGE".to_string(), "1".to_string());

        let policy = EnvPolicy {
            mode: Some(EnvMode::Allowlist),
            allow: vec!["PATH".to_string()],
            block: vec![],
            set,
        };

        let filtered = policy.filter(&env);
        assert_eq!(filtered.len(), 2); // PATH + CAGE
        assert!(filtered.contains_key("PATH"));
        assert!(!filtered.contains_key("HOME"));
        assert!(!filtered.contains_key("SECRET"));
        assert_eq!(filtered.get("CAGE"), Some(&"1".to_string()));
    }
}
