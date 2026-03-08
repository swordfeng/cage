use crate::policy::types::{EnvMode, EnvPolicy};
use std::collections::HashMap;
use std::path::PathBuf;

pub fn expand_path(template: &str, cwd: &std::path::Path) -> Option<PathBuf> {
    todo!("T1.5: Implement variable expansion for paths")
}

impl EnvPolicy {
    pub fn filter(&self, env: &HashMap<String, String>) -> HashMap<String, String> {
        let mut result = HashMap::new();

        match self.mode {
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
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let name_chars: Vec<char> = name.chars().collect();
    let p_len = pattern_chars.len();
    let n_len = name_chars.len();

    // dp[i][j] = true if pattern[0..i] matches name[0..j]
    let mut dp = vec![vec![false; n_len + 1]; p_len + 1];
    dp[0][0] = true;

    // Handle patterns like "*", "**", "*?" at the start
    for i in 1..=p_len {
        if pattern_chars[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=p_len {
        for j in 1..=n_len {
            match pattern_chars[i - 1] {
                '*' => {
                    // * can match empty (dp[i-1][j]) or consume one char (dp[i][j-1])
                    dp[i][j] = dp[i - 1][j] || dp[i][j - 1];
                }
                '?' => {
                    // ? matches exactly one character
                    dp[i][j] = dp[i - 1][j - 1];
                }
                c => {
                    // Exact character match
                    dp[i][j] = dp[i - 1][j - 1] && c == name_chars[j - 1];
                }
            }
        }
    }

    dp[p_len][n_len]
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
            mode: EnvMode::Allowlist,
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
            mode: EnvMode::Blocklist,
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
            mode: EnvMode::Allowlist,
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
            mode: EnvMode::Blocklist,
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
            mode: EnvMode::Blocklist,
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
            mode: EnvMode::Allowlist,
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
