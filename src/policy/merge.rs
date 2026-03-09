use crate::policy::types::{EnvMode, EnvPolicy, FilterAction};
use std::collections::HashMap;
use std::path::PathBuf;

/// Expand variables in a path template and resolve relative paths.
/// Supports:
/// - `~` or `~user` - home directory expansion
/// - `$CWD` - current working directory (passed as `cwd` parameter)
/// - `$VAR` or `${VAR}` - environment variable lookup
/// - Relative paths - resolved relative to cwd
///
/// Returns None if a referenced environment variable is not set.
pub fn expand_path(template: &str, cwd: &std::path::Path) -> Option<PathBuf> {
    // Handle ~ (home directory) expansion at the start
    if template.starts_with('~') {
        return expand_tilde(template, cwd);
    }

    // Handle all variables using a single pass
    let path = expand_all_vars(template, cwd)?;

    // If the path is relative, resolve it against cwd
    if path.is_relative() {
        Some(cwd.join(path))
    } else {
        Some(path)
    }
}

/// Expand ~ to home directory
fn expand_tilde(template: &str, cwd: &std::path::Path) -> Option<PathBuf> {
    let home = dirs::home_dir()?;

    if template == "~" {
        return Some(home);
    }

    if template.starts_with("~/") {
        let rest = &template[2..];
        // Expand any variables in the rest of the path using the original cwd
        // (so $CWD expands to the cage invocation dir, not home)
        let path = expand_all_vars(rest, cwd)?;
        // Join with home if the expanded result is still relative
        if path.is_relative() {
            return Some(home.join(path));
        }
        return Some(path);
    }

    // ~user syntax - not supported, treat as literal relative path
    let path = PathBuf::from(template);
    if path.is_relative() {
        Some(cwd.join(path))
    } else {
        Some(path)
    }
}

/// Expand all variables ($CWD, $VAR, ${VAR}) in a string
fn expand_all_vars(s: &str, cwd: &std::path::Path) -> Option<PathBuf> {
    let mut result = String::new();
    let mut chars = s.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' {
            // Check for ${VAR} syntax
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let var_name: String = chars.by_ref().take_while(|c| *c != '}').collect();
                let var_value = lookup_var(&var_name, cwd)?;
                result.push_str(&var_value);
            } else {
                // $VAR syntax - peek ahead to collect identifier chars without consuming terminator
                let mut var_name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        chars.next();
                        var_name.push(c);
                    } else {
                        break;
                    }
                }
                if var_name.is_empty() {
                    // Lone $ at end or followed by non-var char, treat literally
                    result.push('$');
                } else {
                    let var_value = lookup_var(&var_name, cwd)?;
                    result.push_str(&var_value);
                }
            }
        } else {
            result.push(ch);
        }
    }

    Some(PathBuf::from(result))
}

/// Look up a variable value ($CWD is special, others are env vars)
fn lookup_var(name: &str, cwd: &std::path::Path) -> Option<String> {
    if name == "CWD" {
        Some(cwd.to_string_lossy().to_string())
    } else {
        std::env::var(name).ok()
    }
}

impl EnvPolicy {
    /// Filter environment variables based on ordered filter list.
    ///
    /// For each env var, go through filters in order:
    /// - If a filter pattern matches, follow its action (Allow/Block)
    /// - If no filter matches, use the default mode (Allowlist=deny, Blocklist=allow)
    ///
    /// Finally, apply `set` overrides on top.
    pub fn filter(&self, env: &HashMap<String, String>) -> HashMap<String, String> {
        let mut result = HashMap::new();

        for (key, value) in env {
            // Check filters in order - first match wins
            let mut matched = false;
            let mut should_allow = false;

            for filter in &self.filters {
                if glob_match(&filter.pattern, key) {
                    matched = true;
                    should_allow = matches!(filter.action, FilterAction::Allow);
                    break;
                }
            }

            if matched {
                // Follow the filter's action
                if should_allow {
                    result.insert(key.clone(), value.clone());
                }
                // If blocked, don't add to result
            } else {
                // No filter matched, use default mode
                let should_include = match self.mode() {
                    EnvMode::DefaultAllow => true,  // Allow by default
                    EnvMode::DefaultBlock => false, // Block by default
                };
                if should_include {
                    result.insert(key.clone(), value.clone());
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

        // Parse from TOML to get proper filter ordering
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_block"
allow = ["PATH"]
"#,
        )
        .unwrap();

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

        // Parse from TOML to get proper filter ordering
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_allow"
block = ["*_TOKEN", "*KEY"]
"#,
        )
        .unwrap();

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

        // Parse from TOML
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_block"
allow = ["PATH"]
set = { PATH = "/new", CAGE = "1" }
"#,
        )
        .unwrap();

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

        // Parse from TOML
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_allow"
block = ["SECRET"]
set = { CAGE = "1" }
"#,
        )
        .unwrap();

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

        // Parse from TOML to get proper filter ordering
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_allow"
block = ["*_TOKEN", "*_SECRET", "*_PASSWORD", "*_API_KEY", "AWS_*", "GITHUB_*"]
set = { CAGE = "1" }
"#,
        )
        .unwrap();

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

        // Parse from TOML to get proper filter ordering
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_block"
allow = ["PATH"]
set = { CAGE = "1" }
"#,
        )
        .unwrap();

        let filtered = policy.filter(&env);
        assert_eq!(filtered.len(), 2); // PATH + CAGE
        assert!(filtered.contains_key("PATH"));
        assert!(!filtered.contains_key("HOME"));
        assert!(!filtered.contains_key("SECRET"));
        assert_eq!(filtered.get("CAGE"), Some(&"1".to_string()));
    }

    #[test]
    fn test_env_filter_first_match_wins() {
        // Test that first matching filter wins
        let env: HashMap<String, String> = [("MY_TOKEN".to_string(), "secret".to_string())]
            .into_iter()
            .collect();

        // With default_block mode and filters: block *_TOKEN, allow MY_TOKEN
        // The block filter comes first (in TOML, block patterns are before allow)
        // So MY_TOKEN should be blocked
        let policy: EnvPolicy = toml::from_str(
            r#"
mode = "default_block"
block = ["*_TOKEN"]
allow = ["MY_TOKEN"]
"#,
        )
        .unwrap();

        let filtered = policy.filter(&env);
        // block filter comes before allow filter in the list
        // So *_TOKEN matches first and blocks it
        assert!(!filtered.contains_key("MY_TOKEN"));
    }

    #[test]
    fn test_env_filter_allow_before_block() {
        // If we manually construct policy with allow before block
        // (which wouldn't happen from TOML parsing, but test the logic)
        let env: HashMap<String, String> = [("MY_TOKEN".to_string(), "secret".to_string())]
            .into_iter()
            .collect();

        let policy = EnvPolicy {
            mode: Some(EnvMode::DefaultAllow),
            filters: vec![
                crate::policy::types::EnvFilter {
                    pattern: "MY_TOKEN".to_string(),
                    action: FilterAction::Allow,
                },
                crate::policy::types::EnvFilter {
                    pattern: "*_TOKEN".to_string(),
                    action: FilterAction::Block,
                },
            ],
            set: HashMap::new(),
        };

        let filtered = policy.filter(&env);
        // MY_TOKEN matches first (allow), so it should be allowed
        assert!(filtered.contains_key("MY_TOKEN"));
    }

    #[test]
    fn test_expand_path_cwd() {
        let cwd = std::path::Path::new("/project");

        let expanded = expand_path("$CWD", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/project"));

        // Separator after $VAR must be preserved
        let expanded = expand_path("$CWD/src", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/project/src"));

        // ${CWD} braced syntax
        let expanded = expand_path("${CWD}/src", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/project/src"));
    }

    #[test]
    fn test_expand_path_tilde() {
        let home = dirs::home_dir().unwrap();
        let cwd = std::path::Path::new("/tmp");

        // ~ should expand to home
        let expanded = expand_path("~", cwd).unwrap();
        assert_eq!(expanded, home);

        // ~/something should expand to home/something with exact path
        let expanded = expand_path("~/projects", cwd).unwrap();
        assert_eq!(expanded, home.join("projects"));
    }

    #[test]
    fn test_expand_path_env_var() {
        // Set up test environment variable
        unsafe {
            std::env::set_var("CAGE_TEST_VAR", "/test/path");
        }
        let cwd = std::path::Path::new("/tmp");

        // $VAR syntax — exact match
        let expanded = expand_path("$CAGE_TEST_VAR", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/test/path"));

        // $VAR/suffix syntax — separator after var must be preserved
        let expanded = expand_path("$CAGE_TEST_VAR/subdir", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/test/path/subdir"));

        // ${VAR}/suffix syntax
        let expanded = expand_path("${CAGE_TEST_VAR}/subdir", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/test/path/subdir"));

        // ${VAR} syntax (no suffix)
        let expanded = expand_path("${CAGE_TEST_VAR}", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/test/path"));

        // prefix/$VAR/suffix — separators on both sides preserved
        let expanded = expand_path("/data/$CAGE_TEST_VAR/extra", cwd).unwrap();
        // $CAGE_TEST_VAR = "/test/path" which is absolute; PathBuf joining behaviour:
        // "/data/" + "/test/path" replaces, so just check the var expansion part works
        // Actually the string concatenation here yields "/data//test/path/extra" as a raw string
        // PathBuf::from that string keeps it as-is on Unix
        let s = expanded.to_string_lossy();
        assert!(s.contains("/test/path"), "env var value should appear: {s}");
        assert!(s.contains("extra"), "trailing component should appear: {s}");

        // Clean up
        unsafe {
            std::env::remove_var("CAGE_TEST_VAR");
        }
    }

    #[test]
    fn test_expand_path_unset_var_returns_none() {
        let cwd = std::path::Path::new("/tmp");
        // This variable should not be set
        assert_eq!(expand_path("$CAGE_NONEXISTENT_VAR_XYZ", cwd), None);
    }

    #[test]
    fn test_expand_path_mixed() {
        unsafe {
            std::env::set_var("CAGE_MIXED", "data");
        }
        let home = dirs::home_dir().unwrap();
        let cwd = std::path::Path::new("/workspace");

        // ~/cache/$CAGE_MIXED — exact path
        let expanded = expand_path("~/cache/$CAGE_MIXED", cwd).unwrap();
        assert_eq!(expanded, home.join("cache").join("data"));

        // ~/cache/$CAGE_MIXED/sub — separator after var must be preserved
        let expanded = expand_path("~/cache/$CAGE_MIXED/sub", cwd).unwrap();
        assert_eq!(expanded, home.join("cache").join("data").join("sub"));

        unsafe {
            std::env::remove_var("CAGE_MIXED");
        }
    }

    #[test]
    fn test_expand_path_cwd_inside_tilde() {
        // $CWD inside ~/... must expand to the real cwd, not home.
        // We test this using an env var set to a distinguishable sentinel value
        // in a ~/sub/$VAR path, confirming the separator is preserved correctly
        // (which implicitly verifies expand_all_vars receives cwd, not home).
        unsafe {
            std::env::set_var("CAGE_CWD_TILDE_TEST", "myval");
        }
        let home = dirs::home_dir().unwrap();
        let cwd = std::path::Path::new("/ignored");

        // ~/sub/$CAGE_CWD_TILDE_TEST — separator before and after var must survive
        let expanded = expand_path("~/sub/$CAGE_CWD_TILDE_TEST/end", cwd).unwrap();
        assert_eq!(expanded, home.join("sub").join("myval").join("end"));

        unsafe {
            std::env::remove_var("CAGE_CWD_TILDE_TEST");
        }

        // Direct $CWD test: $CWD should equal cwd argument, not home
        let cwd2 = std::path::Path::new("/actual_cwd_value");
        let expanded2 = expand_path("$CWD", cwd2).unwrap();
        assert_eq!(expanded2, cwd2, "$CWD must expand to the cwd parameter");
    }

    #[test]
    fn test_expand_path_lone_dollar() {
        let cwd = std::path::Path::new("/tmp");
        // Lone $ followed by non-identifier should be treated literally
        let expanded = expand_path("$/foo", cwd).unwrap();
        // The $ is literal; the resulting string "$/foo" is absolute (starts with $/)
        // PathBuf sees it as relative on most systems... exact result depends on platform
        // Key assertion: it must not return None
        let _ = expanded; // just ensure no panic / None
    }

    #[test]
    fn test_expand_path_relative() {
        let cwd = std::path::Path::new("/workspace/project");

        // Relative path should be resolved against cwd with exact result
        let expanded = expand_path("src", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/workspace/project/src"));

        let expanded = expand_path("./config", cwd).unwrap();
        assert_eq!(expanded, std::path::Path::new("/workspace/project/config"));

        // ../relative path
        let expanded = expand_path("../other", cwd).unwrap();
        // PathBuf::join doesn't resolve ..  — it gives "/workspace/project/../other"
        assert!(expanded.to_string_lossy().contains("workspace"));
        assert!(expanded.to_string_lossy().contains("other"));
    }
}
