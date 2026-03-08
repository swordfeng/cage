use crate::policy::types::{EnvPolicy, SandboxPolicy};
use std::collections::HashMap;
use std::path::PathBuf;

pub fn expand_path(template: &str, cwd: &std::path::Path) -> Option<PathBuf> {
    todo!("T1.5: Implement variable expansion for paths")
}

impl EnvPolicy {
    pub fn filter(&self, env: &HashMap<String, String>) -> HashMap<String, String> {
        todo!("T1.3: Implement environment filtering with glob matching")
    }
}

pub fn glob_match(pattern: &str, name: &str) -> bool {
    todo!("T1.3: Implement glob pattern matching with * and ? support")
}
