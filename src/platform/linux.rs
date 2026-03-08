use crate::policy::types::SandboxPolicy;
use std::path::Path;

pub fn run_sandboxed(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> anyhow::Result<i32> {
    todo!("T1.7: Implement Linux bubblewrap launcher")
}
