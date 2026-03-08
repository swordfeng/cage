use crate::policy::types::SandboxPolicy;
use std::path::Path;

pub fn run_sandboxed(
    policy: &SandboxPolicy,
    command: &str,
    args: &[String],
    session_tmpdir: &Path,
) -> anyhow::Result<i32> {
    todo!("T2.4-T2.5: Implement Windows restricted token launcher")
}
