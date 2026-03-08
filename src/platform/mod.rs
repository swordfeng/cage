pub mod linux;
pub mod macos;
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::run_sandboxed;

#[cfg(target_os = "macos")]
pub use macos::run_sandboxed;

#[cfg(target_os = "windows")]
pub use windows::run_sandboxed;
