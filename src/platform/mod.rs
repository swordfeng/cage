#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

#[cfg(target_os = "linux")]
pub use linux::run_sandboxed;

#[cfg(target_os = "macos")]
pub use macos::run_sandboxed;

#[cfg(target_os = "windows")]
pub use windows::run_sandboxed;
