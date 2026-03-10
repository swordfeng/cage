//! Global verbose logging utilities

use std::sync::atomic::{AtomicBool, Ordering};

static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Set the global verbose flag.
/// Call this once at startup with args.verbose || args.dry_run.
pub fn set_verbose(v: bool) {
    VERBOSE.store(v, Ordering::Relaxed);
}

/// Check if verbose mode is enabled.
pub fn is_verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Print a warning message only when verbose mode is enabled.
#[macro_export]
macro_rules! verbose_warn {
    ($($arg:tt)*) => {
        if $crate::log::is_verbose() {
            eprintln!("[cage] warning: {}", format!($($arg)*));
        }
    };
}

/// Print an informational message only when verbose mode is enabled.
#[macro_export]
macro_rules! verbose_info {
    ($($arg:tt)*) => {
        if $crate::log::is_verbose() {
            eprintln!("[cage] {}", format!($($arg)*));
        }
    };
}
