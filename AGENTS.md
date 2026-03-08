# Agent Task Execution Guide

This document provides guidance for AI agents working on the `cage` project.

## Task Workflow

1. **Read TASK.md first** - Understand the current state and what tasks need to be done
2. **Check git status** - See what files have been modified
3. **Review SPEC.md** - Understand the technical requirements for the task
4. **Implement the task** - Write code following existing patterns
5. **Update TASK.md** - Mark the task as complete with `[x]`
6. **Commit changes** - Use descriptive commit messages referencing the task ID

## Commit Message Format

```
feat: add T1.X - brief description

- Detail 1
- Detail 2
```

## Task Priority Order

### Phase 1a - Core Platforms (Current)
- T1.1 ✓ Project scaffold
- T1.2 CLI argument parsing
- T1.3 Policy types
- T1.4 Config loading and merge
- T1.5 Variable expansion
- T1.6 Session temp dir
- T1.7 Linux: bubblewrap launcher
- T1.8 macOS: Seatbelt launcher
- T1.9 ✗ MCP socket passthrough (deferred to Phase 2)
- T1.10 --dry-run and -v output
- T1.11 Integration tests

### Phase 1b - Windows + Localhost Network
- T2.1-T2.7 Windows implementation

### Phase 2 - Enhanced Features
- T3.1-T3.3 Policy composition, validation, audit log

## Code Style

- Follow existing Rust conventions in the codebase
- Use `anyhow` for error handling
- Use `todo!("T1.X: description")` for unimplemented placeholders
- Add module-level documentation for public modules
- Keep functions focused and under 50 lines when possible

## Testing

Before committing:
1. Run `cargo check` to ensure code compiles
2. Run `cargo clippy` to catch common issues
3. Run `cargo test` if tests exist
4. For Windows: ensure `windows` crate features are correct
5. For Linux: ensure `seccompiler` is only used in Linux-specific modules

## Platform-Specific Code

- Use `#[cfg(target_os = "...")]` for platform-specific implementations
- Place platform code in `src/platform/{linux,macos,windows}.rs`
- Re-export via `src/platform/mod.rs` using conditional compilation
- Keep common interfaces identical across platforms

## Configuration

- Bundled config: `config/cage.toml` (embedded at compile time)
- User config: `~/.config/cage/cage.toml`
- Project config: `.cage.toml` (walks up from `$CWD`)
- Config merging order: bundled → user → project → CLI flags

## Dependencies

Check `Cargo.toml` before adding new dependencies. Prefer:
- Standard library when possible
- Existing dependencies in the project
- Well-maintained crates with good documentation

## Questions?

Refer to SPEC.md for detailed technical specifications or ask for clarification on implementation details.
