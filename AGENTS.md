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

## Anti-Hallucination Rules

**ALWAYS verify before claiming:**

1. **Read file contents before describing them** - Never assume what a file contains based on its name or your training data. Use `read` tool.

2. **Search before stating patterns exist** - Use `grep` to verify claims about code patterns, API usage, or constant definitions.

3. **Check for duplicates before creating** - Before defining constants, types, or functions, search if they already exist.

4. **Don't invent APIs** - If an API doesn't exist in the codebase, don't use it. Check imports and existing implementations.

5. **Verify variable/field names** - Don't guess struct field names or variable names. Read the actual definitions.

6. **Test assumptions** - If you're about to say "we have X" or "there is Y", verify it first with the appropriate tool.

7. **When unsure, ask** - It's better to ask the user for clarification than to make up an answer.

**Examples of what NOT to do:**
- "We have `allow` and `block` fields in EnvPolicy" (check if these exist first)
- "The constant is defined in main.rs" (check all files first)
- "This function returns X" (read the function implementation)

## Code Deduplication

**IMPORTANT: Never duplicate `include_str!` or similar constants across files.**

Before defining a constant with `include_str!`, `include_bytes!`, or similar macros:
1. Search the codebase: `grep -r "include_str!" src/`
2. If it already exists, import it instead of duplicating
3. Example: Tests should use `crate::config::BUNDLED_CONFIG` rather than defining their own

This prevents embedding the same file multiple times in the binary and ensures single source of truth.

## Questions?

Refer to SPEC.md for detailed technical specifications or ask for clarification on implementation details.
