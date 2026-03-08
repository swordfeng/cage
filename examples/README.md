# Cage Permission Test Program

This program tests whether the cage sandbox is correctly enforcing the default policy permissions. It is designed to be run **inside** the cage sandbox.

## Default Policy Being Tested

```toml
[policies.default]
writable_roots = ["$CWD"]
write_restricted_paths = ["$CWD/.git", "$CWD/.env"]
read_restricted_paths = ["~/.ssh", "~/.aws", "~/.gnupg"]
```

## Important Note on `read_restricted_paths`

**Behavior:** `read_restricted_paths` blocks reading file *content*, not directory listing.

This means:
- You **can** list the contents of `~/.ssh` (see that `id_rsa` exists)
- You **cannot** read the content of `~/.ssh/id_rsa`

This is consistent across platforms because:
- **Linux (bubblewrap):** Can choose to hide paths entirely or make them inaccessible
- **macOS (Seatbelt):** `(deny file-read*)` blocks reading file content, but `(allow default)` allows directory listing
- **Windows (ACLs):** Can set deny ACEs on read data but allow read attributes/listing

## Test Coverage

The program tests the following permissions:

### Writable Paths (`writable_roots`)
| Path | List | Read Content | Write | Notes |
|------|------|--------------|-------|-------|
| `$CWD` | ✓ | ✓ | ✓ | Fully writable |

### Write-Restricted Paths (`write_restricted_paths`)
| Path | List | Read Content | Write | Notes |
|------|------|--------------|-------|-------|
| `$CWD/.git` | ✓ | ✓ | ✗ | Read-only overlay |
| `$CWD/.env` | ✓ | ✓ | ✗ | Read-only if exists |

### Read-Restricted Paths (`read_restricted_paths`)
| Path | List | Read Content | Write | Notes |
|------|------|--------------|-------|-------|
| `~/.ssh` | ? | ✗ | ✗ | Listing: either OK, Reading files: blocked |
| `~/.aws` | ? | ✗ | ✗ | Listing: either OK, Reading files: blocked |
| `~/.gnupg` | ? | ✗ | ✗ | Listing: either OK, Reading files: blocked |

**Note:** `?` means either allowed or denied is acceptable. The sandbox may or may not allow directory listing for read-restricted paths - we accept both outcomes. The important restriction is that file content reading must be blocked.

### System Paths (Base read-only mount)
| Path | List | Read Content | Write | Notes |
|------|------|--------------|-------|-------|
| `/etc/hosts` | N/A | ✓ | ✗ | System file, read-only |
| `/tmp` | ✓ | ✓ | ✓ | Temp directory, writable |
| `~` | ✓ | ✓ | ✗ | Home readable, not writable |
| `/bin` or `C:\Windows` | ✓ | ✓ | ✗ | System, read-only |

## Platform Support

### Linux
```bash
cd examples
rustc --edition 2021 test_permissions.rs -o test_permissions
../target/release/cage ./test_permissions
```

### macOS
```bash
cd examples
rustc --edition 2021 test_permissions.rs -o test_permissions
cage ./test_permissions
```

### Windows
```cmd
cd examples
rustc --edition 2021 test_permissions.rs -o test_permissions.exe
cage test_permissions.exe
```

## Expected Output

When running inside the cage sandbox, all tests should pass:

```
============================================================
CAGE SANDBOX PERMISSION TEST (Rust)
Platform: Linux
============================================================
...
============================================================
SUMMARY
============================================================
Tests passed: 10/10

✓ All tests passed!
```

When running **outside** the sandbox (without cage), most tests will fail because the OS doesn't enforce the restrictions.

## Non-Destructive Testing

The program uses non-destructive testing methods:
- **Read tests**: Try to open and read files/directories without modifying them
- **Write tests**: Create temporary test files (named `.cage_test_<PID>`) and immediately delete them
- **No permanent changes**: All test files are cleaned up immediately after the test
- **Directory listing**: Lists directory contents but doesn't modify anything
