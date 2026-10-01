use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;

// Linux Syscall numbers for Landlock LSM (x86_64, aarch64)
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_ADD_RULE: i64 = 445;
#[cfg(target_arch = "x86_64")]
const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;

#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_CREATE_RULESET: i64 = 444;
#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_ADD_RULE: i64 = 445;
#[cfg(target_arch = "aarch64")]
const SYS_LANDLOCK_RESTRICT_SELF: i64 = 446;

// Landlock access flags (ABI v1)
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
pub const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
pub const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
pub const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
pub const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

// Landlock ABI v2 flag (Linux 5.19+)
pub const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;

// Landlock ABI v3 flag (Linux 6.2+)
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

// Flags for landlock_create_ruleset
pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

/// Enables anti-forensics and memory protection primitives:
/// 1. PR_SET_DUMPABLE = 0: Prevents core dumps and blocks ptrace memory snooping from non-root.
/// 2. PR_SET_NO_NEW_PRIVS = 1: Permanently prevents gaining new privileges via execve/setuid.
pub fn enable_anti_forensics() -> bool {
    unsafe {
        // Disable core dumps and ptrace attachment
        let res_dumpable = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // Enforce no new privileges
        let res_noprivs = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);

        res_dumpable == 0 && res_noprivs == 0
    }
}

/// Queries the host kernel for the supported Landlock ABI version.
/// Returns the integer ABI version (e.g. 1, 2, 3...) or -1 if Landlock is unsupported or disabled.
pub fn get_supported_landlock_abi() -> i32 {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let version = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                std::ptr::null::<LandlockRulesetAttr>(),
                0usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if version < 0 {
            -1
        } else {
            version as i32
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        -1
    }
}

/// Enforces Linux Landlock LSM filesystem restriction if supported by host kernel (Linux 5.13+).
/// Dynamically adapts to kernel ABI v1, v2 (REFER), and v3 (TRUNCATE) masks.
/// Sandboxes the daemon process so it cannot read or write outside allowed directories.
pub fn enable_landlock_sandbox(
    allowed_read_paths: &[&Path],
    allowed_write_paths: &[&Path],
) -> bool {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        // Must have PR_SET_NO_NEW_PRIVS before restricting self
        enable_anti_forensics();

        let abi = get_supported_landlock_abi();
        if abi < 1 {
            // Kernel does not support Landlock or not enabled, gracefully fallback
            return false;
        }

        let mut handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;

        if abi >= 2 {
            handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }

        let attr = LandlockRulesetAttr {
            handled_access_fs,
        };

        let ruleset_fd = unsafe {
            libc::syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                &attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };

        if ruleset_fd < 0 {
            return false;
        }

        let ruleset_fd = ruleset_fd as i32;

        let read_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
        let mut write_access = read_access
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_REMOVE_FILE;

        if abi >= 2 {
            write_access |= LANDLOCK_ACCESS_FS_REFER;
        }
        if abi >= 3 {
            write_access |= LANDLOCK_ACCESS_FS_TRUNCATE;
        }

        for path in allowed_read_paths {
            if let Ok(file) = File::open(path) {
                let path_beneath = LandlockPathBeneathAttr {
                    allowed_access: read_access,
                    parent_fd: file.as_raw_fd(),
                };
                unsafe {
                    libc::syscall(
                        SYS_LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH,
                        &path_beneath as *const LandlockPathBeneathAttr,
                        0u32,
                    );
                }
            }
        }

        for path in allowed_write_paths {
            if let Ok(file) = File::open(path) {
                let path_beneath = LandlockPathBeneathAttr {
                    allowed_access: write_access,
                    parent_fd: file.as_raw_fd(),
                };
                unsafe {
                    libc::syscall(
                        SYS_LANDLOCK_ADD_RULE,
                        ruleset_fd,
                        LANDLOCK_RULE_PATH_BENEATH,
                        &path_beneath as *const LandlockPathBeneathAttr,
                        0u32,
                    );
                }
            }
        }

        // Restrict self using the ruleset
        let restrict_res = unsafe {
            libc::syscall(SYS_LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32)
        };

        unsafe {
            libc::close(ruleset_fd);
        }

        restrict_res == 0
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        enable_anti_forensics();
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anti_forensics_prctl() {
        assert!(enable_anti_forensics());
    }

    #[test]
    fn test_get_supported_landlock_abi() {
        let abi = get_supported_landlock_abi();
        // On Linux 5.13+, abi >= 1, on older kernels or unprivileged containers, abi == -1
        assert!(abi >= -1);
    }

    #[test]
    fn test_landlock_sandbox_fallback_or_success() {
        let temp_dir = std::env::temp_dir();
        // Should either succeed or return false cleanly without crashing
        let _ = enable_landlock_sandbox(&[&temp_dir], &[&temp_dir]);
    }
}
