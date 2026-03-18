//! Seccomp supervisor for localhost networking policy
//!
//! Implements user notification-based seccomp filtering for the `connect()` syscall.
//! This allows fine-grained control over network connections, permitting only:
//! - AF_UNIX (Unix domain sockets)
//! - AF_INET/AF_INET6 to localhost addresses (127.0.0.1, ::1)

use anyhow::{Context, Result};
use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags,
    SockFlag, SockType,
};
use std::io::{IoSlice, IoSliceMut};
use std::os::unix::io::{OwnedFd, RawFd};

/// AUDIT_ARCH values for seccomp (from linux/audit.h)
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000003E; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC00000B7; // AUDIT_ARCH_AARCH64
#[cfg(target_arch = "x86")]
const AUDIT_ARCH: u32 = 0x40000002; // AUDIT_ARCH_I386

/// Seccomp user notification structures (from linux/seccomp.h)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotif {
    pub id: u64,
    pub pid: u32,
    pub flags: u32,
    pub data: SeccompData,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompData {
    pub nr: i32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SeccompNotifResp {
    pub id: u64,
    pub val: i64,
    pub error: i32,
    pub flags: u32,
}

/// Socket address families we care about
pub const AF_UNIX: u16 = 1;
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

/// seccomp_notif_resp flag to continue the syscall in-kernel (Linux >= 5.5)
const SECCOMP_USER_NOTIF_FLAG_CONTINUE: u32 = 1;

// BPF instruction constants (from linux/bpf_common.h and linux/filter.h)
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

// Seccomp return values (from linux/seccomp.h)
const SECCOMP_RET_ALLOW: u32 = 0x7FFF0000;
const SECCOMP_RET_USER_NOTIF: u32 = 0x7FC00000;

macro_rules! bpf_stmt {
    ($code:expr, $k:expr) => {
        libc::sock_filter {
            code: $code,
            jt: 0,
            jf: 0,
            k: $k,
        }
    };
}

macro_rules! bpf_jump {
    ($code:expr, $k:expr, $jt:expr, $jf:expr) => {
        libc::sock_filter {
            code: $code,
            jt: $jt,
            jf: $jf,
            k: $k,
        }
    };
}

pub fn install_seccomp_filter() -> Result<RawFd> {
    let connect_syscall = libc::SYS_connect as u32;

    // BPF program: trap connect() syscall with USER_NOTIF, allow others
    let bpf_instructions: Vec<libc::sock_filter> = vec![
        bpf_stmt!(BPF_LD | BPF_W | BPF_ABS, 4),                       // load arch
        bpf_jump!(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH, 0, 3),      // check arch
        bpf_stmt!(BPF_LD | BPF_W | BPF_ABS, 0),                       // load syscall nr
        bpf_jump!(BPF_JMP | BPF_JEQ | BPF_K, connect_syscall, 0, 1), // check connect
        bpf_stmt!(BPF_RET, SECCOMP_RET_USER_NOTIF),                   // trap connect
        bpf_stmt!(BPF_RET, SECCOMP_RET_ALLOW),                        // allow rest
    ];

    let prog = libc::sock_fprog {
        len: bpf_instructions.len() as u16,
        filter: bpf_instructions.as_ptr() as *mut libc::sock_filter,
    };

    const SECCOMP_SET_MODE_FILTER: u64 = 1;
    const SECCOMP_FILTER_FLAG_NEW_LISTENER: u64 = 1 << 3;

    // PR_SET_NO_NEW_PRIVS is required before installing a seccomp filter as non-root
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(anyhow::anyhow!(
            "prctl(PR_SET_NO_NEW_PRIVS) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let notify_fd = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            SECCOMP_SET_MODE_FILTER,
            SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &prog as *const _ as usize,
        )
    };

    if notify_fd < 0 {
        return Err(anyhow::anyhow!(
            "seccomp syscall failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(notify_fd as RawFd)
}

pub fn send_fd(socket: RawFd, fd_to_send: RawFd) -> Result<()> {
    let dummy_byte = [0u8; 1];
    let iov = [IoSlice::new(&dummy_byte)];
    let fds = [fd_to_send];
    let cmsg = ControlMessage::ScmRights(&fds);

    sendmsg::<()>(socket, &iov, &[cmsg], MsgFlags::empty(), None)
        .context("Failed to send file descriptor")?;

    Ok(())
}

pub fn recv_fd(socket: RawFd) -> Result<RawFd> {
    let mut buf = [0u8; 256];
    let mut iov = [IoSliceMut::new(&mut buf)];
    let mut cmsg_buffer = vec![0u8; 128];

    let msg = recvmsg::<()>(socket, &mut iov, Some(&mut cmsg_buffer), MsgFlags::empty())
        .context("Failed to receive file descriptor")?;

    let cmsg_iter = msg.cmsgs().context("Failed to get control messages")?;
    for cmsg in cmsg_iter {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            if let Some(&fd) = fds.first() {
                return Ok(fd);
            }
        }
    }

    Err(anyhow::anyhow!("No file descriptor received"))
}

pub fn read_seccomp_notification(notify_fd: RawFd) -> Result<SeccompNotif> {
    let mut notif: SeccompNotif = unsafe { std::mem::zeroed() };
    let notif_size = std::mem::size_of::<SeccompNotif>();

    let bytes_read = nix::unistd::read(notify_fd, unsafe {
        std::slice::from_raw_parts_mut(&mut notif as *mut _ as *mut u8, notif_size)
    })
    .context("Failed to read seccomp notification")?;

    if bytes_read != notif_size {
        return Err(anyhow::anyhow!(
            "Read {} bytes for seccomp notification, expected {}",
            bytes_read,
            notif_size
        ));
    }

    Ok(notif)
}

pub fn write_seccomp_response(notify_fd: RawFd, response: &SeccompNotifResp) -> Result<()> {
    use std::os::unix::io::BorrowedFd;
    let resp_size = std::mem::size_of::<SeccompNotifResp>();

    let fd = unsafe { BorrowedFd::borrow_raw(notify_fd) };
    let bytes_written = nix::unistd::write(fd, unsafe {
        std::slice::from_raw_parts(response as *const _ as *const u8, resp_size)
    })
    .context("Failed to write seccomp response")?;

    if bytes_written != resp_size {
        return Err(anyhow::anyhow!(
            "Wrote {} bytes for seccomp response, expected {}",
            bytes_written,
            resp_size
        ));
    }

    Ok(())
}

pub fn read_sockaddr_from_process(pid: u32, addr: u64, addrlen: u64) -> Result<Vec<u8>> {
    let mem_path = format!("/proc/{}/mem", pid);
    let mut file =
        std::fs::File::open(&mem_path).with_context(|| format!("Failed to open {}", mem_path))?;

    let read_len = std::cmp::min(addrlen as usize, 256);
    let mut buf = vec![0u8; read_len];

    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(addr))
        .with_context(|| format!("Failed to seek to address 0x{:x} in process memory", addr))?;

    file.read_exact(&mut buf)
        .with_context(|| format!("Failed to read sockaddr from process {} memory", pid))?;

    Ok(buf)
}

pub fn is_localhost_address(sockaddr: &[u8]) -> bool {
    if sockaddr.len() < 2 {
        return false;
    }

    let family = u16::from_ne_bytes([sockaddr[0], sockaddr[1]]);

    match family {
        AF_INET => {
            // struct sockaddr_in: family(2) + port(2) + addr(4)
            // IP address starts at offset 4; first byte == 127 means 127.x.x.x
            if sockaddr.len() >= 8 {
                return sockaddr[4] == 127;
            }
        }
        AF_INET6 => {
            // struct sockaddr_in6: family(2) + port(2) + flowinfo(4) + addr(16)
            // IPv6 address starts at offset 8; ::1 = 15 zero bytes + 0x01
            const ADDR_START: usize = 8;
            if sockaddr.len() >= ADDR_START + 16 {
                let is_loopback = sockaddr[ADDR_START..ADDR_START + 15]
                    .iter()
                    .all(|&b| b == 0)
                    && sockaddr[ADDR_START + 15] == 1;
                return is_loopback;
            }
        }
        _ => {}
    }

    false
}

pub fn is_unix_socket(sockaddr: &[u8]) -> bool {
    if sockaddr.len() < 2 {
        return false;
    }
    let family = u16::from_ne_bytes([sockaddr[0], sockaddr[1]]);
    family == AF_UNIX
}

pub fn validate_connect(pid: u32, sockaddr_ptr: u64, addrlen: u64) -> bool {
    match read_sockaddr_from_process(pid, sockaddr_ptr, addrlen) {
        Ok(sockaddr) => {
            if is_unix_socket(&sockaddr) {
                return true;
            }
            if is_localhost_address(&sockaddr) {
                return true;
            }
            false
        }
        Err(e) => {
            eprintln!(
                "[cage] Warning: Failed to read sockaddr from process {}: {}",
                pid, e
            );
            false
        }
    }
}

pub fn run_supervisor(notify_fd: RawFd, child_pid: nix::unistd::Pid) -> Result<()> {
    use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
    use std::os::unix::io::BorrowedFd;

    // SAFETY: BorrowedFd::borrow_raw is safe because we're just using it for polling
    let poll_fd = unsafe { PollFd::new(BorrowedFd::borrow_raw(notify_fd), PollFlags::POLLIN) };

    loop {
        match poll(&mut [poll_fd], PollTimeout::from(100u16)) {
            Ok(0) => {
                // Poll timeout — check if child is still alive without reaping
                // (the main thread does the blocking waitpid)
                match nix::sys::signal::kill(child_pid, None) {
                    Ok(_) => continue,  // Process still exists
                    Err(_) => break,    // Process gone
                }
            }
            Ok(_) => match read_seccomp_notification(notify_fd) {
                Ok(notif) => {
                    let allowed =
                        validate_connect(notif.pid, notif.data.args[1], notif.data.args[2]);

                    let response = if allowed {
                        // SECCOMP_USER_NOTIF_FLAG_CONTINUE tells the kernel to
                        // actually execute the syscall (requires error=0, val=0)
                        SeccompNotifResp {
                            id: notif.id,
                            val: 0,
                            error: 0,
                            flags: SECCOMP_USER_NOTIF_FLAG_CONTINUE,
                        }
                    } else {
                        // Deny with negative errno
                        SeccompNotifResp {
                            id: notif.id,
                            val: 0,
                            error: -(libc::ECONNREFUSED as i32),
                            flags: 0,
                        }
                    };

                    if let Err(e) = write_seccomp_response(notify_fd, &response) {
                        eprintln!("[cage] Warning: Failed to write seccomp response: {}", e);
                    }
                }
                Err(e) => {
                    eprintln!("[cage] Warning: Failed to read seccomp notification: {}", e);
                }
            },
            Err(e) => {
                eprintln!("[cage] Error: poll failed: {}", e);
                break;
            }
        }
    }

    let _ = nix::unistd::close(notify_fd);
    Ok(())
}

/// Create a socketpair for parent-child communication
pub fn create_socketpair() -> Result<(OwnedFd, OwnedFd)> {
    socketpair(
        AddressFamily::Unix,
        SockType::SeqPacket,
        None::<nix::sys::socket::SockProtocol>,
        SockFlag::empty(),
    )
    .context("Failed to create socketpair")
}
