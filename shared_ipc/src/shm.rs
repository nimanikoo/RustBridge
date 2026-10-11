//! POSIX shared memory segments backed directly by the kernel (`shm_open` + `mmap`).
//!
//! Works on macOS and Linux. Unlike a file under `/dev/shm`, nothing touches the
//! filesystem and no `fsync` is ever needed: both processes map the same physical pages.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr::NonNull;

/// macOS limits shared memory names to `PSHMNAMLEN` (31) bytes, including the leading `/`.
pub const MAX_NAME_LEN: usize = 31;

const SHM_MODE: libc::c_uint = 0o600;

/// A mapped POSIX shared memory segment.
///
/// The creating side owns the name and unlinks it on drop. Existing mappings stay valid
/// after the unlink, so a peer that is still attached keeps working.
pub struct ShmSegment {
    ptr: NonNull<u8>,
    len: usize,
    name: CString,
    owner: bool,
}

// SAFETY: the segment is a plain memory region; synchronisation is the caller's job.
unsafe impl Send for ShmSegment {}

impl ShmSegment {
    /// Creates a fresh, zero-filled segment of `len` bytes, replacing any stale one.
    pub fn create(name: &str, len: usize) -> io::Result<Self> {
        let cname = validate_name(name)?;
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "segment size must be non-zero",
            ));
        }
        let off_len = libc::off_t::try_from(len)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "segment size too large"))?;

        unsafe {
            // A crashed previous run may have left the name behind. macOS also refuses to
            // ftruncate an already-sized segment, so always start from a new object.
            libc::shm_unlink(cname.as_ptr());

            let fd = libc::shm_open(
                cname.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_RDWR,
                SHM_MODE,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);

            let mapped = if libc::ftruncate(fd.as_raw_fd(), off_len) == 0 {
                map(&fd, len)
            } else {
                Err(io::Error::last_os_error())
            };
            match mapped {
                Ok(ptr) => Ok(Self {
                    ptr,
                    len,
                    name: cname,
                    owner: true,
                }),
                Err(err) => {
                    libc::shm_unlink(cname.as_ptr());
                    Err(err)
                }
            }
        }
    }

    /// Opens an existing segment. Returns `NotFound` if it does not exist or is not sized yet.
    pub fn open(name: &str) -> io::Result<Self> {
        let cname = validate_name(name)?;
        unsafe {
            let fd = libc::shm_open(cname.as_ptr(), libc::O_RDWR, SHM_MODE);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = OwnedFd::from_raw_fd(fd);

            let mut st: libc::stat = std::mem::zeroed();
            if libc::fstat(fd.as_raw_fd(), &mut st) != 0 {
                return Err(io::Error::last_os_error());
            }
            // The creator may not have called ftruncate yet.
            let len = usize::try_from(st.st_size).unwrap_or(0);
            if len == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "segment exists but is not sized yet",
                ));
            }

            let ptr = map(&fd, len)?;
            Ok(Self {
                ptr,
                len,
                name: cname,
                owner: false,
            })
        }
    }

    pub fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn name(&self) -> &str {
        self.name.to_str().unwrap_or_default()
    }
}

impl Drop for ShmSegment {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast(), self.len);
            if self.owner {
                libc::shm_unlink(self.name.as_ptr());
            }
        }
    }
}

fn validate_name(name: &str) -> io::Result<CString> {
    let valid = name.len() >= 2
        && name.len() <= MAX_NAME_LEN
        && name.starts_with('/')
        && !name[1..].contains('/');
    if !valid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "shared memory name must look like \"/name\" and be at most {MAX_NAME_LEN} bytes: {name:?}"
            ),
        ));
    }
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains a NUL byte"))
}

unsafe fn map(fd: &OwnedFd, len: usize) -> io::Result<NonNull<u8>> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(NonNull::new(ptr.cast()).expect("mmap returned null"))
}
