//! Zero-copy, encrypted inter-process messaging over POSIX shared memory.
//!
//! - [`shm`]: raw kernel shared memory segments (`shm_open` / `mmap`).
//! - [`ring`]: a lock-free SPSC message ring living inside a segment.
//! - [`crypto`]: AES-256-GCM framing that encrypts messages in place in the ring.

pub mod crypto;
pub mod ring;
pub mod shm;

pub use ring::{Consumer, Grant, Message, Producer};
pub use shm::ShmSegment;

/// Default channel name shared by the writer and reader binaries.
pub const DEFAULT_CHANNEL: &str = "/rustbridge";

/// Default ring size: 4 MiB.
pub const DEFAULT_RING_SIZE: usize = 4 << 20;

/// Default plaintext bytes per message: 256 KiB.
pub const DEFAULT_CHUNK_SIZE: usize = 256 << 10;
