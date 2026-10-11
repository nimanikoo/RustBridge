//! Authenticated, in-place encryption of a message stream (AES-256-GCM).
//!
//! Frame layout: `[flags: u8][nonce: 12][ciphertext][tag: 16]`.
//!
//! The associated data binds every frame to its position in the stream and to the
//! end-of-stream flag, so frames cannot be reordered, replayed, dropped or truncated
//! without the reader noticing.

use std::io;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
/// Bytes in front of the plaintext inside a frame.
pub const PREFIX_LEN: usize = 1 + NONCE_LEN;
/// Total bytes a frame adds on top of the plaintext.
pub const OVERHEAD: usize = PREFIX_LEN + TAG_LEN;

/// Environment variable holding the shared key as 64 hex characters.
pub const KEY_ENV: &str = "RUSTBRIDGE_KEY";

const FLAG_LAST: u8 = 1;

/// Reads the key from [`KEY_ENV`].
pub fn key_from_env() -> io::Result<[u8; KEY_LEN]> {
    let hex = std::env::var(KEY_ENV).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "{KEY_ENV} is not set; generate one with: export {KEY_ENV}=$(openssl rand -hex 32)"
            ),
        )
    })?;
    key_from_hex(&hex)
}

/// Parses a 32-byte key from 64 hex characters.
pub fn key_from_hex(hex: &str) -> io::Result<[u8; KEY_LEN]> {
    let hex = hex.trim().as_bytes();
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("key must be {} hex characters", KEY_LEN * 2),
        )
    };
    if hex.len() != KEY_LEN * 2 {
        return Err(invalid());
    }
    let nibble = |c: u8| {
        (c as char)
            .to_digit(16)
            .map(|d| d as u8)
            .ok_or_else(invalid)
    };
    let mut key = [0u8; KEY_LEN];
    for (byte, pair) in key.iter_mut().zip(hex.as_chunks::<2>().0) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(key)
}

fn aad(seq: u64, flags: u8) -> [u8; 9] {
    let mut aad = [0u8; 9];
    aad[..8].copy_from_slice(&seq.to_le_bytes());
    aad[8] = flags;
    aad
}

fn nonce_for(base: &[u8; NONCE_LEN], seq: u64) -> [u8; NONCE_LEN] {
    let mut nonce = *base;
    for (n, s) in nonce[4..].iter_mut().zip(seq.to_le_bytes()) {
        *n ^= s;
    }
    nonce
}

fn crypto_error(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Encrypting side of a stream.
pub struct Sealer {
    cipher: Aes256Gcm,
    nonce_base: [u8; NONCE_LEN],
    seq: u64,
}

impl Sealer {
    /// Starts a new stream with a random nonce base, so nonces never repeat across runs.
    pub fn new(key: &[u8; KEY_LEN]) -> io::Result<Self> {
        let mut nonce_base = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_base).map_err(io::Error::other)?;
        Ok(Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)),
            nonce_base,
            seq: 0,
        })
    }

    /// Encrypts a frame in place. `frame` must be `[PREFIX_LEN spare][plaintext][TAG_LEN spare]`.
    pub fn seal_in_place(&mut self, frame: &mut [u8], last: bool) -> io::Result<()> {
        if frame.len() < OVERHEAD {
            return Err(crypto_error("frame shorter than encryption overhead"));
        }
        let flags = if last { FLAG_LAST } else { 0 };
        let nonce = nonce_for(&self.nonce_base, self.seq);
        let (prefix, rest) = frame.split_at_mut(PREFIX_LEN);
        let (body, tag_out) = rest.split_at_mut(rest.len() - TAG_LEN);

        let tag = self
            .cipher
            .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad(self.seq, flags), body)
            .map_err(|_| crypto_error("encryption failed"))?;
        prefix[0] = flags;
        prefix[1..].copy_from_slice(&nonce);
        tag_out.copy_from_slice(&tag);
        self.seq += 1;
        Ok(())
    }
}

/// Decrypting side of a stream.
pub struct Opener {
    cipher: Aes256Gcm,
    seq: u64,
}

impl Opener {
    pub fn new(key: &[u8; KEY_LEN]) -> Self {
        Self {
            cipher: Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key)),
            seq: 0,
        }
    }

    /// Verifies and decrypts a frame in place. Returns the plaintext and whether it is the last frame.
    pub fn open_in_place<'a>(&mut self, frame: &'a mut [u8]) -> io::Result<(&'a [u8], bool)> {
        if frame.len() < OVERHEAD {
            return Err(crypto_error("frame shorter than encryption overhead"));
        }
        let (prefix, rest) = frame.split_at_mut(PREFIX_LEN);
        let (body, tag) = rest.split_at_mut(rest.len() - TAG_LEN);
        let flags = prefix[0];

        self.cipher
            .decrypt_in_place_detached(
                Nonce::from_slice(&prefix[1..]),
                &aad(self.seq, flags),
                body,
                Tag::from_slice(tag),
            )
            .map_err(|_| {
                crypto_error(
                    "authentication failed: wrong key, or data was tampered with or reordered",
                )
            })?;
        self.seq += 1;
        Ok((body, flags & FLAG_LAST != 0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];

    fn frame(plaintext: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; plaintext.len() + OVERHEAD];
        f[PREFIX_LEN..PREFIX_LEN + plaintext.len()].copy_from_slice(plaintext);
        f
    }

    #[test]
    fn hex_key_parsing() {
        let key = key_from_hex(&"0f".repeat(32)).unwrap();
        assert_eq!(key, [0x0f; 32]);
        assert!(key_from_hex("abc").is_err());
        assert!(key_from_hex(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn roundtrip() {
        let mut sealer = Sealer::new(&KEY).unwrap();
        let mut opener = Opener::new(&KEY);
        for (i, text) in [&b"hello"[..], b"", b"world"].iter().enumerate() {
            let mut f = frame(text);
            sealer.seal_in_place(&mut f, i == 2).unwrap();
            if !text.is_empty() {
                assert_ne!(&f[PREFIX_LEN..PREFIX_LEN + text.len()], *text);
            }
            let (plain, last) = opener.open_in_place(&mut f).unwrap();
            assert_eq!(plain, *text);
            assert_eq!(last, i == 2);
        }
    }

    #[test]
    fn detects_tampering_wrong_key_and_reordering() {
        let mut sealer = Sealer::new(&KEY).unwrap();
        let mut a = frame(b"first");
        let mut b = frame(b"second");
        sealer.seal_in_place(&mut a, false).unwrap();
        sealer.seal_in_place(&mut b, false).unwrap();

        let mut tampered = a.clone();
        tampered[PREFIX_LEN] ^= 1;
        assert!(Opener::new(&KEY).open_in_place(&mut tampered).is_err());

        let mut flipped_flag = a.clone();
        flipped_flag[0] = FLAG_LAST;
        assert!(Opener::new(&KEY).open_in_place(&mut flipped_flag).is_err());

        assert!(
            Opener::new(&[9; KEY_LEN])
                .open_in_place(&mut a.clone())
                .is_err()
        );
        assert!(
            Opener::new(&KEY).open_in_place(&mut b).is_err(),
            "out-of-order frame accepted"
        );
    }
}
