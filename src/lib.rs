//! This crate provides an implementation of the SHA-2 384 hash function with a straightforward interface for computing digests of bytes, files, directories, and more.
//!
//! For a low-level interface, you can explore the [`chksum_hash_sha2_384`] crate.
//!
//! # Setup
//!
//! To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2-384 = "0.1.0"
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```sh
//! cargo add chksum-sha2-384
//! ```     
//!
//! # Usage
//!
//! Use the [`chksum`] function to calculate digest of file, directory and so on.
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_384::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Asynchronous Runtime
//!
//! Use the [`async_chksum`] function to calculate digest of file, directory and so on.
//!
//! ```rust
//! # #[cfg(feature = "async-runtime-tokio")]
//! # {
//! # use std::path::Path;
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//! use tokio::fs::File;
//!
//! # async fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path).await?;
//! let digest = sha2_384::async_chksum(file).await?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! # }
//! ```
//!
//! # Input Types
//!
//! ## Bytes
//!
//! ### Array
//!
//! ```rust
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper() -> Result<()> {
//! let data = [0, 1, 2, 3];
//! let digest = sha2_384::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### Vec
//!
//! ```rust
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper() -> Result<()> {
//! let data = vec![0, 1, 2, 3];
//! let digest = sha2_384::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### Slice
//!
//! ```rust
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper() -> Result<()> {
//! let data = &[0, 1, 2, 3];
//! let digest = sha2_384::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Strings
//!
//! ### str
//!
//! ```rust
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper() -> Result<()> {
//! let data = "&str";
//! let digest = sha2_384::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ### String
//!
//! ```rust
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper() -> Result<()> {
//! let data = String::from("String");
//! let digest = sha2_384::chksum(data)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## File
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//!
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let digest = sha2_384::chksum(file)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Directory
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::read_dir;
//!
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let readdir = read_dir(path)?;
//! let digest = sha2_384::chksum(readdir)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Path
//!
//! ```rust
//! # use std::path::Path;
//! use std::path::PathBuf;
//!
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let path = PathBuf::from(path);
//! let digest = sha2_384::chksum(path)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! ## Standard Input
//!
//! ```rust
//! use std::io::stdin;
//!
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper() -> Result<()> {
//! let stdin = stdin();
//! let digest = sha2_384::chksum(stdin)?;
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```
//!
//! # Features
//!
//! Cargo features are utilized to enable extra options.
//!
//! * `reader` enables the [`reader`] module with the [`Reader`] struct.
//! * `writer` enables the [`writer`] module with the [`Writer`] struct.
//!
//! By default, neither of these features is enabled.
//!
//! To customize your setup, disable the default features and enable only those that you need in your `Cargo.toml` file:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2-384 = { version = "0.1.0", features = ["reader", "writer"] }
//! ```
//!
//! Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-sha2-384 --features reader,writer
//! ```
//!
//! ## Asynchronous Runtime
//!
//! * `async-runtime-tokio`: Enables async interface for Tokio runtime.
//!
//! By default, neither of these features is enabled.
//!
//! # License
//!
//! This crate is licensed under the MIT License.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![forbid(unsafe_code)]

#[cfg(feature = "reader")]
pub mod reader;
#[cfg(feature = "writer")]
pub mod writer;

use std::fmt::{self, Display, Formatter, LowerHex, UpperHex};

use chksum_core as core;
#[cfg(feature = "async-runtime-tokio")]
#[doc(no_inline)]
pub use chksum_core::AsyncChksumable;
#[doc(no_inline)]
pub use chksum_core::{Chksumable, Error, Hash, Hashable, Result};
#[doc(no_inline)]
pub use chksum_hash_sha2_384 as hash;

#[cfg(all(feature = "reader", feature = "async-runtime-tokio"))]
#[doc(inline)]
pub use crate::reader::AsyncReader;
#[cfg(feature = "reader")]
#[doc(inline)]
pub use crate::reader::Reader;
#[cfg(all(feature = "writer", feature = "async-runtime-tokio"))]
#[doc(inline)]
pub use crate::writer::AsyncWriter;
#[cfg(feature = "writer")]
#[doc(inline)]
pub use crate::writer::Writer;

/// Creates a new hash.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_384 as sha2_384;
///
/// let mut hash = sha2_384::new();
/// hash.update(b"example data");
/// let digest = hash.digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
/// );
/// ```
#[must_use]
pub fn new() -> SHA2_384 {
    SHA2_384::new()
}

/// Creates a default hash.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_384 as sha2_384;
///
/// let mut hash = sha2_384::default();
/// hash.update(b"example data");
/// let digest = hash.digest();
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
/// );
/// ```
#[must_use]
pub fn default() -> SHA2_384 {
    core::default()
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_384 as sha2_384;
///
/// let data = b"example data";
/// let digest = sha2_384::hash(data);
/// assert_eq!(
///     digest.to_hex_lowercase(),
///     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
/// );
/// ```
pub fn hash(data: impl core::Hashable) -> Digest {
    core::hash::<SHA2_384>(data)
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_384 as sha2_384;
///
/// let data = b"example data";
/// if let Ok(digest) = sha2_384::chksum(data) {
///     assert_eq!(
///         digest.to_hex_lowercase(),
///         "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
///     );
/// }
/// ```
pub fn chksum(data: impl core::Chksumable) -> Result<Digest> {
    core::chksum::<SHA2_384>(data)
}

/// Computes the hash of the given input.
///
/// # Example
///
/// ```rust
/// use chksum_sha2_384 as sha2_384;
///
/// # async fn wrapper() {
/// let data = b"example data";
/// if let Ok(digest) = sha2_384::async_chksum(data).await {
///     assert_eq!(
///         digest.to_hex_lowercase(),
///         "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
///     );
/// }
/// # }
/// ```
#[cfg(feature = "async-runtime-tokio")]
pub async fn async_chksum(data: impl core::AsyncChksumable) -> Result<Digest> {
    core::async_chksum::<SHA2_384>(data).await
}

/// The SHA-2 384 hash instance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SHA2_384 {
    inner: hash::Update,
}

impl SHA2_384 {
    /// Calculates the hash digest of an input data.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_384::SHA2_384;
    ///
    /// let data = b"example data";
    /// let digest = SHA2_384::hash(data);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
    /// );
    /// ```
    #[must_use]
    pub fn hash<T>(data: T) -> Digest
    where
        T: AsRef<[u8]>,
    {
        let mut hash = Self::new();
        hash.update(data);
        hash.digest()
    }

    /// Creates a new hash.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_384::SHA2_384;
    ///
    /// let mut hash = SHA2_384::new();
    /// hash.update(b"example data");
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
    /// );
    /// ```
    #[must_use]
    pub fn new() -> Self {
        let inner = hash::Update::new();
        Self { inner }
    }

    /// Updates the hash state with an input data.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_384::SHA2_384;
    ///
    /// let mut hash = SHA2_384::new();
    /// hash.update(b"example");
    /// hash.update(" ");
    /// hash.update("data");
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
    /// );
    /// ```
    pub fn update<T>(&mut self, data: T)
    where
        T: AsRef<[u8]>,
    {
        self.inner.update(data);
    }

    /// Resets the hash state to its initial state.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_384::SHA2_384;
    ///
    /// let mut hash = SHA2_384::new();
    /// hash.update(b"example data");
    /// hash.reset();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    /// );
    /// ```
    pub fn reset(&mut self) {
        self.inner.reset();
    }

    /// Produces the hash digest.
    ///
    /// # Example
    ///
    /// ```
    /// use chksum_sha2_384::SHA2_384;
    ///
    /// let mut hash = SHA2_384::new();
    /// let digest = hash.digest();
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    /// );
    /// ```
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.inner.digest().into()
    }
}

impl core::Hash for SHA2_384 {
    type Digest = Digest;

    fn update<T>(&mut self, data: T)
    where
        T: AsRef<[u8]>,
    {
        self.update(data);
    }

    fn reset(&mut self) {
        self.reset();
    }

    fn digest(&self) -> Self::Digest {
        self.digest()
    }
}

/// A hash digest.
pub struct Digest(hash::Digest);

impl Digest {
    /// Creates a new digest.
    #[must_use]
    pub const fn new(digest: [u8; hash::DIGEST_LENGTH_BYTES]) -> Self {
        let inner = hash::Digest::new(digest);
        Self(inner)
    }

    /// Returns a byte slice of the digest's contents.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8] {
        let Self(inner) = self;
        inner.as_bytes()
    }

    /// Consumes the digest, returning the digest bytes.
    #[must_use]
    pub fn into_inner(self) -> [u8; hash::DIGEST_LENGTH_BYTES] {
        let Self(inner) = self;
        inner.into_inner()
    }

    /// Returns a string in the lowercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_384 as sha2_384;
    ///
    /// let digest = [
    ///     0x38, 0xB0, 0x60, 0xA7,
    ///     0x51, 0xAC, 0x96, 0x38,
    ///     0x4C, 0xD9, 0x32, 0x7E,
    ///     0xB1, 0xB1, 0xE3, 0x6A,
    ///     0x21, 0xFD, 0xB7, 0x11,
    ///     0x14, 0xBE, 0x07, 0x43,
    ///     0x4C, 0x0C, 0xC7, 0xBF,
    ///     0x63, 0xF6, 0xE1, 0xDA,
    ///     0x27, 0x4E, 0xDE, 0xBF,
    ///     0xE7, 0x6F, 0x65, 0xFB,
    ///     0xD5, 0x1A, 0xD2, 0xF1,
    ///     0x48, 0x98, 0xB9, 0x5B,
    /// ];
    /// let digest = sha2_384::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_lowercase(),
    ///     "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_lowercase(&self) -> String {
        let Self(inner) = self;
        inner.to_hex_lowercase()
    }

    /// Returns a string in the uppercase hexadecimal representation.
    ///
    /// # Example
    ///
    /// ```rust
    /// use chksum_sha2_384 as sha2_384;
    ///
    /// let digest = [
    ///     0x38, 0xB0, 0x60, 0xA7,
    ///     0x51, 0xAC, 0x96, 0x38,
    ///     0x4C, 0xD9, 0x32, 0x7E,
    ///     0xB1, 0xB1, 0xE3, 0x6A,
    ///     0x21, 0xFD, 0xB7, 0x11,
    ///     0x14, 0xBE, 0x07, 0x43,
    ///     0x4C, 0x0C, 0xC7, 0xBF,
    ///     0x63, 0xF6, 0xE1, 0xDA,
    ///     0x27, 0x4E, 0xDE, 0xBF,
    ///     0xE7, 0x6F, 0x65, 0xFB,
    ///     0xD5, 0x1A, 0xD2, 0xF1,
    ///     0x48, 0x98, 0xB9, 0x5B,
    /// ];
    /// let digest = sha2_384::Digest::new(digest);
    /// assert_eq!(
    ///     digest.to_hex_uppercase(),
    ///     "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
    /// );
    /// ```
    #[must_use]
    pub fn to_hex_uppercase(&self) -> String {
        let Self(inner) = self;
        inner.to_hex_uppercase()
    }
}

impl core::Digest for Digest {}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        let Self(inner) = self;
        inner.as_bytes()
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(inner) = self;
        Display::fmt(inner, f)
    }
}

impl LowerHex for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(inner) = self;
        LowerHex::fmt(inner, f)
    }
}

impl UpperHex for Digest {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self(inner) = self;
        UpperHex::fmt(inner, f)
    }
}

impl From<[u8; hash::DIGEST_LENGTH_BYTES]> for Digest {
    fn from(digest: [u8; hash::DIGEST_LENGTH_BYTES]) -> Self {
        Self::new(digest)
    }
}

impl From<hash::Digest> for Digest {
    fn from(digest: hash::Digest) -> Self {
        Self(digest)
    }
}
