//! This module is optional and can be enabled using the `reader` Cargo feature.
//!
//! The [`Reader`] allows on-the-fly calculation of the digest while reading the data.
//!
//! # Enabling
//!
//! Add the following entry to your `Cargo.toml` file to enable the `reader` feature:
//!
//! ```toml
//! [dependencies]
//! chksum-sha2-384 = { version = "0.1.0", features = ["reader"] }
//! ```
//!
//! Alternatively, use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:
//!
//! ```shell
//! cargo add chksum-sha2-384 --features reader
//! ```
//!
//! # Example
//!
//! ```rust
//! # use std::path::Path;
//! use std::fs::File;
//! use std::io::Read; // required by reader
//!
//! # use chksum_sha2_384::Result;
//! use chksum_sha2_384 as sha2_384;
//!
//! # fn wrapper(path: &Path) -> Result<()> {
//! let file = File::open(path)?;
//! let mut reader = sha2_384::reader::new(file);
//!
//! let mut buffer = Vec::new();
//! reader.read_to_end(&mut buffer)?;
//! assert_eq!(buffer, b"example data");
//!
//! let digest = reader.digest();
//! assert_eq!(
//!     digest.to_hex_lowercase(),
//!     "12ecdfd463a85a301b7c29a43bf4b19cdfc6e5e86a5f40396aa6ae3368a7e5b0ed31f3bef2eb3071577ba610b4ed1cb8"
//! );
//! # Ok(())
//! # }
//! ```

use std::io::Read;

use chksum_reader as reader;
#[cfg(feature = "async-runtime-tokio")]
use tokio::io::AsyncRead;

use crate::SHA2_384;

/// A specialized [`Reader`](reader::Reader) type with the [`SHA2_384`] hash algorithm.
pub type Reader<R> = reader::Reader<R, SHA2_384>;

#[cfg(feature = "async-runtime-tokio")]
/// A specialized [`AsyncReader`](reader::AsyncReader) type with the [`SHA2_384`] hash algorithm.
pub type AsyncReader<R> = reader::AsyncReader<R, SHA2_384>;

/// Creates new [`Reader`].
pub fn new(inner: impl Read) -> Reader<impl Read> {
    reader::new(inner)
}

/// Creates new [`Reader`] with provided hash.
pub fn with_hash(inner: impl Read, hash: SHA2_384) -> Reader<impl Read> {
    reader::with_hash(inner, hash)
}

#[cfg(feature = "async-runtime-tokio")]
/// Creates new [`AsyncReader`].
pub fn async_new(inner: impl AsyncRead) -> AsyncReader<impl AsyncRead> {
    reader::async_new(inner)
}

#[cfg(feature = "async-runtime-tokio")]
/// Creates new [`AsyncReader`] with provided hash.
pub fn async_with_hash(inner: impl AsyncRead, hash: SHA2_384) -> AsyncReader<impl AsyncRead> {
    reader::async_with_hash(inner, hash)
}
