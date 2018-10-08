// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Utilities for stable cryptographic hashing of data structures.
//!
//! # Example
//!
//! ```
//! extern crate digest_hash;
//! extern crate sha2;
//!
//! use digest_hash::{BigEndian, Hash};
//! use digest_hash::EndianInput;
//! use sha2::{Sha256, Digest};
//!
//! pub struct MyHashStableStruct {
//!     foo: u32,
//!     bar: i16
//! }
//!
//! impl Hash for MyHashStableStruct {
//!     fn hash<H: EndianInput>(&self, digest: &mut H) {
//!         self.foo.hash(digest);
//!         self.bar.hash(digest);
//!     }
//! }
//!
//! fn main() {
//!     let inst = MyHashStableStruct { foo: 0x01020304, bar: 0x0506 };
//!
//!     let mut hasher = BigEndian::<Sha256>::new();
//!     inst.hash(&mut hasher);
//!     let hash = hasher.result();
//!
//!     const EXPECTED: &[u8] =
//!             &[0x71, 0x92, 0x38, 0x5c, 0x3c, 0x06, 0x05, 0xde,
//!               0x55, 0xbb, 0x94, 0x76, 0xce, 0x1d, 0x90, 0x74,
//!               0x81, 0x90, 0xec, 0xb3, 0x2a, 0x8e, 0xed, 0x7f,
//!               0x52, 0x07, 0xb3, 0x0c, 0xf6, 0xa1, 0xfe, 0x89];
//!     assert_eq!(hash.as_ref(), EXPECTED);
//! }
//! ```

pub extern crate byteorder;
pub extern crate digest;

#[macro_use]
mod macros;

mod endian;
mod hash;

pub use endian::{BigEndian, LittleEndian, NetworkEndian};
pub use endian::{Endian, EndianInput};
pub use hash::Hash;

#[path = "opinionated.rs"]
pub mod personality;

#[cfg(test)]
mod testmocks;
