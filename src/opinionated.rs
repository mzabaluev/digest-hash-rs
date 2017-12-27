// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Helper functions for hashing data in a specific representation.
//!
//! The `Hash` trait implementations provided by this crate do not cover
//! machine-dependent data types, or types for which data representation
//! for calculating a digest is subject to implementer's choice.
//! This module defines helper functions that provide an explicit,
//! auditable way to select some commonly used representation choices.
//!
//! # Examples
//!
//! The recommended way to use the hash personality helper functions is to
//! list them in `use` statements at the beginning of the module that provides
//! `Hash` implementations using the functions. For convenience, the functions
//! can be given short local names.
//!
//! ```
//! use digest_hash::personality::hash_bool_as_byte             as hash_bool;
//! use digest_hash::personality::hash_ip_addr_in_network_order as hash_ip_addr;
//! use digest_hash::{Hash, EndianInput};
//! use std::net::IpAddr;
//!
//! pub struct A {
//!     addr: IpAddr,
//!     foo: bool
//! }
//!
//! impl Hash for A {
//!     fn hash<H>(&self, digest: &mut H)
//!     where H: EndianInput {
//!         hash_ip_addr(self.addr, digest);
//!         hash_bool(self.foo, digest);
//!     }
//! }
//! ```

use super::{EndianInput, Hash};
use digest;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


/// Feeds a boolean value as a byte to the digest function.
///
/// `false` is represented with byte 0, `true` is represented with byte 1.
pub fn hash_bool_as_byte<H: digest::Input>(input: bool, digest: &mut H) {
    digest.process(&[input as u8]);
}

/// Feeds a Unicode character, encoded in UTF-8,
/// to the digest function.
pub fn hash_char_as_utf8<H: digest::Input>(input: char, digest: &mut H) {
    let mut buf = [0u8; 4];
    let encoded = input.encode_utf8(&mut buf);
    digest.process(encoded.as_bytes());
}

/// Feeds a Unicode character, encoded in UTF-16, to the digest function.
///
/// The UTF-16 code units are hashed in the byte order selected by the
/// `EndianInput` implementation.
pub fn hash_char_as_utf16<H: EndianInput>(input: char, digest: &mut H) {
    let mut buf = [0u16; 2];
    let encoded = input.encode_utf16(&mut buf);
    digest.process_u16(encoded[0]);
    if encoded.len() > 1 {
        digest.process_u16(encoded[1]);
    }
}

/// Feeds a Unicode character, encoded in UTF-32, to the digest function.
///
/// The UTF-32 representation is synonymous to UCS-4.
/// The UTF-32 code units are hashed in the byte order selected by the
/// `EndianInput` implementation.
pub fn hash_char_as_utf32<H: EndianInput>(input: char, digest: &mut H) {
    digest.process_u32(input as u32);
}

/// Encodes a string in UTF-16 and feeds it to the digest function.
///
/// The UTF-16 code units are hashed in the byte order selected by the
/// `EndianInput` implementation.
pub fn hash_str_as_utf16<S, H>(input: S, digest: &mut H)
where S: AsRef<str>, H: EndianInput {
    hash_str_as_utf16_impl(input.as_ref(), digest)
}

/// Encodes a string in UTF-16, prepended with a Byte Order Mark (U+FEFF)
/// code point, and feeds it to the digest function.
///
/// The UTF-16 code units are hashed in the byte order selected by the
/// `EndianInput` implementation.
pub fn hash_str_as_utf16_with_bom<S, H>(input: S, digest: &mut H)
where S: AsRef<str>, H: EndianInput {
    digest.process_u16(0xFEFF);
    hash_str_as_utf16_impl(input.as_ref(), digest)
}

fn hash_str_as_utf16_impl<H>(input: &str, digest: &mut H)
where H: EndianInput {
    input.encode_utf16().for_each(|c| {
        digest.process_u16(c);
    });
}

/// Feeds an IP address in the network byte order to the digest function.
pub fn hash_ip_addr_in_network_order<H>(
    addr: IpAddr,
    digest: &mut H
) where H: digest::Input {
    match addr {
        IpAddr::V4(v4addr) => hash_ipv4_addr_in_network_order(v4addr, digest),
        IpAddr::V6(v6addr) => hash_ipv6_addr_in_network_order(v6addr, digest)
    }
}

/// Feeds an IPv4 address in the network byte order to the digest function.
pub fn hash_ipv4_addr_in_network_order<H>(
    addr: Ipv4Addr,
    digest: &mut H
) where H: digest::Input {
    digest.process(&addr.octets());
}

/// Feeds an IPv6 address in the network byte order to the digest function.
pub fn hash_ipv6_addr_in_network_order<H>(
    addr: Ipv6Addr,
    digest: &mut H
) where H: digest::Input {
    digest.process(&addr.octets());
}

/// Computes the digest over a slice by feeding the slice's elements in the
/// direct order to the digest function.
///
/// The slice, and the container it was obtained from, is thus made
/// transparent to hashing. The implementer should take protection against
/// potential second-preimage attacks by making sure that the digest for a
/// compound data structure containing hashed slices is computed
/// unambiguously from components' data.
pub fn hash_slice_as_elements<T, H>(
    slice: &[T],
    digest: &mut H
) where T: Hash, H: EndianInput {
    for elem in slice {
        elem.hash(digest);
    }
}

#[cfg(test)]
mod tests {
    use super::hash_slice_as_elements as hash_slice;

    use BigEndian;
    use testmocks::{MockDigest, Hashable};

    #[test]
    fn u8_slice_hash() {
        const TEST_DATA: &[u8] = &[b'A', b'B', b'C'];
        let mut hasher = BigEndian::<MockDigest>::new();
        hash_slice(TEST_DATA, &mut hasher);
        let output = hasher.into_inner().bytes;
        assert_eq!(output, TEST_DATA);
    }

    #[test]
    fn i8_slice_hash() {
        const TEST_DATA: &[i8] = &[-128, -127, -126];
        let mut hasher = BigEndian::<MockDigest>::new();
        hash_slice(TEST_DATA, &mut hasher);
        let output = hasher.into_inner().bytes;
        let expected: Vec<_> = TEST_DATA.iter()
                                        .map(|c| { *c as u8 })
                                        .collect();
        assert_eq!(output, expected);
    }

    #[test]
    fn u8_vec_hash() {
        let test_vec = vec![b'A', b'B', b'C'];
        let mut hasher = BigEndian::<MockDigest>::new();
        hash_slice(test_vec.as_slice(), &mut hasher);
        let output = hasher.into_inner().bytes;
        assert_eq!(output, test_vec);
    }

    #[test]
    fn i8_vec_hash() {
        let test_vec = vec![-128i8, -127i8, -126i8];
        let mut hasher = BigEndian::<MockDigest>::new();
        hash_slice(test_vec.as_slice(), &mut hasher);
        let output = hasher.into_inner().bytes;
        let expected: Vec<_> = test_vec.iter()
                                        .map(|c| { *c as u8 })
                                        .collect();
        assert_eq!(output, expected);
    }

    #[test]
    fn str_hash() {
        const TEST_DATA: &str = "Hello";
        let mut hasher = BigEndian::<MockDigest>::new();
        hash_slice(TEST_DATA.as_bytes(), &mut hasher);
        let output = hasher.into_inner().bytes;
        assert_eq!(output, TEST_DATA.as_bytes());
    }

    #[test]
    fn string_hash() {
        let test_str = String::from("Hello");
        let mut hasher = BigEndian::<MockDigest>::new();
        hash_slice(test_str.as_bytes(), &mut hasher);
        let output = hasher.into_inner().bytes;
        assert_eq!(output, test_str.as_bytes());
    }

    #[test]
    fn custom_slice_hash() {
        let a = [
            Hashable { foo: 0x0102, bar: 0x03040506 },
            Hashable { foo: 0x0708, bar: 0x0A0B0C0D },
        ];
        let mut hasher = BigEndian::<MockDigest>::new();
        hash_slice(&a[..], &mut hasher);
        let output = hasher.into_inner().bytes;
        assert_eq!(output,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
             0x07, 0x08, 0x0A, 0x0B, 0x0C, 0x0D]);
    }
}
