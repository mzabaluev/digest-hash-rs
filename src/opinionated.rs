// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use super::{EndianInput, Hash};
use digest;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


pub fn hash_bool_as_byte<H: digest::Input>(input: bool, digest: &mut H) {
    digest.process(&[input as u8]);
}

pub fn hash_char_as_utf8<H: digest::Input>(input: char, digest: &mut H) {
    let mut buf = [0u8; 4];
    let encoded = input.encode_utf8(&mut buf);
    digest.process(encoded.as_bytes());
}

pub fn hash_char_as_utf16<H: EndianInput>(input: char, digest: &mut H) {
    let mut buf = [0u16; 2];
    let encoded = input.encode_utf16(&mut buf);
    digest.process_u16(encoded[0]);
    if encoded.len() > 1 {
        digest.process_u16(encoded[1]);
    }
}

pub fn hash_char_as_utf32<H: EndianInput>(input: char, digest: &mut H) {
    digest.process_u32(input as u32);
}

pub fn hash_str_as_utf16<S, H>(input: S, digest: &mut H)
where S: AsRef<str>, H: EndianInput {
    hash_str_as_utf16_impl(input.as_ref(), digest)
}

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

pub fn hash_ip_addr_in_network_order<H>(
    addr: IpAddr,
    digest: &mut H
) where H: digest::Input {
    match addr {
        IpAddr::V4(v4addr) => hash_ipv4_addr_in_network_order(v4addr, digest),
        IpAddr::V6(v6addr) => hash_ipv6_addr_in_network_order(v6addr, digest)
    }
}

pub fn hash_ipv4_addr_in_network_order<H>(
    addr: Ipv4Addr,
    digest: &mut H
) where H: digest::Input {
    digest.process(&addr.octets());
}

pub fn hash_ipv6_addr_in_network_order<H>(
    addr: Ipv6Addr,
    digest: &mut H
) where H: digest::Input {
    digest.process(&addr.octets());
}

pub fn hash_slice_as_elements<T, H>(
    slice: &[T],
    digest: &mut H
) where T: Hash, H: EndianInput {
    for elem in slice {
        elem.hash(digest);
    }
}
