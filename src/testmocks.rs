// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use digest;
use EndianInput;
use Hash;

#[derive(Debug)]
pub struct MockDigest {
    pub bytes: Vec<u8>
}

impl Default for MockDigest {
    fn default() -> Self {
        MockDigest { bytes: Vec::new() }
    }
}

impl digest::Input for MockDigest {
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.bytes.extend_from_slice(data.as_ref());
    }
}

#[derive(Clone)]
pub struct Hashable {
    pub foo: u16,
    pub bar: i32
}

impl Hash for Hashable {
    fn hash<H: EndianInput>(&self, digest: &mut H) {
        self.foo.hash(digest);
        self.bar.hash(digest);
    }
}

// A function to help type inference in macros
pub fn conv_with<T, F, R>(v: T, f: F) -> R
    where F: FnOnce(T) -> R
{
    f(v)
}
