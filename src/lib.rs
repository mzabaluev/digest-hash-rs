// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Traits for stable cryptographic hashing of data structures.

extern crate digest;
extern crate byteorder;

use byteorder::{ByteOrder, BigEndian, LittleEndian};

use std::mem;

macro_rules! for_all_mi_words {
    (T, method, bo_func : $macro:ident!(T, method, bo_func)) => {
        $macro!(u16, process_u16, write_u16);
        $macro!(i16, process_i16, write_i16);
        $macro!(u32, process_u32, write_u32);
        $macro!(i32, process_i32, write_i32);
        $macro!(u64, process_u64, write_u64);
        $macro!(i64, process_i64, write_i64);
        $macro!(f32, process_f32, write_f32);
        $macro!(f64, process_f64, write_f64);
    }
}

macro_rules! endian_method {
    ($t:ty, $name:ident, $bo_func:ident) => {
        fn $name(&mut self, n: $t) {
            let mut buf: [u8; mem::size_of::<$t>()]
                         = unsafe { mem::uninitialized() };
            Bo::$bo_func(&mut buf, n);
            self.process(&buf);
        }
    }
}

/// Extends `digest::Input` to provide primitives for type-safe hashing.
///
/// `EndianInput` provides methods to process machine-independent values
/// of widths larger than 8-bit.
/// The trait is parameterized with a byte order which determines the
/// "endianness" of how the integer and floating-point values are going to
/// be serialized for digest computation.
pub trait EndianInput<Bo> : digest::Input
    where Bo: ByteOrder
{

    /// Feeds an unsigned 8-bit value into the digest function.
    ///
    /// This method is provided for completeness.
    fn process_u8(&mut self, n: u8) {
        self.process(&[n]);
    }

    /// Feeds a signed 8-bit value into the digest function.
    ///
    /// This method is provided for completeness.
    fn process_i8(&mut self, n: i8) {
        self.process(&[n as u8]);
    }

    for_all_mi_words!(T, method, bo_func:
                      endian_method!(T, method, bo_func));
}

// Blanket impl for all digest functions. This makes it impossible to
// implement the trait for anything else.
impl<T> EndianInput<LittleEndian> for T where T: digest::Input {}
impl<T> EndianInput<BigEndian> for T where T: digest::Input {}

/// A cryptographically hashable type.
///
/// This trait is similar to `std::hash::Hash`, with some differences:
///
/// - The byte order for representation of multi-byte values is determined
///   by the trait parameter.
/// - The choice of provided trait implementations discourages hashing of
///   machine-dependent types, or types without an unambiguous byte stream
///   representation.
/// - The standard sequential byte containers are transparent to hashing.
/// - The intended recipients of data for hashing are cryptographic hash
///   functions that implement traits defined in crate `digest`.
///
/// This trait can be implemented for a user-defined type to provide it with
/// a cryptographically stable representation for secure hashing.
pub trait Hash<Bo: ByteOrder> {
    /// Feeds this value into the given digest function.
    ///
    /// For multi-byte values, the byte order is selected by the
    /// trait parameter.
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput<Bo>;
}

macro_rules! impl_hash_for {
    {
        ($self:ident: &$t:ty, $digest:ident) $body:block
    } => {
        impl<Bo: ByteOrder> Hash<Bo> for $t {
            fn hash<H>(&$self, $digest: &mut H)
                where H: EndianInput<Bo>
            $body
        }
    }
}

macro_rules! impl_hash_for_primitive {
    ($t:ty, $method:ident, $_bo_func:ident) => {
        impl_hash_for! {
            (self: &$t, digest) {
                digest.$method(*self);
            }
        }
    }
}

for_all_mi_words!(T, method, bo_func:
                  impl_hash_for_primitive!(T, method, bo_func));

impl<'a, T: ?Sized, Bo> Hash<Bo> for &'a T
    where Bo: ByteOrder,
          T: Hash<Bo>
{
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput<Bo>,
              Bo: ByteOrder
    {
        (*self).hash::<H>(digest);
    }
}

impl_hash_for! {
    (self: &[u8], digest) {
        digest.process(self);
    }
}

impl_hash_for! {
    (self: &Box<[u8]>, digest) {
        digest.process(self);
    }
}

impl_hash_for! {
    (self: &Vec<u8>, digest) {
        digest.process(self);
    }
}

impl_hash_for! {
    (self: &str, digest) {
        digest.process(self.as_bytes());
    }
}

impl_hash_for! {
    (self: &Box<str>, digest) {
        digest.process(self.as_bytes());
    }
}

impl_hash_for! {
    (self: &String, digest) {
        digest.process(self.as_bytes());
    }
}

