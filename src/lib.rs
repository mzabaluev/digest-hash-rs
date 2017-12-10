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

use byteorder::ByteOrder;

use std::marker;
use std::mem;
use std::rc::Rc;
use std::sync::Arc;
use std::borrow::{Cow, ToOwned};

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
            <Self::ByteOrder>::$bo_func(&mut buf, n);
            self.process(&buf);
        }
    }
}

/// Extends `digest::Input` to provide primitives for type-safe hashing.
///
/// `EndianInput` provides methods to process machine-independent values
/// of bit widths larger than 8 bit.
/// The methods are parameterized with a byte order which determines the
/// "endianness" of how the integer and floating-point values are going to
/// be serialized for digest computation.
pub trait EndianInput : digest::Input {

    /// The byte order this implementation provides.
    ///
    /// This type binding determines the "endianness" of how the integer
    /// and floating-point values are serialized for digest computation.
    type ByteOrder : ByteOrder;

    /// Feeds an unsigned 8-bit value into the digest function.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn process_u8(&mut self, n: u8) {
        self.process(&[n]);
    }

    /// Feeds a signed 8-bit value into the digest function.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn process_i8(&mut self, n: i8) {
        self.process(&[n as u8]);
    }

    for_all_mi_words!(T, method, bo_func:
                      endian_method!(T, method, bo_func));
}

/// An adapter to provide digest functions with endian-awareness.
#[derive(Default, Clone)]
pub struct Endian<D, Bo> {
    inner: D,
    phantom: marker::PhantomData<Bo>
}

/// A type alias for `Endian` specialized for big endian byte order.
pub type BigEndian<D> = Endian<D, byteorder::BigEndian>;

/// A type alias for `Endian` specialized for little endian byte order.
pub type LittleEndian<D> = Endian<D, byteorder::LittleEndian>;

impl<D, Bo> EndianInput for Endian<D, Bo>
    where D: digest::Input,
          Bo: ByteOrder
{
    type ByteOrder = Bo;
}

impl<D, Bo> digest::Input for Endian<D, Bo>
    where D: digest::Input
{
    fn process(&mut self, input: &[u8]) { self.inner.process(input) }
}

impl<D, Bo> Endian<D, Bo>
    where D: digest::Input,
          D: Default,
          Bo: ByteOrder
{
    pub fn new() -> Self {
        Endian {
            inner: D::default(),
            phantom: marker::PhantomData
        }
    }
}

impl<D, Bo> From<D> for Endian<D, Bo>
    where D: digest::Input,
          Bo: ByteOrder
{
    fn from(digest: D) -> Self {
        Endian {
            inner: digest,
            phantom: marker::PhantomData
        }
    }
}

impl<D, Bo> Endian<D, Bo>
    where D: digest::Input
{
    pub fn into_inner(self) -> D { self.inner }
}

/// A cryptographically hashable type.
///
/// This trait is similar to `std::hash::Hash`, with some differences:
///
/// - The choice of provided trait implementations discourages hashing of
///   machine-dependent types, or types without an unambiguous byte stream
///   representation.
/// - The standard sequential byte containers are transparent to hashing.
/// - The intended recipients of data for hashing are cryptographic hash
///   functions that implement traits defined in crate `digest`.
///
/// This trait can be implemented for a user-defined type to provide it with
/// a cryptographically stable representation for secure hashing.
pub trait Hash {
    /// Feeds this value into the given digest function.
    ///
    /// For multi-byte data member values, the byte order is imposed by the
    /// implementation of `EndianInput` that the digest function provides.
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput;
}

macro_rules! impl_hash_for {
    {
        ($self:ident: &$t:ty, $digest:ident)
        $body:block
    } => {
        impl Hash for $t {
            fn hash<H>(&$self, $digest: &mut H)
                where H: EndianInput
            $body
        }
    }
}

macro_rules! impl_hash_for_mi_word {
    ($t:ty, $method:ident, $_bo_func:ident) => {
        impl_hash_for! {
            (self: &$t, digest) {
                digest.$method(*self);
            }
        }
    }
}

for_all_mi_words!(T, method, bo_func:
                  impl_hash_for_mi_word!(T, method, bo_func));

impl Hash for u8 {
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        digest.process_u8(*self);
    }
}

impl Hash for i8 {
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        digest.process_i8(*self);
    }
}

impl_hash_for! {
    (self: &[u8], digest) {
        digest.process(self);
    }
}

impl_hash_for! {
    (self: &[i8], digest) {
        let bytes: &[u8] = unsafe { mem::transmute(self) };
        digest.process(bytes);
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
    (self: &String, digest) {
        digest.process(self.as_bytes());
    }
}

impl<'a, T: ?Sized> Hash for &'a T where T: Hash
{
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        (*self).hash(digest);
    }
}

macro_rules! impl_hash_for_gen_pointer {
    ($Ptr:ident<$T:ident>) => {
        impl<$T: ?Sized> Hash for $Ptr<$T> where $T: Hash
        {
            fn hash<H>(&self, digest: &mut H)
                where H: EndianInput
            {
                (**self).hash(digest);
            }
        }
    }
}

impl_hash_for_gen_pointer!(Box<T>);
impl_hash_for_gen_pointer!(Rc<T>);
impl_hash_for_gen_pointer!(Arc<T>);

impl<'a, B: ?Sized> Hash for Cow<'a, B>
    where B: Hash,
          B: ToOwned,
          B::Owned: Hash
{
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        match *self {
            Cow::Borrowed(b)  => b.hash(digest),
            Cow::Owned(ref v) => v.hash(digest)
        }
    }
}

#[cfg(test)]
mod tests {

    use digest;

    struct MockDigest {
        bytes: Vec<u8>
    }

    impl Default for MockDigest {
        fn default() -> Self {
            MockDigest { bytes: Vec::new() }
        }
    }

    impl digest::Input for MockDigest {
        fn process(&mut self, input: &[u8]) {
            self.bytes.extend_from_slice(input);
        }
    }

    // A function to help type inference in macros
    fn conv_with<T, F, R>(v: T, f: F) -> R
        where F: FnOnce(T) -> R
    {
        f(v)
    }

    macro_rules! bytes_from_endian {
        ($val:expr) => {
            {
                let n_bytes = mem::size_of_val(&$val);
                let val = ($val as u64).to_le();
                let bytes: Vec<_> =
                        (0 .. n_bytes).map(|i| {
                            ((val >> i * 8) & 0xFF) as u8
                        })
                        .collect();
                bytes
            }
        }
    }

    mod endian {
        use {BigEndian, LittleEndian};
        use EndianInput;

        use super::MockDigest;
        use super::conv_with;

        use std::mem;
        use std::{f32, f64};

        macro_rules! test_endian_input {
            (   $test:ident,
                $Endian:ident,
                $method:ident,
                $val:expr,
                $to_endian_bits:expr) =>
            {
                #[test]
                fn $test() {
                    let mut hasher = $Endian::<MockDigest>::new();
                    hasher.$method($val);
                    let output = hasher.into_inner().bytes;
                    let val_bits = conv_with($val, $to_endian_bits);
                    let expected = bytes_from_endian!(val_bits);
                    assert_eq!(output, expected);
                }
            }
        }

        macro_rules! test_byte_input {
            (   $be_test:ident,
                $le_test:ident,
                $method:ident,
                $val:expr) =>
            {
                test_endian_input!(
                    $be_test, BigEndian, $method, $val,
                    |v| { v });
                test_endian_input!(
                    $le_test, LittleEndian, $method, $val,
                    |v| { v });
            };
        }

        macro_rules! test_word_input {
            (   $be_test:ident,
                $le_test:ident,
                $method:ident,
                $val:expr) =>
            {
                test_word_input!(
                    $be_test, $le_test, $method, $val,
                    |v| { v });
            };

            (   $be_test:ident,
                $le_test:ident,
                $method:ident,
                $val:expr,
                $conv:expr) =>
            {
                test_endian_input!(
                    $be_test, BigEndian, $method, $val,
                    |v| { conv_with(v, $conv).to_be() });
                test_endian_input!(
                    $le_test, LittleEndian, $method, $val,
                    |v| { conv_with(v, $conv).to_le() });
            };
        }

        macro_rules! test_float_input {
            (   $be_test:ident,
                $le_test:ident,
                $method:ident,
                $val:expr) =>
            {
                test_word_input!(
                    $be_test, $le_test, $method, $val,
                    |v| { v.to_bits() });
            }
        }

        test_byte_input!(
             u8_be_input,  u8_le_input, process_u8, 0xA5u8);
        test_byte_input!(
             i8_be_input,  i8_le_input, process_i8, -128i8);
        test_word_input!(
            u16_be_input, u16_le_input, process_u16, 0xA55Au16);
        test_word_input!(
            i16_be_input, i16_le_input, process_i16, -0x7FFEi16);
        test_word_input!(
            u32_be_input, u32_le_input, process_u32, 0xA0B0_C0D0u32);
        test_word_input!(
            i32_be_input, i32_le_input, process_i32, -0x7F01_02FDi32);
        test_word_input!(
            u64_be_input, u64_le_input, process_u64, 0xA0B0_C0D0_0102_0304u64);
        test_word_input!(
            i64_be_input, i64_le_input, process_i64, -0x7F01_0203_0405_FFFDi64);
        test_float_input!(
            f32_be_input, f32_le_input, process_f32, f32::consts::PI);
        test_float_input!(
            f64_be_input, f64_le_input, process_f64, f64::consts::PI);
    }

    mod hash {
        use Hash;

        use {BigEndian, LittleEndian};
        use super::MockDigest;
        use super::conv_with;

        use std::mem;
        use std::{f32, f64};

        macro_rules! test_endian_hash {
            (   $test:ident,
                $Endian:ident,
                $val:expr,
                $to_endian_bits:expr) =>
            {
                #[test]
                fn $test() {
                    let mut hasher = $Endian::<MockDigest>::new();
                    ($val).hash(&mut hasher);
                    let output = hasher.into_inner().bytes;
                    let val_bits = conv_with($val, $to_endian_bits);
                    let expected = bytes_from_endian!(val_bits);
                    assert_eq!(output, expected);
                }
            }
        }

        macro_rules! test_byte_hash {
            (   $be_test:ident,
                $le_test:ident,
                $val:expr) =>
            {
                test_endian_hash!(
                    $be_test, BigEndian, $val,
                    |v| { v });
                test_endian_hash!(
                    $le_test, LittleEndian, $val,
                    |v| { v });
            };
        }

        macro_rules! test_word_hash {
            (   $be_test:ident,
                $le_test:ident,
                $val:expr) =>
            {
                test_word_hash!(
                    $be_test, $le_test, $val,
                    |v| { v });
            };

            (   $be_test:ident,
                $le_test:ident,
                $val:expr,
                $conv:expr) =>
            {
                test_endian_hash!(
                    $be_test, BigEndian, $val,
                    |v| { conv_with(v, $conv).to_be() });
                test_endian_hash!(
                    $le_test, LittleEndian, $val,
                    |v| { conv_with(v, $conv).to_le() });
            };
        }

        macro_rules! test_float_hash {
            (   $be_test:ident,
                $le_test:ident,
                $val:expr) =>
            {
                test_word_hash!(
                    $be_test, $le_test, $val,
                    |v| { v.to_bits() });
            }
        }

        test_byte_hash!(
             u8_be_hash,  u8_le_hash, 0xA5u8);
        test_byte_hash!(
             i8_be_hash,  i8_le_hash, -128i8);
        test_word_hash!(
            u16_be_hash, u16_le_hash, 0xA55Au16);
        test_word_hash!(
            i16_be_hash, i16_le_hash, -0x7FFEi16);
        test_word_hash!(
            u32_be_hash, u32_le_hash, 0xA0B0_C0D0u32);
        test_word_hash!(
            i32_be_hash, i32_le_hash, -0x7F01_02FDi32);
        test_word_hash!(
            u64_be_hash, u64_le_hash, 0xA0B0_C0D0_0102_0304u64);
        test_word_hash!(
            i64_be_hash, i64_le_hash, -0x7F01_0203_0405_FFFDi64);
        test_float_hash!(
            f32_be_hash, f32_le_hash, f32::consts::PI);
        test_float_hash!(
            f64_be_hash, f64_le_hash, f64::consts::PI);
    }
}
