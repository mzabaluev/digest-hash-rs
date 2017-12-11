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

extern crate digest;
extern crate byteorder;

use byteorder::ByteOrder;
use digest::generic_array::{GenericArray, ArrayLength};

use std::fmt;
use std::fmt::Debug;
use std::marker;
use std::mem;
use std::rc::Rc;
use std::sync::Arc;
use std::borrow::{Cow, ToOwned};

macro_rules! for_all_mi_words {
    ($macro:ident!) => {
        $macro!(u16, 2, process_u16, write_u16);
        $macro!(i16, 2, process_i16, write_i16);
        $macro!(u32, 4, process_u32, write_u32);
        $macro!(i32, 4, process_i32, write_i32);
        $macro!(u64, 8, process_u64, write_u64);
        $macro!(i64, 8, process_i64, write_i64);
        $macro!(f32, 4, process_f32, write_f32);
        $macro!(f64, 8, process_f64, write_f64);
    }
}

macro_rules! endian_method {
    ($t:ty, $size:expr, $name:ident, $bo_func:ident) => {
        fn $name(&mut self, n: $t) {
            let mut buf: [u8; $size]
                         = unsafe { mem::uninitialized() };
            <Self::ByteOrder>::$bo_func(&mut buf, n);
            self.process(&buf);
        }
    }
}

/// Extends `digest::Input` to provide primitives for type-safe hashing.
///
/// `EndianInput` provides methods to process machine-independent values
/// of bit widths larger than 8 bit. The values are serialized with the
/// byte order which is defined in the associated type `ByteOrder`.
pub trait EndianInput : digest::Input {

    /// The byte order this implementation provides.
    ///
    /// This type binding determines the "endianness" of how integer
    /// and floating-point values are serialized by this implementation
    /// towards computation of the digest.
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

    for_all_mi_words!(endian_method!);
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

impl<D, Bo> Endian<D, Bo>
    where Bo: ByteOrder
{
    /// Returns a string describing the byte order used by this
    /// `Endian` type instance.
    /// This is mainly used for debugging purposes.
    fn byte_order_str() -> &'static str {
        // Do a bit of runtime testing.
        let mut buf = [0u8; 2];
        Bo::write_u16(&mut buf, 0x0100);
        match buf[0] {
            0x01 => "BigEndian",
            0x00 => "LittleEndian",
            _ => unreachable!()
        }
    }
}

impl<D, Bo> Debug for Endian<D, Bo>
    where D: Debug,
          Bo: ByteOrder
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct(Self::byte_order_str())
         .field("digest", &self.inner)
         .finish()
    }
}

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

impl<D, Bo> digest::BlockInput for Endian<D, Bo>
    where D: digest::BlockInput
{
    type BlockSize = D::BlockSize;
}

impl<D, Bo> digest::FixedOutput for Endian<D, Bo>
    where D: digest::FixedOutput
{
    type OutputSize = D::OutputSize;

    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        self.inner.fixed_result()
    }
}

impl<D, Bo> Endian<D, Bo>
    where D: digest::Input,
          D: Default,
          Bo: ByteOrder
{
    /// Constructs an instance of an endian-aware hasher.
    ///
    /// # Examples
    ///
    /// ```
    /// # extern crate digest_hash;
    /// # extern crate sha2;
    /// # use sha2::Sha256;
    /// # fn main() {
    /// let hasher = digest_hash::BigEndian::<Sha256>::new();
    /// # }
    /// ```
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

impl<D, Bo> Endian<D, Bo> {
    /// Consumes self and returns the underlying digest implementation.
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
    ($t:ty, $_size:expr, $method:ident, $_bo_func:ident) => {
        impl_hash_for! {
            (self: &$t, digest) {
                digest.$method(*self);
            }
        }
    }
}

for_all_mi_words!(impl_hash_for_mi_word!);

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
    (self: &Vec<i8>, digest) {
        self.as_slice().hash(digest);
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

impl<N> Hash for GenericArray<u8, N>
    where N: ArrayLength<u8>
{
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        digest.process(self);
    }
}

impl<N> Hash for GenericArray<i8, N>
    where N: ArrayLength<i8>
{
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        self.as_slice().hash(digest);
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

    #[derive(Debug)]
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

        macro_rules! test_endian_debug {
            (   $test:ident,
                $Endian:ident) =>
            {
                #[test]
                fn $test() {
                    assert_eq!($Endian::<MockDigest>::byte_order_str(),
                               stringify!($Endian));
                    let hasher = $Endian::<MockDigest>::new();
                    let repr = format!("{:?}", hasher);
                    assert!(repr.starts_with(stringify!($Endian)));
                    assert!(repr.contains("MockDigest"));
                    assert!(!repr.contains("PhantomData"));
                }
            }
        }

        test_endian_debug!(debug_be, BigEndian);
        test_endian_debug!(debug_le, LittleEndian);

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

        use {BigEndian, LittleEndian, EndianInput};
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

        #[test]
        fn u8_slice_hash() {
            const TEST_DATA: &[u8] = &[b'A', b'B', b'C'];
            let mut hasher = BigEndian::<MockDigest>::new();
            (*TEST_DATA).hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, TEST_DATA);
        }

        #[test]
        fn i8_slice_hash() {
            const TEST_DATA: &[i8] = &[-128, -127, -126];
            let mut hasher = BigEndian::<MockDigest>::new();
            (*TEST_DATA).hash(&mut hasher);
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
            test_vec.hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, test_vec);
        }

        #[test]
        fn i8_vec_hash() {
            let test_vec = vec![-128i8, -127i8, -126i8];
            let mut hasher = BigEndian::<MockDigest>::new();
            test_vec.hash(&mut hasher);
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
            (*TEST_DATA).hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, TEST_DATA.as_bytes());
        }

        #[test]
        fn string_hash() {
            let test_str = String::from("Hello");
            let mut hasher = BigEndian::<MockDigest>::new();
            test_str.hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, test_str.as_bytes());
        }

        macro_rules! test_generic_array_hash {
            ($test:ident, $bt:ty) => {
                #[test]
                fn $test() {
                    use digest::generic_array::GenericArray;
                    use digest::generic_array::typenum::consts::U4;

                    let array = GenericArray::<$bt, U4>::generate(|n| { n as $bt });
                    let mut hasher = BigEndian::<MockDigest>::new();
                    array.hash(&mut hasher);
                    let output = hasher.into_inner().bytes;
                    assert_eq!(output, [0, 1, 2, 3]);
                }
            }
        }

        test_generic_array_hash!(generic_array_u8_hash, u8);
        test_generic_array_hash!(generic_array_i8_hash, i8);

        struct Hashable {
            foo: u16,
            bar: i32
        }

        impl Hash for Hashable {
            fn hash<H: EndianInput>(&self, digest: &mut H) {
                self.foo.hash(digest);
                self.bar.hash(digest);
            }
        }

        #[test]
        fn custom_be_hash() {
            let v = Hashable { foo: 0x0102, bar: 0x03040506 };
            let mut hasher = BigEndian::<MockDigest>::new();
            v.hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        }

        #[test]
        fn custom_le_hash() {
            let v = Hashable { foo: 0x0102, bar: 0x03040506 };
            let mut hasher = LittleEndian::<MockDigest>::new();
            v.hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, [0x02, 0x01, 0x06, 0x05, 0x04, 0x03]);
        }

        fn test_generic_impl<T: Hash>(v: &T, expected: &[u8]) {
            let mut hasher = BigEndian::<MockDigest>::new();
            v.hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, expected);
        }

        #[test]
        fn ref_hash() {
            let v = Hashable { foo: 0x0102, bar: 0x03040506 };
            test_generic_impl(&v, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        }

        #[test]
        fn box_hash() {
            let v = Box::new(Hashable { foo: 0x0102, bar: 0x03040506 });
            test_generic_impl(&v, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        }

        #[test]
        fn rc_hash() {
            use std::rc::Rc;

            let v = Rc::new(Hashable { foo: 0x0102, bar: 0x03040506 });
            test_generic_impl(&v, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        }

        #[test]
        fn arc_hash() {
            use std::sync::Arc;

            let v = Arc::new(Hashable { foo: 0x0102, bar: 0x03040506 });
            test_generic_impl(&v, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        }

        #[test]
        fn cow_borrowed_hash() {
            let cow = String::from_utf8_lossy(b"Hello");
            let mut hasher = BigEndian::<MockDigest>::new();
            cow.hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, cow.as_bytes());
        }

        #[test]
        fn cow_owned_hash() {
            let cow = String::from_utf8_lossy(b"Hello\xFF");
            let mut hasher = BigEndian::<MockDigest>::new();
            cow.hash(&mut hasher);
            let output = hasher.into_inner().bytes;
            assert_eq!(output, cow.as_bytes());
        }
    }
}
