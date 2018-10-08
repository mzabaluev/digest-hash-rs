// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use byteorder;
use byteorder::ByteOrder;
use digest;
use digest::generic_array::GenericArray;

use std::fmt;
use std::fmt::Debug;
use std::marker;
use std::mem;

macro_rules! endian_methods {
    (
        $t:ty,
        $size:expr,
        $input_method:ident,
        $chain_method:ident,
        $bo_func:ident
    ) => {
        fn $input_method(&mut self, n: $t) {
            let mut buf: [u8; $size]
                         = unsafe { mem::uninitialized() };
            <Self::ByteOrder>::$bo_func(&mut buf, n);
            self.input(&buf);
        }

        fn $chain_method(mut self, n: $t) -> Self
        where Self: Sized {
            self.$input_method(n);
            self
        }
    }
}

/// Extends `digest::Input` to provide primitives for type-safe hashing.
///
/// `EndianInput` provides methods to process machine-independent values
/// of bit widths larger than 8 bit. The values are serialized with the
/// byte order which is defined in the associated type `ByteOrder`.
pub trait EndianInput: digest::Input {
    /// The byte order this implementation provides.
    ///
    /// This type binding determines the "endianness" of how integer
    /// and floating-point values are serialized by this implementation
    /// towards computation of the digest.
    type ByteOrder: ByteOrder;

    /// Feeds an unsigned 8-bit value into the digest function.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn input_u8(&mut self, n: u8) {
        self.input(&[n]);
    }

    /// Feeds a signed 8-bit value into the digest function.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn input_i8(&mut self, n: i8) {
        self.input(&[n as u8]);
    }

    /// Digest an unsigned 8-bit value in a chained manner.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn chain_u8(self, n: u8) -> Self
    where
        Self: Sized,
    {
        self.chain(&[n])
    }

    /// Digest a signed 8-bit value in a chained manner.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn chain_i8(self, n: i8) -> Self
    where
        Self: Sized,
    {
        self.chain(&[n as u8])
    }

    for_all_mi_words!(endian_methods!);
}

/// An adapter to provide digest functions with endian-awareness.
#[derive(Clone)]
pub struct Endian<D, Bo> {
    inner: D,
    phantom: marker::PhantomData<Bo>,
}

/// A type alias for `Endian` specialized for big endian byte order.
pub type BigEndian<D> = Endian<D, byteorder::BigEndian>;

/// A type alias for `Endian` specialized for little endian byte order.
pub type LittleEndian<D> = Endian<D, byteorder::LittleEndian>;

/// A type alias for `Endian` specialized for network byte order.
///
/// Network byte order is defined by [RFC 1700][rfc1700] to be big-endian,
/// and is referred to in several protocol specifications.
/// This type is an alias of `BigEndian`.
///
/// [rfc1700]: https://tools.ietf.org/html/rfc1700
pub type NetworkEndian<D> = BigEndian<D>;

impl<D, Bo> Endian<D, Bo>
where
    Bo: ByteOrder,
{
    /// Returns a string describing the byte order used by this
    /// `Endian` type instance.
    ///
    /// This is mainly used for debugging purposes. The user
    /// should not rely on any particular output.
    pub fn byte_order_str() -> &'static str {
        // Do a bit of runtime testing.
        let mut buf = [0u8; 4];
        Bo::write_u32(&mut buf, 0x01020304);
        let le = byteorder::LittleEndian::read_u32(&buf);
        match le {
            0x01020304 => "LittleEndian",
            0x04030201 => "BigEndian",
            _ => "unknown byte order",
        }
    }
}

impl<D, Bo> Debug for Endian<D, Bo>
where
    D: Debug,
    Bo: ByteOrder,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        f.debug_struct(Self::byte_order_str())
            .field("digest", &self.inner)
            .finish()
    }
}

impl<D, Bo> EndianInput for Endian<D, Bo>
where
    D: digest::Input,
    Bo: ByteOrder,
{
    type ByteOrder = Bo;
}

impl<D, Bo> digest::Input for Endian<D, Bo>
where
    D: digest::Input,
{
    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        self.inner.input(data)
    }
}

impl<D, Bo> digest::BlockInput for Endian<D, Bo>
where
    D: digest::BlockInput,
{
    type BlockSize = D::BlockSize;
}

impl<D, Bo> digest::FixedOutput for Endian<D, Bo>
where
    D: digest::FixedOutput,
{
    type OutputSize = D::OutputSize;

    fn fixed_result(self) -> GenericArray<u8, Self::OutputSize> {
        self.inner.fixed_result()
    }
}

impl<D, Bo> digest::Reset for Endian<D, Bo>
where
    D: digest::Reset,
{
    fn reset(&mut self) {
        self.inner.reset()
    }
}

impl<D, Bo> Endian<D, Bo>
where
    D: digest::Input,
    D: Default,
    Bo: ByteOrder,
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
            phantom: marker::PhantomData,
        }
    }
}

impl<D, Bo> Default for Endian<D, Bo>
where
    D: digest::Input,
    D: Default,
    Bo: ByteOrder,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D, Bo> From<D> for Endian<D, Bo>
where
    D: digest::Input,
    Bo: ByteOrder,
{
    fn from(digest: D) -> Self {
        Endian {
            inner: digest,
            phantom: marker::PhantomData,
        }
    }
}

impl<D, Bo> Endian<D, Bo> {
    /// Consumes self and returns the underlying digest implementation.
    pub fn into_inner(self) -> D {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use EndianInput;
    use {BigEndian, LittleEndian, NetworkEndian};

    use testmocks::conv_with;
    use testmocks::MockDigest;

    use std::mem;
    use std::{f32, f64};

    #[test]
    fn default_works() {
        let _ = NetworkEndian::<MockDigest>::default();
    }

    macro_rules! test_endian_debug {
        (
            $test:ident,
            $Endian:ident
        ) => {
            #[test]
            fn $test() {
                assert_eq!($Endian::<MockDigest>::byte_order_str(), stringify!($Endian));
                let hasher = $Endian::<MockDigest>::new();
                let repr = format!("{:?}", hasher);
                assert!(repr.starts_with(stringify!($Endian)));
                assert!(repr.contains("MockDigest"));
                assert!(!repr.contains("PhantomData"));
            }
        };
    }

    test_endian_debug!(debug_be, BigEndian);
    test_endian_debug!(debug_le, LittleEndian);

    macro_rules! test_endian_input {
        (
            $test:ident,
            $Endian:ident,
            $input_method:ident,
            $chain_method:ident,
            $val:expr,
            $to_endian_bits:expr
        ) => {
            #[test]
            fn $test() {
                let val_bits = conv_with($val, $to_endian_bits);
                let expected = bytes_from_endian!(val_bits);

                let mut hasher = $Endian::<MockDigest>::new();
                hasher.$input_method($val);
                let output = hasher.into_inner().bytes;
                assert_eq!(output, expected);

                let hasher = $Endian::<MockDigest>::new();
                let output = hasher.$chain_method($val).into_inner().bytes;
                assert_eq!(output, expected);
            }
        };
    }

    macro_rules! test_byte_input {
        (
            $be_test:ident,
            $le_test:ident,
            $input_method:ident,
            $chain_method:ident,
            $val:expr
        ) => {
            test_endian_input!(
                $be_test,
                BigEndian,
                $input_method,
                $chain_method,
                $val,
                |v| v
            );
            test_endian_input!(
                $le_test,
                LittleEndian,
                $input_method,
                $chain_method,
                $val,
                |v| v
            );
        };
    }

    macro_rules! test_word_input {
        (
            $be_test:ident,
            $le_test:ident,
            $input_method:ident,
            $chain_method:ident,
            $val:expr
        ) => {
            test_word_input!(
                $be_test,
                $le_test,
                $input_method,
                $chain_method,
                $val,
                |v| v
            );
        };

        (
            $be_test:ident,
            $le_test:ident,
            $input_method:ident,
            $chain_method:ident,
            $val:expr,
            $conv:expr
        ) => {
            test_endian_input!(
                $be_test,
                BigEndian,
                $input_method,
                $chain_method,
                $val,
                |v| conv_with(v, $conv).to_be()
            );
            test_endian_input!(
                $le_test,
                LittleEndian,
                $input_method,
                $chain_method,
                $val,
                |v| conv_with(v, $conv).to_le()
            );
        };
    }

    macro_rules! test_float_input {
        (
            $be_test:ident,
            $le_test:ident,
            $input_method:ident,
            $chain_method:ident,
            $val:expr
        ) => {
            test_word_input!(
                $be_test,
                $le_test,
                $input_method,
                $chain_method,
                $val,
                |v| v.to_bits()
            );
        };
    }

    test_byte_input!(u8_be_input, u8_le_input, input_u8, chain_u8, 0xA5u8);
    test_byte_input!(i8_be_input, i8_le_input, input_i8, chain_i8, -128i8);
    test_word_input!(u16_be_input, u16_le_input, input_u16, chain_u16, 0xA55Au16);
    test_word_input!(i16_be_input, i16_le_input, input_i16, chain_i16, -0x7FFEi16);
    test_word_input!(
        u32_be_input,
        u32_le_input,
        input_u32,
        chain_u32,
        0xA0B0_C0D0u32
    );
    test_word_input!(
        i32_be_input,
        i32_le_input,
        input_i32,
        chain_i32,
        -0x7F01_02FDi32
    );
    test_word_input!(
        u64_be_input,
        u64_le_input,
        input_u64,
        chain_u64,
        0xA0B0_C0D0_0102_0304u64
    );
    test_word_input!(
        i64_be_input,
        i64_le_input,
        input_i64,
        chain_i64,
        -0x7F01_0203_0405_FFFDi64
    );
    test_float_input!(
        f32_be_input,
        f32_le_input,
        input_f32,
        chain_f32,
        f32::consts::PI
    );
    test_float_input!(
        f64_be_input,
        f64_le_input,
        input_f64,
        chain_f64,
        f64::consts::PI
    );
}
