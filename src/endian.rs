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

use std::fmt;
use std::fmt::Debug;
use std::marker;

macro_rules! endian_methods {
    (
        $t:ty,
        $size:expr,
        $update_method:ident,
        $chain_method:ident,
        $bo_func:ident
    ) => {
        fn $update_method(&mut self, n: $t) {
            let mut buf = [0; $size];
            <Self::ByteOrder>::$bo_func(&mut buf, n);
            self.update(&buf);
        }

        fn $chain_method(mut self, n: $t) -> Self
        where
            Self: Sized,
        {
            self.$update_method(n);
            self
        }
    };
}

/// Extends `digest::Update` to provide primitives for type-safe hashing.
///
/// `EndianUpdate` provides methods to process machine-independent values
/// of bit widths larger than 8 bit. The values are serialized with the
/// byte order which is defined in the associated type `ByteOrder`.
pub trait EndianUpdate: digest::Update {
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
    fn update_u8(&mut self, n: u8) {
        self.update(&[n]);
    }

    /// Feeds a signed 8-bit value into the digest function.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn update_i8(&mut self, n: i8) {
        self.update(&[n as u8]);
    }

    /// Digest an unsigned 8-bit value in a chained manner.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn chain_u8(self, n: u8) -> Self
    where
        Self: Sized,
    {
        self.chain([n])
    }

    /// Digest a signed 8-bit value in a chained manner.
    ///
    /// This method is agnostic to the byte order, and is only provided
    /// for completeness.
    fn chain_i8(self, n: i8) -> Self
    where
        Self: Sized,
    {
        self.chain([n as u8])
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

impl<D, Bo> EndianUpdate for Endian<D, Bo>
where
    D: digest::Update,
    Bo: ByteOrder,
{
    type ByteOrder = Bo;
}

impl<D, Bo> digest::Update for Endian<D, Bo>
where
    D: digest::Update,
{
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data)
    }
}

impl<D, Bo> digest::OutputSizeUser for Endian<D, Bo>
where
    D: digest::OutputSizeUser,
{
    type OutputSize = D::OutputSize;
}

impl<D, Bo> digest::FixedOutput for Endian<D, Bo>
where
    D: digest::FixedOutput,
{
    fn finalize_into(self, out: &mut digest::Output<Self>) {
        self.inner.finalize_into(out)
    }

    fn finalize_fixed(self) -> digest::Output<Self> {
        self.inner.finalize_fixed()
    }
}

impl<D, Bo> digest::FixedOutputReset for Endian<D, Bo>
where
    D: digest::FixedOutputReset,
{
    fn finalize_into_reset(&mut self, out: &mut digest::Output<Self>) {
        self.inner.finalize_into_reset(out)
    }

    fn finalize_fixed_reset(&mut self) -> digest::Output<Self> {
        self.inner.finalize_fixed_reset()
    }
}

impl<D, Bo> digest::HashMarker for Endian<D, Bo> where D: digest::Update {}

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
    D: digest::Update,
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
    D: digest::Update,
    D: Default,
    Bo: ByteOrder,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<D, Bo> From<D> for Endian<D, Bo>
where
    D: digest::Update,
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
    use EndianUpdate;
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

    macro_rules! test_endian_update {
        (
            $test:ident,
            $Endian:ident,
            $update_method:ident,
            $chain_method:ident,
            $val:expr,
            $to_endian_bits:expr
        ) => {
            #[test]
            fn $test() {
                let val_bits = conv_with($val, $to_endian_bits);
                let expected = bytes_from_endian!(val_bits);

                let mut hasher = $Endian::<MockDigest>::new();
                hasher.$update_method($val);
                let output = hasher.into_inner().bytes;
                assert_eq!(output, expected);

                let hasher = $Endian::<MockDigest>::new();
                let output = hasher.$chain_method($val).into_inner().bytes;
                assert_eq!(output, expected);
            }
        };
    }

    macro_rules! test_byte_update {
        (
            $be_test:ident,
            $le_test:ident,
            $update_method:ident,
            $chain_method:ident,
            $val:expr
        ) => {
            test_endian_update!(
                $be_test,
                BigEndian,
                $update_method,
                $chain_method,
                $val,
                |v| v
            );
            test_endian_update!(
                $le_test,
                LittleEndian,
                $update_method,
                $chain_method,
                $val,
                |v| v
            );
        };
    }

    macro_rules! test_word_update {
        (
            $be_test:ident,
            $le_test:ident,
            $update_method:ident,
            $chain_method:ident,
            $val:expr
        ) => {
            test_word_update!(
                $be_test,
                $le_test,
                $update_method,
                $chain_method,
                $val,
                |v| v
            );
        };

        (
            $be_test:ident,
            $le_test:ident,
            $update_method:ident,
            $chain_method:ident,
            $val:expr,
            $conv:expr
        ) => {
            test_endian_update!(
                $be_test,
                BigEndian,
                $update_method,
                $chain_method,
                $val,
                |v| conv_with(v, $conv).to_be()
            );
            test_endian_update!(
                $le_test,
                LittleEndian,
                $update_method,
                $chain_method,
                $val,
                |v| conv_with(v, $conv).to_le()
            );
        };
    }

    macro_rules! test_float_update {
        (
            $be_test:ident,
            $le_test:ident,
            $update_method:ident,
            $chain_method:ident,
            $val:expr
        ) => {
            test_word_update!(
                $be_test,
                $le_test,
                $update_method,
                $chain_method,
                $val,
                |v| v.to_bits()
            );
        };
    }

    test_byte_update!(u8_be_update, u8_le_update, update_u8, chain_u8, 0xA5u8);
    test_byte_update!(i8_be_update, i8_le_update, update_i8, chain_i8, -128i8);
    test_word_update!(
        u16_be_update,
        u16_le_update,
        update_u16,
        chain_u16,
        0xA55Au16
    );
    test_word_update!(
        i16_be_update,
        i16_le_update,
        update_i16,
        chain_i16,
        -0x7FFEi16
    );
    test_word_update!(
        u32_be_update,
        u32_le_update,
        update_u32,
        chain_u32,
        0xA0B0_C0D0u32
    );
    test_word_update!(
        i32_be_update,
        i32_le_update,
        update_i32,
        chain_i32,
        -0x7F01_02FDi32
    );
    test_word_update!(
        u64_be_update,
        u64_le_update,
        update_u64,
        chain_u64,
        0xA0B0_C0D0_0102_0304u64
    );
    test_word_update!(
        i64_be_update,
        i64_le_update,
        update_i64,
        chain_i64,
        -0x7F01_0203_0405_FFFDi64
    );
    test_float_update!(
        f32_be_update,
        f32_le_update,
        update_f32,
        chain_f32,
        f32::consts::PI
    );
    test_float_update!(
        f64_be_update,
        f64_le_update,
        update_f64,
        chain_f64,
        f64::consts::PI
    );
}
