// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use EndianInput;
use digest::generic_array::{GenericArray, ArrayLength};

use std::mem;
use std::rc::Rc;
use std::sync::Arc;
use std::borrow::{Cow, ToOwned};


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
        digest.input_u8(*self);
    }
}

impl Hash for i8 {
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        digest.input_i8(*self);
    }
}

impl<N> Hash for GenericArray<u8, N>
    where N: ArrayLength<u8>
{
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        digest.input(self.as_slice());
    }
}

impl<N> Hash for GenericArray<i8, N>
    where N: ArrayLength<i8>
{
    fn hash<H>(&self, digest: &mut H)
        where H: EndianInput
    {
        let bytes: &[u8] = unsafe { mem::transmute(self.as_slice()) };
        digest.input(bytes);
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
    use Hash;

    use {BigEndian, LittleEndian};
    use testmocks::{MockDigest, Hashable};
    use testmocks::conv_with;

    use std::mem;
    use std::{f32, f64};
    use std::borrow::Cow;

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

    macro_rules! test_generic_array_hash {
        ($test:ident, $bt:ty) => {
            #[test]
            fn $test() {
                use digest::generic_array::GenericArray;
                use digest::generic_array::typenum::consts::U4;

                let array = GenericArray::<$bt, U4>::from_exact_iter(
                    (0..4).map(|n| { n as $bt })).unwrap();
                let mut hasher = BigEndian::<MockDigest>::new();
                array.hash(&mut hasher);
                let output = hasher.into_inner().bytes;
                assert_eq!(output, [0, 1, 2, 3]);
            }
        }
    }

    test_generic_array_hash!(generic_array_u8_hash, u8);
    test_generic_array_hash!(generic_array_i8_hash, i8);

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
        let borrowed = &Hashable { foo: 0x0102, bar: 0x03040506 };
        let cow = Cow::Borrowed(borrowed);
        let mut hasher = BigEndian::<MockDigest>::new();
        cow.hash(&mut hasher);
        let output = hasher.into_inner().bytes;
        assert_eq!(output, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }

    #[test]
    fn cow_owned_hash() {
        let owned = Hashable { foo: 0x0102, bar: 0x03040506 };
        let cow = Cow::Owned::<Hashable>(owned);
        let mut hasher = BigEndian::<MockDigest>::new();
        cow.hash(&mut hasher);
        let output = hasher.into_inner().bytes;
        assert_eq!(output, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
    }
}
