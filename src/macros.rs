// Copyright 2017 Mikhail Zabaluev <mikhail.zabaluev@gmail.com>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

// Macros used by multiple modules of this crate.

macro_rules! for_all_mi_words {
    ($macro:ident!) => {
        $macro!(u16, 2, input_u16, write_u16);
        $macro!(i16, 2, input_i16, write_i16);
        $macro!(u32, 4, input_u32, write_u32);
        $macro!(i32, 4, input_i32, write_i32);
        $macro!(u64, 8, input_u64, write_u64);
        $macro!(i64, 8, input_i64, write_i64);
        $macro!(f32, 4, input_f32, write_f32);
        $macro!(f64, 8, input_f64, write_f64);
    }
}

#[cfg(test)]
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
