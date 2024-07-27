// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! # General utility functions
//!
//! This submodule provides general-purpose methods and structs
//! that aren't necessarily packet-specific. At present time, none
//! of these functions should be considered stable--they may be
//! removed or changed at any release.

use core::{array, default, mem};

//#[cfg(all(not(feature = "std"), feature = "alloc"))]
//use alloc::vec::Vec;

// TODO: optimize this
pub fn ones_complement_16bit(bytes: &[u8]) -> u16 {
    let mut res: u16 = 0;
    let mut iter = bytes.iter();
    while let Some(&first) = iter.next() {
        let second = *iter.next().unwrap_or(&0);
        res = ones_complement_add(res, (first as u16) << 8 | (second as u16));
    }

    res
}

#[inline]
pub fn ones_complement_add(a: u16, b: u16) -> u16 {
    let new = a.wrapping_add(b);
    if new < a {
        new.wrapping_add(1)
    } else {
        new
    }
}

#[inline]
pub(crate) fn to_array<const T: usize>(bytes: &[u8], start: usize) -> Option<[u8; T]> {
    Some(*get_array(bytes, start)?)
}

#[inline]
pub fn get_array<const T: usize>(bytes: &[u8], start: usize) -> Option<&[u8; T]> {
    bytes.get(start..start + T)?.try_into().ok()
}

#[inline]
pub fn get_mut_array<const T: usize>(
    bytes: &mut [u8],
    start: usize,
) -> Option<&mut [u8; T]> {
    bytes.get_mut(start..start + T)?.try_into().ok()
}

#[inline]
pub(crate) fn split_array<const T: usize>(bytes: &[u8]) -> Option<(&[u8; T], &[u8])> {
    Some((bytes.get(..T)?.try_into().ok()?, bytes.get(T..)?))
}

#[inline]
pub(crate) fn split_at(bytes: &[u8], idx: usize) -> Option<(&[u8], &[u8])> {
    match (bytes.get(..idx), bytes.get(idx..)) {
        (Some(b1), Some(b2)) => Some((b1, b2)),
        _ => None,
    }
}

/// Split the slice at the first instance of a particular delimeter, returning the bytes preceeding and following it.
/// If no instance of the delimeter is found, None is returned.
#[inline]
pub(crate) fn split_delim(bytes: &[u8], delim: u8) -> Option<(&[u8], &[u8])> {
    for (idx, b) in bytes.iter().enumerate() {
        if *b == delim {
            return Some((&bytes[..idx], &bytes[idx + 1..]));
        }
    }

    None
}

#[inline]
pub(crate) fn padded_length<const T: usize>(unpadded_len: usize) -> usize {
    unpadded_len + ((T - (unpadded_len % T)) % T)
}

/*
#[inline]
fn bits_ge(idx: usize) -> u64 {
    assert!(idx < 64, "bit index out of range for bits_ge()");
    if idx == 0 {
        u64::MAX
    } else {
        (1 << (64 - (idx % 64))) - 1
    }
}


#[inline]
fn bits_lt(idx: usize) -> u64 {
    assert!(idx < 64, "bit index out of range for bits_lt()");
    !bits_ge(idx)
}


// A simplified bit vector, for use in Ipv4/v6 defragmentation and other things
pub(crate) struct BitVec {
    bits: Vec<u64>,
    end: usize,
}

impl BitVec {
    #[inline]
    pub fn new() -> Self {
        BitVec {
            bits: Vec::new(),
            end: 0,
        }
    }

    pub fn is_filled(&self) -> bool {
        match self.bits.split_last() {
            None => true,
            Some((last, filled)) => {
                for &b in filled {
                    if b != u64::MAX {
                        return false;
                    }
                }

                let last_bit_idx = self.end % 64;
                if last_bit_idx == 0 {
                    true
                } else {
                    last ^ bits_lt(last_bit_idx) == 0
                }
            }
        }
    }

    pub fn set(&mut self, bits_start: usize, bits_end: usize) {
        assert!(
            bits_start <= bits_end,
            "invalid BitVec set() range: start must be less than or equal to end"
        );
        if bits_start == bits_end {
            return;
        }

        self.end = cmp::max(self.end, bits_end);

        let new_len = (bits_end + 63) / 64;
        if new_len > self.bits.len() {
            self.bits
                .extend(iter::repeat(0).take(new_len - self.bits.len()));
        }

        let start_idx = bits_start / 64;
        let end_idx = bits_end / 64;

        if start_idx == end_idx {
            let mut bitmask = u64::MAX;

            if bits_start % 64 > 0 {
                bitmask &= (1u64 << (bits_start % 64)) - 1;
            }

            if bits_end % 64 == 0 {
                bitmask = 0;
            } else {
                bitmask &= !((1u64 << (64 - (bits_end % 64))) - 1);
            }
            self.bits[start_idx] |= bitmask;
        } else {
            self.bits[start_idx] |= u64::MAX
                & if bits_start % 64 == 0 {
                    u64::MAX
                } else {
                    (1u64 << (bits_start % 64)) - 1
                };

            for curr_idx in start_idx + 1..end_idx {
                self.bits[curr_idx] = u64::MAX;
            }

            if bits_end % 64 > 0 {
                self.bits[end_idx] |= u64::MAX & !((1u64 << (64 - (bits_end % 64))) - 1);
            }
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.bits.clear();
        self.end = 0;
    }
}
*/

pub struct ArrayRing<T, const N: usize> {
    start: usize,
    arr: [Option<T>; N],
}

impl<T, const N: usize> default::Default for ArrayRing<T, N> {
    #[inline]
    fn default() -> Self {
        Self {
            start: 0,
            arr: array::from_fn(|_| None),
        }
    }
}

impl<T, const N: usize> ArrayRing<T, N> {
    #[inline]
    pub fn new() -> Self {
        ArrayRing::default()
    }

    #[inline]
    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= N {
            return None;
        }

        self.arr.get((self.start + idx) % N)?.as_ref()
    }

    #[inline]
    pub fn get_mut(&mut self, idx: usize) -> Option<&T> {
        if idx >= N {
            return None;
        }

        self.arr.get_mut((self.start + idx) % N)?.as_ref()
    }

    #[inline]
    pub fn insert(&mut self, elem: T, idx: usize) -> Option<T> {
        assert!(idx < N, "ArrayRing insert() index exceeded size of array");

        let mut ret = Some(elem);
        mem::swap(&mut self.arr[(self.start + idx) % N], &mut ret);
        ret
    }

    #[inline]
    pub fn remove(&mut self, idx: usize) -> Option<T> {
        assert!(idx < N, "ArrayRing remove() index exceeded size of array");

        let mut ret = None;
        mem::swap(&mut self.arr[(self.start + idx) % N], &mut ret);
        ret
    }

    pub fn pop_front(&mut self) -> Option<T> {
        if N == 0 {
            return None; // Who would ever want a 0-sized array...
        }

        let mut ret = None;
        mem::swap(&mut self.arr[0], &mut ret);
        if ret.is_some() {
            self.start = (self.start + 1) % N;
        }

        ret
    }
}
