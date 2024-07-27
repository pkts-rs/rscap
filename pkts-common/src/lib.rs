// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![forbid(unsafe_code)]

use core::array;

#[derive(Clone, Debug)]
pub struct Buffer<T: Copy, const N: usize> {
    buf: [T; N],
    buf_len: usize,
}

impl<T: Copy + Default, const N: usize> Buffer<T, N> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &self.buf[..self.buf_len]
    }

    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.buf[..self.buf_len]
    }

    /// Appends the provided bytes to the buffer, panicking if insufficient space is available in
    /// the buffer.
    #[inline]
    pub fn append(&mut self, slice: &[T]) {
        self.buf[self.buf_len..self.buf_len + slice.len()].copy_from_slice(slice);
        self.buf_len += slice.len();
    }

    /// Truncates the buffer to the specified position.
    pub fn truncate(&mut self, pos: usize) {
        assert!(self.buf_len >= pos);
        self.buf_len = pos;
    }

    #[inline]
    pub fn into_parts(self) -> ([T; N], usize) {
        (self.buf, self.buf_len)
    }

    /// The length of the stored buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf_len == 0
    }

    /// The number of unused bytes in the buffer.
    #[inline]
    pub fn remaining(&self) -> usize {
        N - self.buf_len
    }
}

impl<T: Copy + Default, const N: usize> Default for Buffer<T, N> {
    #[inline]
    fn default() -> Self {
        Self {
            buf: array::from_fn(|_| T::default()),
            buf_len: 0,
        }
    }
}

#[derive(Debug)]
pub struct BufferMut<'a> {
    buf: &'a mut [u8],
    buf_len: usize,
}

impl<'a> BufferMut<'a> {
    #[inline]
    pub fn new(slice: &'a mut [u8]) -> Self {
        Self {
            buf: slice,
            buf_len: 0,
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.buf_len]
    }

    
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buf[..self.buf_len]
    }
    

    /// Appends the provided bytes to the buffer, panicking if insufficient space is available in
    /// the buffer.
    #[inline]
    pub fn append(&mut self, bytes: &[u8]) {
        self.buf[self.buf_len..self.buf_len + bytes.len()].copy_from_slice(bytes);
        self.buf_len += bytes.len();
    }

    /// Appends the provided bytes to the buffer, returning `error` if insufficient space is
    /// available in the buffer.
    #[inline]
    pub fn append_or<T>(&mut self, bytes: &[u8], error: T) -> Result<(), T> {
        let buf_slice = self.buf.get_mut(self.buf_len..self.buf_len + bytes.len()).ok_or(error)?;
        buf_slice.copy_from_slice(bytes);
        self.buf_len += bytes.len();
        Ok(())
    }

    /// Appends the provided bytes to the buffer, panicking if insufficient space is available in
    /// the buffer.
    #[inline]
    pub fn try_append(&mut self, bytes: &[u8]) -> Option<()> {
        if self.remaining() < bytes.len() {
            return None
        } else {
            self.append(bytes);
            return Some(())       
        }
    }

    /// Truncates the buffer to the specified position.
    pub fn truncate(&mut self, pos: usize) {
        assert!(self.buf_len >= pos);
        self.buf_len = pos;
    }

    #[inline]
    pub fn to_mut_slice(self) -> &'a mut [u8] {
        &mut self.buf[..self.buf_len]
    }

    /// The length of the stored buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf_len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.buf_len == 0
    }

    /// The number of unused bytes in the buffer.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.buf_len
    }
}
