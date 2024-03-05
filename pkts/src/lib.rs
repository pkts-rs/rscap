// Copyright 2022 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! A library for creating, decoding and modifying packet layers.
//!

#![allow(clippy::len_without_is_empty)]
#![allow(dead_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod layers;
pub mod prelude;
pub mod sequence;
pub mod sessions;
pub mod utils;

mod private {
    pub trait Sealed {}
}

pub struct Buffer<const N: usize> {
    buf: [u8; N],
    buf_len: usize,
}

impl<const N: usize> Buffer<N> {
    #[inline]
    pub fn new() -> Self {
        Self {
            buf: [0u8; N],
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

    #[inline]
    pub fn into_parts(self) -> ([u8; N], usize) {
        (self.buf, self.buf_len)
    }

    /// The length of the stored buffer.
    #[inline]
    pub fn len(&self) -> usize {
        self.buf_len
    }

    /// The number of unused bytes in the buffer.
    #[inline]
    pub fn remaining(&self) -> usize {
        N - self.buf_len
    }
}

#[cfg(test)]
mod tests {
    use crate::layers::ip::Ipv4;

    use crate::layers::udp::*;
    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::*;
    use crate::{parse_layers, Buffer};
    use crate::sequence::*;

    #[test]
    fn udp_builder() {
        let payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        
        let udp_builder = UdpBuilder::new()
            .sport(65321)
            .dport(443)
            .chksum(0)
            .payload_raw(&payload);

        let _buf: Buffer<65536> = match udp_builder.build() {
            Ok(buf) => buf,
            Err(e) => panic!("{:?}", e),
        };
    }


    #[test]
    fn from_the_layers() {
        let bytes = b"hello".as_slice();
        let _tcp = Tcp::from_bytes(bytes);

        let tcpref = TcpRef::from_bytes_unchecked(bytes);

        let _into_tcp: Tcp = tcpref.into();

        let _layers = parse_layers!(bytes, Tcp, Tcp, Ipv4).unwrap();

        //let layers = Tcp::from_layers(bytes, [Tcp, Ipv4, Tcp]);
    }

    #[test]
    fn multi_layer_sequence() {
        let ip1 = Ipv4Sequence::new();

        let mut _layered_seq = LayeredSequence::new(ip1, false)
            .add(Ipv4Sequence::new(), true)
            .add(Ipv4Sequence::new(), false)
            .add(Ipv4Sequence::new(), true);
    }
}
