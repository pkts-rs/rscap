// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
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
#![forbid(unsafe_code)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod error;
pub mod layers;
#[doc(hidden)]
pub mod prelude;
pub mod sequence;
pub mod sessions;
pub mod utils;

use pkts_common::Buffer;

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use crate::layers::ip::Ipv4;

    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::*;
    use crate::layers::udp::*;
    use crate::parse_layers;
    use crate::sequence::*;
    use pkts_common::BufferMut;

    #[test]
    fn udp_builder() {
        let payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];

        let mut buffer = [0u8; 128];

        let udp_builder = UdpBuilder::new(&mut buffer)
            .sport(65321)
            .dport(443)
            .chksum(0)
            .payload_raw(&payload);

        let _buf: BufferMut<'_> = match udp_builder.build() {
            Ok(buf) => buf,
            Err(e) => panic!("{:?}", e),
        };
    }

    #[test]
    fn udp_builder_2() {
        let inner_payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        let mut buffer = [0u8; 100];

        let udp_builder = UdpBuilder::new(&mut buffer)
            .sport(65321)
            .dport(443)
            .chksum(0)
            .payload(|b| {
                UdpBuilder::from_buffer(b)
                    .sport(2452)
                    .dport(80)
                    .chksum(0)
                    .payload_raw(&inner_payload)
                    .build()
            });

        let _udp_packet = udp_builder.build().unwrap();
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
