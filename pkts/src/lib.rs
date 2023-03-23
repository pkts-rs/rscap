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
pub mod sequence;
pub mod sessions;
pub mod utils;

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use crate::layers::ip::Ipv4;
    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::extras::*;
    use crate::layers::traits::*;
    use crate::parse_layers;
    use crate::sequence::*;

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

        let mut layered_seq = LayeredSequence::new(ip1, false)
            .add(Ipv4Sequence::new(), true)
            .add(Ipv4Sequence::new(), false)
            .add(Ipv4Sequence::new(), true);
    }
}
