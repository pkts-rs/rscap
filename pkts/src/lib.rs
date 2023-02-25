// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <contact@rscap.org>

//! A library for creating, decoding and modifying packet layers.
//! 

#![allow(clippy::len_without_is_empty)]
#![allow(dead_code)]

pub mod sequence;
pub mod error;
pub mod layers;
pub mod sessions;
pub mod utils;

mod private {
    pub trait Sealed {}
}


pub trait LendingIterator<'a> {
    type Item: 'a;

    fn next(&mut self) -> Option<Self::Item>;
}

/*
pub trait LendingIterator {
    type Item<'a>
    where
        Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>>;
}
*/


#[cfg(test)]
mod tests {
    use crate::layers::ip::Ipv4;
    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::*;
    use crate::layers::traits::extras::*;
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
