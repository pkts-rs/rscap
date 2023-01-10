#![allow(clippy::len_without_is_empty)]
#![allow(dead_code)]

pub mod defrag;
pub mod error;
pub mod layers;
pub mod sessions;
pub mod utils;

mod private {
    pub trait Sealed {}
}

pub trait LendingIterator {
    type Item<'a>
    where
        Self: 'a;

    fn next(&mut self) -> Option<Self::Item<'_>>;
}

#[cfg(test)]
mod tests {
    use crate::layers::ip::Ipv4;
    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::FromBytes;
    use crate::layers::traits::FromBytesRef;
    use crate::layers::traits::LayerObject;
    use crate::parse_layers;

    #[test]
    fn from_the_layers() {
        let bytes = b"hello".as_slice();
        let _tcp = Tcp::from_bytes(bytes);

        let tcpref = TcpRef::from_bytes_unchecked(bytes);

        let _into_tcp: Tcp = tcpref.into();

        let _layers = parse_layers!(bytes, Tcp, Tcp, Ipv4).unwrap();

        //let layers = Tcp::from_layers(bytes, [Tcp, Ipv4, Tcp]);
    }
}
