//#![allow(clippy::upper_case_acronyms)]

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

    fn next<'a>(&'a mut self) -> Option<Self::Item<'a>>;
}

#[cfg(test)]
mod tests {
    use crate::layers::ip::{Ipv4, Ipv4Ref};
    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::FromBytes;
    use crate::layers::traits::FromBytesRef;
    use crate::layers::traits::LayerObject;
    use crate::layers::RawRef;
    use crate::parse_layers;

    #[test]
    fn from_the_layers() {
        let bytes = b"hello".as_slice();
        let tcp = Tcp::from_bytes(bytes);

        let tcpref = TcpRef::from_bytes_unchecked(bytes);

        let into_tcp: Tcp = tcpref.into();

        let layers = parse_layers!(bytes, Tcp, Tcp, Ipv4).unwrap();

        //let layers = Tcp::from_layers(bytes, [Tcp, Ipv4, Tcp]);
    }
}
