//#![allow(clippy::upper_case_acronyms)]

pub mod defrag;
pub mod layers;
pub mod sessions;
pub mod utils;

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use crate::to_layers;
    use crate::layers::ip::{Ipv4, Ipv4Ref};
    use crate::layers::tcp::{Tcp, TcpRef};
    use crate::layers::traits::FromBytesRef;
    use crate::layers::traits::FromBytes;
    use crate::layers::RawRef;
    use crate::layers::traits::Layer;


    fn than<'wootchlife>(homeslice: &'wootchlife [u8]) -> RawRef<'wootchlife> {
        let wootch: RawRef = RawRef::from_bytes_unchecked(homeslice);
        return wootch;
    }

    #[test]
    fn from_the_layers() {
        let bytes = b"herro".as_slice();
        let tcp = Tcp::from_bytes(bytes);

        let layers = to_layers!(bytes, Tcp, Tcp, Ipv4);

        //let layers = Tcp::from_layers(bytes, [Tcp, Ipv4, Tcp]);
    }
}
