#![allow(clippy::upper_case_acronyms)]

mod layers;

mod private {
    pub trait Sealed {}
}

#[cfg(test)]
mod tests {
    use crate::layers::inet::{Ipv4, Ipv4Ref};
    use crate::layers::tcp::{Tcp, TcpMut};
    use crate::layers::traits::{FromBytes, FromBytesMut};
    use crate::layers::udp::Udp;

    #[test]
    fn indexable() {
        let mut t: Tcp = Tcp {
            sport: 32,
            dport: 21,
            payload: None,
        };
        //let t2 = t.get_layer_mut::<TCP>();
        let t2 = &mut t[Tcp];

        let t3 = &t2[Udp];
        print!("{:?}", &t3.dport);
    }

    #[test]
    fn div() {
        let mut ip = Ipv4::from_bytes_unchecked(b"012");

        let tcp: Tcp = Tcp {
            sport: 32,
            dport: 21,
            payload: None,
        };

        ip /= tcp.clone();
        let tunneled = ip / tcp;

        let t = &tunneled[Tcp];

        let ip2 = Ipv4Ref::from_bytes_unchecked(b"01234");

        let retunneled = ip2.clone() / tunneled;

        let mut data = [0u8; 7];
        let tcp2 = TcpMut::from_bytes_unchecked(data.as_mut());
        let t3 = ip2 / tcp2;
    }
}
