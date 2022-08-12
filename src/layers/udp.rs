use crate::layers;
use crate::layers::traits::*;
use core::any;
use core::fmt::Debug;
use rscap_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(UdpAssociatedMetadata)]
#[ref_type(UdpRef)]
pub struct Udp {
    sport: u16,
    dport: u16,
    chksum: u16,
    #[payload_field]
    payload: Option<Box<dyn Layer>>,
}

impl ToBytes for Udp {
    fn to_bytes_extend(&self, bytes: &mut Vec<u8>) {
        let len: u16 = self
            .len()
            .try_into()
            .expect("UDP packet payload exceeded maximum permittable size of 2^16 bytes");
        bytes.extend(self.sport.to_be_bytes());
        bytes.extend(self.dport.to_be_bytes());
        bytes.extend(len.to_be_bytes());
        bytes.extend(self.chksum.to_be_bytes());
        match &self.payload {
            None => (),
            Some(p) => p.to_bytes_extend(bytes),
        }
    }
}

impl From<&UdpRef<'_>> for Udp {
    #[inline]
    fn from(value: &UdpRef<'_>) -> Self {
        Udp {
            sport: value.sport(),
            dport: value.dport(),
            chksum: value.chksum(),
            payload: Some(Box::new(layers::Raw::from_bytes_unchecked(value.payload()))),
        }
    }
}

impl LayerImpl for Udp {
    #[inline]
    fn can_set_payload_default(&self, _payload: Option<&dyn Layer>) -> bool {
        true // TODO: a TCP payload after UDP wouldn't do, would it? Because the checksum would have to be calculated with IP addresses?
    }

    #[inline]
    fn len(&self) -> usize {
        8 + match &self.payload {
            Some(p) => p.len(),
            None => 0,
        }
    }
}

impl Udp {
    #[inline]
    pub fn sport(&self) -> u16 {
        self.sport
    }

    #[inline]
    pub fn set_sport(&mut self, src_port: u16) {
        self.sport = src_port;
    }

    #[inline]
    pub fn dport(&self) -> u16 {
        self.dport
    }

    #[inline]
    pub fn set_dport(&mut self, dst_port: u16) {
        self.dport = dst_port;
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        self.chksum
    }

    #[inline]
    pub fn set_chksum(&mut self, chksum: u16) {
        self.chksum = chksum;
    }
}

#[derive(Clone, Debug, LayerRef, StatelessLayer)]
#[metadata_type(UdpAssociatedMetadata)]
#[owned_type(Udp)]
pub struct UdpRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> FromBytesRef<'a> for UdpRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        UdpRef { data: bytes }
    }
}

impl LayerByteIndexDefault for UdpRef<'_> {
    #[inline]
    fn get_layer_byte_index_default(_bytes: &[u8], layer_type: any::TypeId) -> Option<usize> {
        if any::TypeId::of::<layers::Raw>() == layer_type {
            Some(8)
        } else {
            None
        }
    }
}

impl UdpRef<'_> {
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(self.data[0..2].try_into().unwrap())
    }

    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(self.data[2..4].try_into().unwrap())
    }

    #[inline]
    pub fn packet_length(&self) -> u16 {
        u16::from_be_bytes(self.data[4..6].try_into().unwrap())
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(self.data[6..8].try_into().unwrap())
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data[8..]
    }
}

impl Validate for UdpRef<'_> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        if curr_layer.len() < 8 {
            return Err(ValidationError::InvalidSize);
        }
        let length_bytes: [u8; 2] = curr_layer[4..6].try_into().unwrap();
        let length = u16::from_be_bytes(length_bytes) as usize;
        if length > curr_layer.len() {
            Err(ValidationError::InvalidValue)
        } else if length < curr_layer.len() {
            Err(ValidationError::TrailingBytes(curr_layer.len() - length))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        // We always consider the next layer after UDP to be Raw
        layers::Raw::validate(&curr_layer[8..])
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[metadata_type(UdpAssociatedMetadata)]
#[owned_type(Udp)]
#[ref_type(UdpRef)]
pub struct UdpMut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    len: usize,
}

impl<'a> From<&'a UdpMut<'a>> for UdpRef<'a> {
    #[inline]
    fn from(value: &'a UdpMut<'a>) -> Self {
        UdpRef {
            data: &value.data[..value.len],
        }
    }
}

impl<'a> FromBytesMut<'a> for UdpMut<'a> {
    #[inline]
    fn from_bytes_trailing_unchecked(bytes: &'a mut [u8], length: usize) -> Self {
        UdpMut {
            len: length,
            data: bytes,
        }
    }
}

impl UdpMut<'_> {
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(self.data[0..2].try_into().unwrap())
    }

    #[inline]
    pub fn set_sport(&mut self, src_port: u16) {
        let src_port_bytes = src_port.to_be_bytes();
        self.data[0] = src_port_bytes[0];
        self.data[1] = src_port_bytes[1];
    }

    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(self.data[2..4].try_into().unwrap())
    }

    #[inline]
    pub fn set_dport(&mut self, dst_port: u16) {
        let dst_port_bytes = dst_port.to_be_bytes();
        self.data[2] = dst_port_bytes[0];
        self.data[3] = dst_port_bytes[1];
    }

    #[inline]
    pub fn packet_length(&self) -> u16 {
        u16::from_be_bytes(self.data[4..6].try_into().unwrap())
    }

    #[inline]
    pub fn set_packet_length(&mut self, len: u16) {
        let len_bytes = len.to_be_bytes();
        self.data[4] = len_bytes[0];
        self.data[5] = len_bytes[1];
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(self.data[6..8].try_into().unwrap())
    }

    #[inline]
    pub fn set_chksum(&mut self, chksum: u16) {
        let chksum_bytes = chksum.to_be_bytes();
        self.data[6] = chksum_bytes[0];
        self.data[7] = chksum_bytes[1];
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data[8..self.len]
    }

    #[inline]
    pub fn set_payload_unchecked(&mut self, payload: &[u8]) {
        let dst = &mut self.data[8..8 + payload.len()];
        for i in 0..payload.len() {
            dst[8 + i] = payload[i];
        }
        self.len = 8 + payload.len();
    }
}
