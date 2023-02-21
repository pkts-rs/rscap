use crate::error::*;
use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::layers::{Raw, RawRef};

use rscap_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use core::fmt::Debug;
use std::cmp;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(UdpMetadata)]
#[ref_type(UdpRef)]
pub struct Udp {
    sport: u16,
    dport: u16,
    chksum: u16,
    payload: Option<Box<dyn LayerObject>>,
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

impl LayerLength for Udp {
    #[inline]
    fn len(&self) -> usize {
        8 + match self.payload.as_ref() {
            Some(p) => p.len(),
            None => 0,
        }
    }
}

impl LayerObject for Udp {
    #[inline]
    fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
        self.payload.as_ref().map(|p| p.as_ref())
    }

    #[inline]
    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        self.payload.as_mut().map(|p| p.as_mut())
    }

    #[inline]
    fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        self.payload = Some(payload);
    }

    #[inline]
    fn has_payload(&self) -> bool {
        self.payload.is_some()
    }

    #[inline]
    fn remove_payload(&mut self) -> Box<dyn LayerObject> {
        let mut ret = None;
        core::mem::swap(&mut ret, &mut self.payload);
        self.payload = None;
        ret.expect("remove_payload() called on UDP layer when layer had no payload")
    }
}

impl ToBytes for Udp {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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
            Some(p) => p.to_bytes_extended(bytes),
        }
    }
}

impl FromBytesCurrent for Udp {
    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let udp = UdpRef::from_bytes_unchecked(bytes);
        Udp {
            sport: udp.sport(),
            dport: udp.dport(),
            chksum: udp.chksum(),
            payload: None,
        }
    }

    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        self.payload = match bytes.len() {
            0..=8 => None,
            _ => Some(Box::new(Raw::from_bytes_unchecked(&bytes[8..]))),
        }
    }
}

impl CanSetPayload for Udp {
    #[inline]
    fn can_set_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        true // TODO: a TCP payload after UDP wouldn't do, would it? Because the checksum would have to be calculated with IP addresses?
    }
}

#[derive(Clone, Debug, LayerRef, StatelessLayer)]
#[metadata_type(UdpMetadata)]
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

impl LayerOffset for UdpRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        if layer_type == RawRef::layer_id_static() {
            Some(8)
        } else {
            None
        }
    }
}

impl UdpRef<'_> {
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(
            self.data[0..2]
                .try_into()
                .expect("insufficient bytes in UdpRef to retrieve source port"),
        )
    }

    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(
            self.data[2..4]
                .try_into()
                .expect("insufficient bytes in UdpRef to retrieve destination port"),
        )
    }

    #[inline]
    pub fn packet_length(&self) -> u16 {
        u16::from_be_bytes(
            self.data[4..6]
                .try_into()
                .expect("insufficient bytes in UdpRef to retrieve packet length"),
        )
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(
            self.data[6..8]
                .try_into()
                .expect("insufficient bytes in UdpRef to retrieve checksum"),
        )
    }

    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.data
            .get(8..)
            .expect("insufficient bytes in UdpRef to retrieve payload")
    }
}

impl Validate for UdpRef<'_> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        match curr_layer.get(4..6) {
            Some(len_slice) => {
                let len_bytes: [u8; 2] = len_slice.try_into().unwrap();
                let length = u16::from_be_bytes(len_bytes) as usize;
                match length.cmp(&curr_layer.len()) {
                    cmp::Ordering::Greater => Err(ValidationError {
                        layer: Udp::name(),
                        err_type: ValidationErrorType::InsufficientBytes,
                        reason: "insufficient bytes for payload length advertised by UDP header",
                    }),
                    cmp::Ordering::Less => Err(ValidationError {
                        layer: Udp::name(),
                        err_type: ValidationErrorType::ExcessBytes(curr_layer.len() - length),
                        reason:
                            "more bytes in packet than advertised by the UDP header length field",
                    }),
                    cmp::Ordering::Equal => Ok(()),
                }
            }
            None => Err(ValidationError {
                layer: Udp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in UDP header (8 bytes required)",
            }),
        }
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        // We always consider the next layer after UDP to be `Raw`
        Raw::validate(&curr_layer[8..])
    }
}

impl<'a> From<&'a UdpMut<'a>> for UdpRef<'a> {
    #[inline]
    fn from(value: &'a UdpMut<'a>) -> Self {
        UdpRef {
            data: &value.data[..value.len],
        }
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[metadata_type(UdpMetadata)]
#[owned_type(Udp)]
#[ref_type(UdpRef)]
pub struct UdpMut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    len: usize,
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
        let payload_location = self
            .data
            .get_mut(8..8 + payload.len())
            .expect("insufficient bytes in UdpMut buffer to set payload");
        for (&src, dst) in payload.iter().zip(payload_location) {
            *dst = src;
        }
        self.len = 8 + payload.len();
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
