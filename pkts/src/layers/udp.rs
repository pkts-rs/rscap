// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me@nathanielbennett.com>

//! The User Datagram Protocol (UDP) layer and its related fields.

use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::layers::{Raw, RawRef};
use crate::{error::*, utils};

use pkts_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use core::fmt::Debug;
use std::cmp;

use super::ip::{Ipv4Ref, Ipv6Ref, DATA_PROTO_UDP};

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(UdpMetadata)]
#[ref_type(UdpRef)]
pub struct Udp {
    sport: u16,
    dport: u16,
    chksum: Option<u16>,
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

    /// Retrieves the assigned checksum for the packet, or `None` if no checksum has explicitly
    /// been assigned to the packet.
    /// 
    /// By default, the UDP checksum is automatically calculated when a [`Udp`] instance is
    /// converted to bytes, unless a checksum is pre-assigned to the instance prior to conversion.
    /// If a checksum has already been assigned to the packet, this method will return it;
    /// otherwise, it will return `None`. This means that a [`Udp`] instance created from bytes
    /// or from a [`UdpRef`] instance will still have a checksum of `None` by default, regardless
    /// of the checksum value of the underlying bytes it was created from.
    #[inline]
    pub fn chksum(&self) -> Option<u16> {
        self.chksum
    }

    /// Assigns a checksum to be used for the packet.
    ///
    /// By default, the UDP checksum is automatically calculated when a [`Udp`] instance is
    /// converted to bytes. This method overrides that behavior so that the provided checksum is
    /// used instead. You generally shouldn't need to use this method unless:
    ///   1. You know the expected checksum of the packet in advance and don't want the checksum
    ///      calculation to automatically run again (since it can be a costly operation), or
    ///   2. Checksum offloading is being employed for the UDP packet and you want to zero out the
    ///      checksum field (again, avoiding unnecessary extra computation), or
    ///   3. You want to explicitly set an invalid checksum.
    #[inline]
    pub fn set_chksum(&mut self, chksum: u16) {
        self.chksum = Some(chksum);
    }

    /// Clears any previously assigned checksum for the packet.
    /// 
    /// This method guarantees that the UDP checksum will be automatically calculated for this
    /// [`Udp`] instance whenever the packet is converted to bytes. You shouldn't need to call
    /// this method unless you've previously explicitly assigned a checksum to the packet--either
    /// through a call to [`Udp::set_chksum()`] or through a Builder pattern. Packets converted
    /// from bytes into [`Udp`] instances from bytes or from a [`UdpRef`] instance will have a 
    /// checksum of `None` by default.
    #[inline]
    pub fn clear_chksum(&mut self) {
        self.chksum = None;
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
    fn to_bytes_chksummed(&self, bytes: &mut Vec<u8>, prev: Option<(LayerId, usize)>) {
        let start = bytes.len();
        let len: u16 = self
            .len()
            .try_into()
            .expect("UDP packet payload exceeded maximum permittable size of 65535 bytes");
        bytes.extend(self.sport.to_be_bytes());
        bytes.extend(self.dport.to_be_bytes());
        bytes.extend(len.to_be_bytes());
        bytes.extend(self.chksum.unwrap_or(0).to_be_bytes());
        match &self.payload {
            None => (),
            Some(p) => p.to_bytes_chksummed(bytes, Some((UdpRef::layer_id_static(), start))),
        }

        if self.chksum.is_none() {
            if let Some((id, prev_idx)) = prev {
                let new_chksum = if id == Ipv4Ref::layer_id_static() {
                    let mut data_chksum: u16 = utils::ones_complement_16bit(&bytes[start..]);
                    let addr_chksum =
                        utils::ones_complement_16bit(&bytes[prev_idx + 12..prev_idx + 20]);
                    data_chksum = utils::ones_complement_add(data_chksum, addr_chksum);
                    data_chksum = utils::ones_complement_add(data_chksum, DATA_PROTO_UDP as u16);
                    let upper_layer_len = (bytes.len() - start) as u16;
                    data_chksum = utils::ones_complement_add(data_chksum, upper_layer_len);

                    data_chksum
                } else if id == Ipv6Ref::layer_id_static() {
                    let mut data_chksum: u16 = utils::ones_complement_16bit(&bytes[start..]);
                    let addr_chksum =
                        utils::ones_complement_16bit(&bytes[prev_idx + 16..prev_idx + 40]);
                    data_chksum = utils::ones_complement_add(data_chksum, addr_chksum);
                    let upper_layer_len = (bytes.len() - start) as u32;
                    data_chksum =
                        utils::ones_complement_add(data_chksum, (upper_layer_len >> 16) as u16);
                    data_chksum =
                        utils::ones_complement_add(data_chksum, (upper_layer_len & 0xFFFF) as u16);
                    // Omit adding 0, it does nothing anyways
                    data_chksum = utils::ones_complement_add(data_chksum, DATA_PROTO_UDP as u16);

                    data_chksum
                } else {
                    return; // Leave the checksum as 0--we don't have an IPv4/IPv6 pseudo-header, so we can't calculate it
                };

                let chksum_field: &mut [u8; 2] =
                    &mut bytes[start + 6..start + 8].try_into().unwrap();
                *chksum_field = new_chksum.to_be_bytes();
            }
            // else don't bother calculating the checksum
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
            chksum: None,
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

    /// The one's complement Checksum field of the packet.
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

    /// The one's complement Checksum field of the packet.
    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(self.data[6..8].try_into().unwrap())
    }

    /// Sets the one's complement checksum to be used for the packet.
    ///
    /// Checksums are _not_ automatically generated for [`UdpMut`] instances,
    /// so any changes in a UDP packet's contents--including source or destination
    /// IP address or IP protocol type--should be followed by a corresponding change
    /// in the checksum as well. Checksums _are_ automatically generated for [`Udp`]
    /// instances, so consider using it instead of this interface if ease of use is
    /// more of a priority than raw speed and performance.
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
