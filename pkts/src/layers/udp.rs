// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The User Datagram Protocol (UDP) layer and related data structures.
//!
//! UDP is a Transport Layer protocol that allows for unreliable transfer of datagrams over an IP
//! network. It provides weak assurance of data correctness via a 16-bit one's complement checksum
//! and preserves message boundaries, but does not guarantee delivery or provide any built-in
//! mechanism for packet acknowledgement or retransmission.
//!
//! A UDP layer can be represented directly with [`struct@Udp`], or referenced from a byte array
//! with [`UdpRef`]. UDP packets can be constructed from scratch using either [`Udp::new()`] (which
//! may use heap allocations) or [`UdpBuilder`], which constructs a UDP packet entirely within
//! a stack-allocated byte array.
use crate::layers::dev_traits::*;
use crate::layers::traits::*;
use crate::layers::Raw;
use crate::Buffer;
use crate::{error::*, utils};

use pkts_macros::{Layer, LayerRef, StatelessLayer};

use core::fmt::Debug;
use std::{cmp, slice};

use super::ip::{Ipv4, Ipv6, DATA_PROTO_UDP};

/// A UDP (User Datagram Protocol) packet.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |          Source Port          |        Destination Port       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |             Length            |            Checksum           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 Z                            Payload                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(UdpMetadata)]
#[ref_type(UdpRef)]
pub struct Udp {
    sport: u16,
    dport: u16,
    chksum: Option<u16>,
    payload: Option<Box<dyn LayerObject>>,
}

impl Default for Udp {
    fn default() -> Self {
        Self::new()
    }
}

impl Udp {
    /// Construct a new UDP packet.
    ///
    /// The default UDP packet contains a source and destination port of 0, no set checksum, and no
    /// payload.
    #[inline]
    pub fn new() -> Self {
        Self {
            sport: 0,
            dport: 0,
            chksum: None,
            payload: None,
        }
    }

    /// The source port of the UDP packet.
    #[inline]
    pub fn sport(&self) -> u16 {
        self.sport
    }

    /// Sets the source port of the UDP packet.
    #[inline]
    pub fn set_sport(&mut self, src_port: u16) {
        self.sport = src_port;
    }

    /// The destination port of the UDP packet.
    #[inline]
    pub fn dport(&self) -> u16 {
        self.dport
    }

    /// Sets the destination port of the UDP packet.
    #[inline]
    pub fn set_dport(&mut self, dst_port: u16) {
        self.dport = dst_port;
    }

    /// Retrieves the assigned checksum for the packet, or `None` if no checksum has explicitly
    /// been assigned to the packet.
    ///
    /// By default, the UDP checksum is automatically calculated when a [`struct@Udp`] instance is
    /// converted to bytes, unless a checksum is pre-assigned to the instance prior to conversion.
    /// If a checksum has already been assigned to the packet, this method will return it;
    /// otherwise, it will return `None`. This means that a [`struct@Udp`] instance created from
    /// bytes or from a [`UdpRef`] instance will still have a checksum of `None` by default,
    /// regardless of the checksum value of the underlying bytes it was created from.
    #[inline]
    pub fn chksum(&self) -> Option<u16> {
        self.chksum
    }

    /// Assigns a checksum to be used for the packet.
    ///
    /// By default, the UDP checksum is automatically calculated when a [`struct@Udp`] instance is
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
    /// [`struct@Udp`] instance whenever the packet is converted to bytes. You shouldn't need to
    /// call this method unless you've previously explicitly assigned a checksum to the
    /// packet--either through a call to [`set_chksum()`](Udp::set_chksum()) or through a Builder
    /// pattern. Packets converted from bytes into [`struct@Udp`] instances from bytes or from a
    /// [`UdpRef`] instance will have a checksum of `None` by default.
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
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        true // TODO: a TCP payload after UDP wouldn't do, would it? Because the checksum would have to be calculated with IP addresses?
    }

    #[inline]
    fn add_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        self.payload = Some(payload);
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        match &self.payload {
            Some(payload) => slice::from_ref(payload),
            None => &[],
        }
    }

    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        match &mut self.payload {
            Some(payload) => slice::from_mut(payload),
            None => &mut [],
        }
    }

    fn remove_payload_at(&mut self, index: usize) -> Option<Box<dyn LayerObject>> {
        if index != 0 {
            return None;
        }

        let mut ret = None;
        core::mem::swap(&mut ret, &mut self.payload);
        ret
    }
}

impl ToBytes for Udp {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
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
            Some(p) => p.to_bytes_checksummed(bytes, Some((Self::layer_id(), start)))?,
        }

        if self.chksum.is_none() {
            let Some((id, prev_idx)) = prev else {
                return Err(SerializationError::bad_upper_layer());
            };

            let new_chksum = if id == Ipv4::layer_id() {
                let mut data_chksum: u16 = utils::ones_complement_16bit(&bytes[start..]);
                let addr_chksum =
                    utils::ones_complement_16bit(&bytes[prev_idx + 12..prev_idx + 20]);
                data_chksum = utils::ones_complement_add(data_chksum, addr_chksum);
                data_chksum = utils::ones_complement_add(data_chksum, DATA_PROTO_UDP as u16);
                let upper_layer_len = (bytes.len() - start) as u16;
                data_chksum = utils::ones_complement_add(data_chksum, upper_layer_len);

                data_chksum
            } else if id == Ipv6::layer_id() {
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
                return Ok(()); // Leave the checksum as 0--we don't have an IPv4/IPv6 pseudo-header, so we can't calculate it
            };

            let chksum_field: &mut [u8; 2] = &mut bytes[start + 6..start + 8].try_into().unwrap();
            *chksum_field = new_chksum.to_be_bytes();
        }

        Ok(())
    }
}

impl FromBytesCurrent for Udp {
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

/// A UDP (User Datagram Protocol) packet.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |          Source Port          |        Destination Port       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |             Length            |            Checksum           |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 Z                            Payload                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
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

#[doc(hidden)]
impl LayerOffset for UdpRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        if layer_type == Raw::layer_id() {
            Some(8)
        } else {
            None
        }
    }
}

impl UdpRef<'_> {
    /// The source port of the UDP packet.
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(
            self.data
                .get(0..2)
                .expect("insufficient bytes in UDP packet to retrieve Source Port field")
                .try_into()
                .unwrap(),
        )
    }

    /// The destination port of the UDP packet.
    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(
            self.data
                .get(2..4)
                .expect("insufficient bytes in UDP packet to retrieve Destination Port field")
                .try_into()
                .unwrap(),
        )
    }

    /// The combined length (in bytes) of the UDP header and payload.
    #[inline]
    pub fn packet_length(&self) -> u16 {
        u16::from_be_bytes(
            self.data
                .get(4..6)
                .expect("insufficient bytes in UDP packet to retrieve Packet Length field")
                .try_into()
                .unwrap(),
        )
    }

    /// The one's complement Checksum field of the packet.
    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(
            self.data
                .get(6..8)
                .expect("insufficient bytes in UDP packet to retrieve Checksum field")
                .try_into()
                .unwrap(),
        )
    }

    /// The payload data of the UDP packet.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        self.data
            .get(8..)
            .expect("insufficient bytes in UDP packet to retrieve payload data")
    }
}

impl Validate for UdpRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        match curr_layer.get(4..6) {
            Some(len_slice) => {
                let len_bytes: [u8; 2] = len_slice.try_into().unwrap();
                let length = u16::from_be_bytes(len_bytes) as usize;
                match length.cmp(&curr_layer.len()) {
                    cmp::Ordering::Greater => Err(ValidationError {
                        layer: Udp::name(),
                        class: ValidationErrorClass::InsufficientBytes,
                        reason: "insufficient bytes for payload length advertised by UDP header",
                    }),
                    cmp::Ordering::Less => Err(ValidationError {
                        layer: Udp::name(),
                        class: ValidationErrorClass::ExcessBytes(curr_layer.len() - length),
                        reason:
                            "more bytes in packet than advertised by the UDP header length field",
                    }),
                    cmp::Ordering::Equal => Ok(()),
                }
            }
            None => Err(ValidationError {
                layer: Udp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                reason: "insufficient bytes in UDP header (8 bytes required)",
            }),
        }
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        // We always consider the next layer after UDP to be `Raw`
        Raw::validate(&curr_layer[8..])
    }
}

// =============================================================================
//                                 UDP Builder
// =============================================================================

#[doc(hidden)]
pub trait UdpBuildPhase {}

#[doc(hidden)]
pub struct UdpBuildSrcPort;

impl UdpBuildPhase for UdpBuildSrcPort {}

#[doc(hidden)]
pub struct UdpBuildDstPort;

impl UdpBuildPhase for UdpBuildDstPort {}

#[doc(hidden)]
pub struct UdpBuildChksum;

impl UdpBuildPhase for UdpBuildChksum {}

#[doc(hidden)]
pub struct UdpBuildPayload;

impl UdpBuildPhase for UdpBuildPayload {}

#[doc(hidden)]
pub struct UdpBuildFinal;

impl UdpBuildPhase for UdpBuildFinal {}

/// A Builder type for UDP packets, with configurable maximum bytearray size.
///
/// This struct employs a type-enforced Builder pattern, meaning that each step of building the
/// UDP packet is represented by a distinct type in the generic type `T`. In practical terms,
/// this simply means that you can build a UDP packet one field at a time without having to
/// worry about getting ordering wrong or missing fields--any errors of this kind will be caught
/// by the compiler.
///
/// # Example
///
/// ```
/// use pkts::prelude::*;
/// use pkts::layers::udp::UdpBuilder;
///
/// let payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
///
/// let udp_builder = UdpBuilder::new()
///     .sport(65321)
///     .dport(443)
///     .chksum(0)
///     .payload_raw(&payload);
///
/// let udp_packet: Buffer<65536> = match udp_builder.build().unwrap();
/// ```
///
pub struct UdpBuilder<T: UdpBuildPhase, const N: usize> {
    data: Buffer<N>,
    layer_start: usize,
    error: Option<ValidationError>,
    phase: T,
}

impl<const N: usize> Default for UdpBuilder<UdpBuildSrcPort, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> UdpBuilder<UdpBuildSrcPort, N> {
    #[inline]
    pub fn new() -> Self {
        Self {
            layer_start: 0,
            data: Buffer::new(),
            error: None,
            phase: UdpBuildSrcPort,
        }
    }

    pub fn from_buffer(buffer: Buffer<N>) -> Self {
        Self {
            layer_start: buffer.len(),
            data: buffer,
            error: None,
            phase: UdpBuildSrcPort,
        }
    }

    pub fn sport(mut self, sport: u16) -> UdpBuilder<UdpBuildDstPort, N> {
        if self.error.is_none() {
            if self.data.remaining() >= 2 {
                self.data.append(&sport.to_be_bytes());
            } else {
                self.error = Some(ValidationError {
                    layer: Udp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    reason: "UDP Source Port serialization exceeded available buffer size",
                });
            }
        }

        UdpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: UdpBuildDstPort,
        }
    }
}

impl<const N: usize> UdpBuilder<UdpBuildDstPort, N> {
    pub fn dport(mut self, dport: u16) -> UdpBuilder<UdpBuildChksum, N> {
        if self.error.is_none() {
            if self.data.remaining() >= 2 {
                self.data.append(&dport.to_be_bytes());
            } else {
                self.error = Some(ValidationError {
                    layer: Udp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    reason: "UDP Destination Port serialization exceeded available buffer size",
                });
            }
        }

        UdpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: UdpBuildChksum,
        }
    }
}

impl<const N: usize> UdpBuilder<UdpBuildChksum, N> {
    pub fn chksum(mut self, chksum: u16) -> UdpBuilder<UdpBuildPayload, N> {
        if self.error.is_none() {
            if self.data.remaining() >= 4 {
                // Pad `length` field with 0s for now--it is filled later
                self.data.append(&[0u8; 2]);
                self.data.append(&chksum.to_be_bytes());
            } else {
                self.error = Some(ValidationError {
                    layer: Udp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    reason: "UDP Checksum serialization exceeded available buffer size",
                });
            }
        }

        UdpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: UdpBuildPayload,
        }
    }
}

impl<const N: usize> UdpBuilder<UdpBuildPayload, N> {
    /// Add a payload consisting of raw bytes to the UDP packet.
    pub fn payload_raw(mut self, data: &[u8]) -> UdpBuilder<UdpBuildFinal, N> {
        'insert_data: {
            if self.error.is_some() {
                break 'insert_data;
            }

            if self.data.remaining() < data.len() {
                self.error = Some(ValidationError {
                    layer: Udp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    reason: "UDP Payload serialization exceeded available buffer size",
                });
                break 'insert_data;
            }

            let Ok(data_len) = u16::try_from(data.len() + 8) else {
                self.error = Some(ValidationError {
                    layer: Udp::name(),
                    class: ValidationErrorClass::InvalidSize,
                    reason: "UDP Payload serialization exceeded UDP maximum possible length",
                });
                break 'insert_data;
            };

            let len_start = self.layer_start + 4;
            let len_end = self.layer_start + 6;

            // Set data length field
            self.data.as_mut_slice()[len_start..len_end].copy_from_slice(&data_len.to_be_bytes());

            // Set data
            self.data.append(data);
        }

        UdpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: UdpBuildFinal,
        }
    }

    /// Add a payload to the UDP packet.
    ///
    /// The UDP packet's payload is constructed via the user-provided `payload_build_fn` closure;
    /// several consecutive layers can be constructed at once using these closures in a nested
    /// manner.
    pub fn payload(
        self,
        payload_build_fn: impl FnOnce(Buffer<N>) -> Result<Buffer<N>, ValidationError>,
    ) -> Result<Buffer<N>, ValidationError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let mut data = payload_build_fn(self.data)?;
        let Ok(data_len) = u16::try_from(data.len() - self.layer_start) else {
            return Err(ValidationError {
                layer: Udp::name(),
                class: ValidationErrorClass::InvalidSize,
                reason: "UDP Payload serialization exceeded UDP maximum possible length",
            });
        };

        let len_start = self.layer_start + 4;
        let len_end = self.layer_start + 6;

        // Set data length field
        data.as_mut_slice()[len_start..len_end].copy_from_slice(&data_len.to_be_bytes());
        Ok(data)
    }
}

impl<const N: usize> UdpBuilder<UdpBuildFinal, N> {
    #[inline]
    pub fn build(self) -> Result<Buffer<N>, ValidationError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.data),
        }
    }
}
