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

use core::fmt::Debug;
use core::{cmp, slice};

use super::ip::{Ipv4, Ipv6, DATA_PROTO_UDP};
use crate::layers::dev_traits::*;
use crate::layers::traits::*;
use crate::layers::Raw;
use crate::{error::*, utils};

use pkts_common::BufferMut;
use pkts_macros::{Layer, LayerRef, StatelessLayer};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

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
    #[inline]
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

    #[inline]
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
            .map_err(|_| SerializationError::length_encoding(Udp::name()))?;
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
                return Err(SerializationError::bad_upper_layer(Udp::name()));
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

// TODO: this API needs to be revised for multi-payload `Layer`s...
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
        u16::from_be_bytes(self.data[0..2].try_into().unwrap())
    }

    /// The destination port of the UDP packet.
    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(self.data[2..4].try_into().unwrap())
    }

    /// The combined length (in bytes) of the UDP header and payload.
    #[inline]
    pub fn packet_length(&self) -> u16 {
        u16::from_be_bytes(self.data[4..6].try_into().unwrap())
    }

    /// The one's complement Checksum field of the packet.
    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(self.data[6..8].try_into().unwrap())
    }

    /// The payload data of the UDP packet.
    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data[8..]
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
                        #[cfg(feature = "error_string")]
                        reason: "insufficient bytes for payload length advertised by UDP header",
                    }),
                    cmp::Ordering::Less => Err(ValidationError {
                        layer: Udp::name(),
                        class: ValidationErrorClass::ExcessBytes(curr_layer.len() - length),
                        #[cfg(feature = "error_string")]
                        reason:
                            "more bytes in packet than advertised by the UDP header length field",
                    }),
                    cmp::Ordering::Equal => Ok(()),
                }
            }
            None => Err(ValidationError {
                layer: Udp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes for UDP header",
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
//                             UDP `Builder` Pattern
// =============================================================================

mod sealed {
    #[doc(hidden)]
    pub trait UdpBuildPhase {}
}
use sealed::UdpBuildPhase;

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

///  Constructs a UDP packet directly onto a mutable slice.
///
/// This struct employs a type-enforced Builder pattern, meaning that each step of building the
/// UDP packet is represented by a distinct type `T`. In practical terms, this simply means that
/// you can build a UDP packet one field at a time without having to worry about getting ordering
/// wrong or missing fields--any errors of this kind will be caught by the compiler.
///
/// # Example
///
/// ```
/// use pkts::prelude::*;
/// use pkts::layers::udp::UdpBuilder;
///
/// let payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
/// let buffer = [0u8; 100];
///
/// let udp_builder = UdpBuilder::new(&mut buffer)
///     .sport(65321)
///     .dport(443)
///     .chksum(0)
///     .payload_raw(&payload);
///
/// let udp_packet = udp_builder.build().unwrap();
/// ```
///
pub struct UdpBuilder<'a, T: UdpBuildPhase> {
    data: BufferMut<'a>,
    layer_start: usize,
    error: Option<SerializationError>,
    #[allow(unused)]
    phase: T,
}

impl<'a> UdpBuilder<'a, UdpBuildSrcPort> {
    #[inline]
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            layer_start: 0,
            data: BufferMut::new(buffer),
            error: None,
            phase: UdpBuildSrcPort,
        }
    }

    #[inline]
    pub fn from_buffer(buffer: BufferMut<'a>) -> Self {
        Self {
            layer_start: 0,
            data: buffer,
            error: None,
            phase: UdpBuildSrcPort,
        }
    }

    pub fn sport(mut self, sport: u16) -> UdpBuilder<'a, UdpBuildDstPort> {
        if self.error.is_none() {
            if self.data.remaining() >= 2 {
                self.data.append(&sport.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Udp::name()));
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

impl<'a> UdpBuilder<'a, UdpBuildDstPort> {
    pub fn dport(mut self, dport: u16) -> UdpBuilder<'a, UdpBuildChksum> {
        if self.error.is_none() {
            if self.data.remaining() >= 2 {
                self.data.append(&dport.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Udp::name()));
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

impl<'a> UdpBuilder<'a, UdpBuildChksum> {
    pub fn chksum(mut self, chksum: u16) -> UdpBuilder<'a, UdpBuildPayload> {
        if self.error.is_none() {
            if self.data.remaining() >= 4 {
                // Pad `length` field with 0s for now--it is filled later
                self.data.append(&[0u8; 2]);
                self.data.append(&chksum.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Udp::name()));
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

impl<'a> UdpBuilder<'a, UdpBuildPayload> {
    /// Add raw bytes as the payload of the UDP packet.
    pub fn payload_raw(mut self, payload: &[u8]) -> UdpBuilder<'a, UdpBuildFinal> {
        'insert_data: {
            if self.error.is_some() {
                break 'insert_data;
            }

            if self.data.remaining() < payload.len() {
                self.error = Some(SerializationError::insufficient_buffer(Udp::name()));
                break 'insert_data;
            }

            let Ok(data_len) = u16::try_from(8 + payload.len()) else {
                self.error = Some(SerializationError::insufficient_buffer(Udp::name()));
                break 'insert_data;
            };

            let len_start = self.layer_start + 4;
            let len_end = self.layer_start + 6;

            // Set data length field
            self.data.as_mut_slice()[len_start..len_end].copy_from_slice(&data_len.to_be_bytes());

            // Set data
            self.data.append(payload);
        }

        UdpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: UdpBuildFinal,
        }
    }

    /// Construct a payload for the UDP packet.
    ///
    /// The UDP packet's payload is constructed via the user-provided `build_payload` closure;
    /// several consecutive layers can be constructed at once using these closures in a nested
    /// manner.
    ///
    /// # Examples
    ///
    /// UDP-within-UDP:
    ///
    /// ```
    /// use pkts::prelude::*;
    /// use pkts::layers::udp::UdpBuilder;
    ///
    /// let inner_payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    /// let buffer = [0u8; 100];
    ///
    /// let udp_builder = UdpBuilder::new(&mut buffer)
    ///     .sport(65321)
    ///     .dport(443)
    ///     .chksum(0)
    ///     .payload(|b| UdpBuilder::from_buffer(b)
    ///         .sport(2452)
    ///         .dport(80)
    ///         .chksum(0)
    ///         .payload_raw(&mut inner_payload)
    ///         .build()
    ///     );
    ///
    /// let udp_packet = udp_builder.build().unwrap();
    /// ```
    pub fn payload(
        mut self,
        build_payload: impl FnOnce(BufferMut<'a>) -> Result<BufferMut<'a>, SerializationError>,
    ) -> UdpBuilder<'a, UdpBuildFinal> {
        let data;

        if self.error.is_some() {
            data = self.data;
        } else {
            match build_payload(self.data) {
                Ok(mut new_data) => {
                    match u16::try_from(new_data.len() - self.layer_start) {
                        Ok(data_len) => new_data.as_mut_slice()
                            [self.layer_start + 4..self.layer_start + 6]
                            .copy_from_slice(&data_len.to_be_bytes()),
                        Err(_) => {
                            self.error = Some(SerializationError::length_encoding(Udp::name()))
                        }
                    }
                    data = new_data;
                }
                Err(e) => {
                    self.error = Some(e);
                    data = BufferMut::new(&mut []);
                }
            }
        }

        UdpBuilder {
            data,
            layer_start: self.layer_start,
            error: self.error,
            phase: UdpBuildFinal,
        }
    }
}

impl<'a> UdpBuilder<'a, UdpBuildFinal> {
    #[inline]
    pub fn build(self) -> Result<BufferMut<'a>, SerializationError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.data),
        }
    }
}
