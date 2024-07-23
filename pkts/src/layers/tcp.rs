// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! The Transmission Control Protocol (TCP) and related data structures.
//!
//!
//!

use crate::layers::dev_traits::*;
use crate::layers::ip::{Ipv4, Ipv6, DATA_PROTO_TCP};
use crate::layers::traits::*;
use crate::utils;
use crate::{layers::*, Buffer};

use bitflags::bitflags;

use pkts_common::BufferMut;
use pkts_macros::{Layer, LayerRef, StatelessLayer};

use core::{cmp, mem, slice};

/// A TCP (Transmission Control Protocol) packet.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |          Source Port          |        Destination Port       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                        Sequence Number                        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                     Acknowledgement Number                    |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 | Offset| Res |N|C|E|U|A|P|R|S|F|          Window Size          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 |            Checksum           |         Urgent Pointer        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 20 Z                            Options                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ?? Z                            Payload                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(TcpMetadata)]
#[ref_type(TcpRef)]
pub struct Tcp {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: TcpFlags,
    window: u16,
    chksum: Option<u16>,
    urgent_ptr: u16,
    options: TcpOptions,
    payload: Option<Box<dyn LayerObject>>,
}

impl Tcp {
    /// The source port of the TCP packet.
    #[inline]
    pub fn sport(&self) -> u16 {
        self.sport
    }

    /// Sets the source port of the TCP packet.
    #[inline]
    pub fn set_sport(&mut self, sport: u16) {
        self.sport = sport;
    }

    /// The destination port of the TCP packet.
    #[inline]
    pub fn dport(&self) -> u16 {
        self.dport
    }

    /// Sets the destination port of the TCP packet.
    #[inline]
    pub fn set_dport(&mut self, dport: u16) {
        self.dport = dport;
    }

    /// The Sequence number of the TCP packet.
    #[inline]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    /// Sets the Sequence number of the TCP packet.
    #[inline]
    pub fn set_seq(&mut self, seq: u32) {
        self.seq = seq;
    }

    /// The Acknowledgement number of the TCP packet.
    #[inline]
    pub fn ack(&self) -> u32 {
        self.ack
    }

    /// Sets the Acknowledgement number of the TCP packet.
    #[inline]
    pub fn set_ack(&mut self, ack: u32) {
        self.ack = ack;
    }

    /// Indicates the first byte of the data payload for the TCP packet.
    ///
    /// Note that this offset is a multiple of 4 bytes, meaning that a data offset value of 5 would
    /// correspond to a 20-byte data offset.
    #[inline]
    pub fn data_offset(&self) -> usize {
        let options_len = self.options.byte_len();
        5 + (options_len / 4) // TODO: error condition here
    }

    /// The flags of the TCP packet (includes the reserved portion of the TCP header).
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        self.flags
    }

    /// Sets the flags of the TCP packet (includes the reserved portion of the TCP header).
    #[inline]
    pub fn set_flags(&mut self, flags: TcpFlags) {
        self.flags = flags;
    }

    // TODO: is this a receive window?? (rwnd)
    /// The congestion window (cwnd) advertised by the TCP packet.
    #[inline]
    pub fn window(&self) -> u16 {
        self.window
    }

    /// Sets the congestion window (cwnd) advertised by the TCP packet.
    #[inline]
    pub fn set_window(&mut self, window: u16) {
        self.window = window;
    }

    /// Retrieves the assigned checksum for the packet, or `None` if no checksum has explicitly
    /// been assigned to the packet.
    ///
    /// By default, the TCP checksum is automatically calculated when a [`struct@Tcp`] instance is
    /// converted to bytes, unless a checksum is pre-assigned to the instance prior to conversion.
    /// If a checksum has already been assigned to the packet, this method will return it;
    /// otherwise, it will return `None`. This means that a [`struct@Tcp`] instance created from
    /// bytes or from a [`TcpRef`] instance will still have a checksum of `None` by default,
    /// regardless of the checksum value of the underlying bytes it was created from.
    #[inline]
    pub fn chksum(&self) -> Option<u16> {
        self.chksum
    }

    /// Assigns a checksum to be used for the packet.
    ///
    /// By default, the TCP checksum is automatically calculated when a [`struct@Tcp`] instance is
    /// converted to bytes. This method overrides that behavior so that the provided checksum is
    /// used instead. You generally shouldn't need to use this method unless:
    ///   1. You know the expected checksum of the packet in advance and don't want the checksum
    ///      calculation to automatically run again (since it can be a costly operation), or
    ///   2. Checksum offloading is being employed for the TCP packet and you want to zero out the
    ///      checksum field (again, avoiding unnecessary extra computation), or
    ///   3. You want to explicitly set an invalid checksum.
    #[inline]
    pub fn set_chksum(&mut self, chksum: u16) {
        self.chksum = Some(chksum);
    }

    /// Clears any previously assigned checksum for the packet.
    ///
    /// This method guarantees that the TCP checksum will be automatically calculated for this
    /// [`struct@Tcp`] instance whenever the packet is converted to bytes. You shouldn't need to
    /// call this method unless you've previously explicitly assigned a checksum to the
    /// packet--either through a call to [`Tcp::set_chksum()`] or through a Builder pattern.
    /// Packets converted from bytes into [`struct@Tcp`] instances from bytes or from a [`TcpRef`]
    /// instance will have a checksum of `None` by default.
    #[inline]
    pub fn clear_chksum(&mut self) {
        self.chksum = None;
    }

    /// A pointer to the offset of data considered to be urgent within the packet.
    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        self.urgent_ptr
    }

    /// Sets the pointer to the offset of data considered to be urgent within the packet.
    #[inline]
    pub fn set_urgent_ptr(&mut self, urgent_ptr: u16) {
        self.urgent_ptr = urgent_ptr;
    }

    /// The optional parameters, or TCP Options, of the TCP packet.
    #[inline]
    pub fn options(&self) -> &TcpOptions {
        &self.options
    }

    /// A mutable reference to the optional parameters, or TCP Options, of the TCP packet.
    #[inline]
    pub fn options_mut(&mut self) -> &mut TcpOptions {
        &mut self.options
    }
}

impl LayerLength for Tcp {
    #[inline]
    fn len(&self) -> usize {
        20 + self.data_offset() * 4
            + match self.payload.as_ref() {
                Some(p) => p.len(),
                None => 0,
            }
    }
}

impl LayerObject for Tcp {
    #[inline]
    fn can_add_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        true // any protocol may be served over TCP
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

impl ToBytes for Tcp {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
        let start = bytes.len();
        bytes.extend(self.sport.to_be_bytes());
        bytes.extend(self.dport.to_be_bytes());
        bytes.extend(self.seq.to_be_bytes());
        bytes.extend(self.ack.to_be_bytes());
        bytes.push(((self.data_offset() as u8) << 4) | ((self.flags.bits() >> 8) as u8));
        bytes.push((self.flags.bits() & 0x00FF) as u8);
        bytes.extend(self.window.to_be_bytes());
        bytes.extend(self.chksum.unwrap_or(0).to_be_bytes());
        bytes.extend(self.urgent_ptr.to_be_bytes());
        match self.payload.as_ref() {
            None => (),
            Some(p) => p.to_bytes_checksummed(bytes, Some((Self::layer_id(), start)))?,
        }

        if self.chksum.is_none() {
            let Some((id, prev_idx)) = prev else {
                return Err(SerializationError::bad_upper_layer(Tcp::name()));
            };

            let new_chksum = if id == Ipv4::layer_id() {
                let mut data_chksum: u16 = utils::ones_complement_16bit(&bytes[start..]);
                let addr_chksum =
                    utils::ones_complement_16bit(&bytes[prev_idx + 12..prev_idx + 20]);
                data_chksum = utils::ones_complement_add(data_chksum, addr_chksum);
                data_chksum = utils::ones_complement_add(data_chksum, DATA_PROTO_TCP as u16);
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
                data_chksum = utils::ones_complement_add(data_chksum, DATA_PROTO_TCP as u16);

                data_chksum
            } else {
                return Ok(()); // Leave the checksum as 0--we don't have an IPv4/IPv6 pseudo-header, so we can't calculate it
            };

            let chksum_field: &mut [u8; 2] = &mut bytes[start + 16..start + 18].try_into().unwrap();
            *chksum_field = new_chksum.to_be_bytes();
            // else don't bother calculating the checksum
        }

        Ok(())
    }
}

#[doc(hidden)]
impl FromBytesCurrent for Tcp {
    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let tcp = TcpRef::from_bytes_unchecked(bytes);
        Tcp {
            sport: tcp.sport(),
            dport: tcp.dport(),
            seq: tcp.seq(),
            ack: tcp.ack(),
            flags: tcp.flags(),
            window: tcp.window(),
            chksum: None,
            urgent_ptr: tcp.urgent_ptr(),
            options: TcpOptions {
                options: None,
                padding: None,
            }, // TcpOptions::from(tcp.options()), TODO: uncomment
            payload: None,
        }
    }

    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        let tcp = TcpRef::from_bytes_unchecked(bytes);
        let start = cmp::max(tcp.data_offset(), 5) * 4;
        self.payload = if start > bytes.len() {
            Some(Box::new(Raw::from_bytes_unchecked(&bytes[start..])))
        } else {
            None
        }
    }
}

/// A TCP (Transmission Control Protocol) packet.
///
/// ## Packet Layout
/// ```txt
///    .    Octet 0    .    Octet 1    .    Octet 2    .    Octet 3    .
///    |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  0 |          Source Port          |        Destination Port       |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  4 |                        Sequence Number                        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  8 |                     Acknowledgement Number                    |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 12 | Offset| Res |N|C|E|U|A|P|R|S|F|          Window Size          |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 16 |            Checksum           |         Urgent Pointer        |
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 20 Z                            Options                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ?? Z                            Payload                            Z
///    Z                                                               Z
/// .. .                              ...                              .
///    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(Tcp)]
#[metadata_type(TcpMetadata)]
pub struct TcpRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> TcpRef<'a> {
    /// The source port of the TCP packet.
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("insufficient bytes in TCP layer to retrieve Source Port field"),
        )
    }

    /// The destination port of the TCP packet.
    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in TCP layer to retrieve Destination Port field"),
        )
    }

    /// The sequence number of the TCP packet.
    #[inline]
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in TCP layer to retrieve Sequence Number field"),
        )
    }

    /// The acknowledgement number of the TCP packet.
    #[inline]
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in TCP layer to retrieve Acknowledgement Number field"),
        )
    }

    /// Indicates the first byte of the data payload for the TCP packet.
    ///
    /// Note that this offset is a multiple of 4 bytes, meaning that a data offset value of 5 would
    /// correspond to a 20-byte data offset.
    #[inline]
    pub fn data_offset(&self) -> usize {
        (self
            .data
            .get(12)
            .expect("insufficient bytes in TCP layer to retrieve Data Offset field")
            >> 4) as usize
    }

    /// The flags of the TCP packet.
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::from(u16::from_be_bytes(
            utils::to_array(self.data, 12)
                .expect("insufficient bytes in TCP layer to retrieve TCP Flags"),
        ))
    }

    /// The congestion window (cwnd) advertised by the TCP packet.
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 14)
                .expect("insufficient bytes in TCP layer to retrieve Window Size field"),
        )
    }

    /// The checksum of the packet, calculated across the entirity of the packet's header and
    /// payload data.
    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in TCP layer to retrieve Checksum field"),
        )
    }

    /// A pointer to the offset of data considered to be urgent within the packet.
    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in TCP layer to retrieve Urgent Pointer field"),
        )
    }

    /// The optional parameters, or TCP Options, of the TCP packet.
    #[inline]
    pub fn options(&self) -> TcpOptionsRef<'a> {
        let end = cmp::max(self.data_offset(), 5) * 4;
        TcpOptionsRef::from_bytes_unchecked(
            self.data
                .get(20..end)
                .expect("insufficient bytes in TCP layer to retrieve TCP Options"),
        )
    }
}

impl<'a> FromBytesRef<'a> for TcpRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        TcpRef { data: bytes }
    }
}

#[doc(hidden)]
impl LayerOffset for TcpRef<'_> {
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        let tcp = TcpRef::from_bytes_unchecked(bytes);
        if layer_type == Raw::layer_id() {
            Some(cmp::max(5, tcp.data_offset()) * 4)
        } else {
            None
        }
    }
}

impl Validate for TcpRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let header_len = match curr_layer.get(12) {
            None => {
                return Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::InsufficientBytes,
                    reason:
                        "packet too short for TCP frame--missing Data Offset byte in TCP header",
                })
            }
            Some(l) => (l >> 4) as usize * 4,
        };

        if curr_layer.len() < header_len {
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                reason: "insufficient bytes for TCP packet header",
            });
        }

        if header_len < 20 {
            // Header length field must be at least 5 (so that corresponding header length is min required 20 bytes)
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InvalidValue,
                reason:
                    "invalid TCP header length value (Data Offset must be a value of 5 or more)",
            });
        }

        TcpOptionsRef::validate(&curr_layer[20..header_len])?;

        Ok(())
    }

    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(()) // By default, we assume the next layer after Tcp is Raw, which has no validation constraints
    }
}

// =============================================================================
//                                 TCP Builder
// =============================================================================

mod sealed {
    #[doc(hidden)]
    pub trait TcpBuildPhase {}
}
use sealed::TcpBuildPhase;

#[doc(hidden)]
pub struct TcpBuildSrcPort;

impl TcpBuildPhase for TcpBuildSrcPort {}

#[doc(hidden)]
pub struct TcpBuildDstPort;

impl TcpBuildPhase for TcpBuildDstPort {}

#[doc(hidden)]
pub struct TcpBuildSeq;

impl TcpBuildPhase for TcpBuildSeq {}

#[doc(hidden)]
pub struct TcpBuildAck;

impl TcpBuildPhase for TcpBuildAck {}

#[doc(hidden)]
pub struct TcpBuildFlags;

impl TcpBuildPhase for TcpBuildFlags {}

#[doc(hidden)]
pub struct TcpBuildWindowSize;

impl TcpBuildPhase for TcpBuildWindowSize {}

#[doc(hidden)]
pub struct TcpBuildChksum;

impl TcpBuildPhase for TcpBuildChksum {}

#[doc(hidden)]
pub struct TcpBuildUrgentPtr;

impl TcpBuildPhase for TcpBuildUrgentPtr {}

#[doc(hidden)]
pub struct TcpBuildOptsPayload;

impl TcpBuildPhase for TcpBuildOptsPayload {}

#[doc(hidden)]
pub struct TcpBuildFinal;

impl TcpBuildPhase for TcpBuildFinal {}

/// A Builder type for TCP packets, with configurable maximum bytearray size.
///
/// This struct employs a type-enforced Builder pattern, meaning that each step of building the
/// TCP packet is represented by a distinct type in the generic type `T`. In practical terms,
/// this simply means that you can build a TCP packet one field at a time without having to
/// worry about getting ordering wrong or missing fields--any errors of this kind will be caught
/// by the compiler.
///
/// # Example
///
/// ```
/// use pkts::prelude::*;
/// use pkts::layers::tcp::TcpBuilder;
///
/// let payload = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
///
/// let tcp_builder = TcpBuilder::new()
///     .sport(65321)
///     .dport(443)
///     .chksum(0)
///     .data(&payload);
///
/// let tcp_packet: Buffer<65536> = match tcp_builder.build().unwrap();
/// ```
///
pub struct TcpBuilder<'a, T: TcpBuildPhase> {
    data: BufferMut<'a>,
    layer_start: usize,
    error: Option<SerializationError>,
    phase: T,
}

impl<'a> TcpBuilder<'a, TcpBuildSrcPort> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            layer_start: 0,
            data: BufferMut::new(buffer),
            error: None,
            phase: TcpBuildSrcPort,
        }
    }

    pub fn from_buffer(buffer: BufferMut<'a>) -> Self {
        Self {
            layer_start: buffer.len(),
            data: buffer,
            error: None,
            phase: TcpBuildSrcPort,
        }
    }

    pub fn sport(mut self, sport: u16) -> TcpBuilder<'a, TcpBuildDstPort> {
        if self.error.is_none() {
            if self.data.remaining() >= mem::size_of::<u16>() {
                self.data.append(&sport.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildDstPort,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildDstPort> {
    #[inline]
    pub fn dport(mut self, dport: u16) -> TcpBuilder<'a, TcpBuildSeq> {
        if self.error.is_none() {
            if self.data.remaining() >= mem::size_of::<u16>() {
                self.data.append(&dport.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildSeq,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildSeq> {
    #[inline]
    pub fn seq(mut self, seq: u32) -> TcpBuilder<'a, TcpBuildAck> {
        if self.error.is_none() {
            if self.data.remaining() >= mem::size_of::<u32>() {
                self.data.append(&seq.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildAck,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildAck> {
    pub fn ack(mut self, ack: u32) -> TcpBuilder<'a, TcpBuildFlags> {
        if self.error.is_none() {
            if self.data.remaining() >= mem::size_of::<u32>() {
                self.data.append(&ack.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildFlags,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildFlags> {
    pub fn flags(mut self, flags: TcpFlags) -> TcpBuilder<'a, TcpBuildFlags> {
        if self.error.is_none() {
            if self.data.remaining() >= mem::size_of::<u32>() {
                self.data.append(&flags.bits().to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildFlags,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildWindowSize> {
    pub fn cwnd(mut self, window: u16) -> TcpBuilder<'a, TcpBuildChksum> {
        if self.error.is_none() {
            if self.data.remaining() >= mem::size_of::<u16>() {
                self.data.append(&window.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildChksum,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildChksum> {
    pub fn chksum(mut self, chksum: u16) -> TcpBuilder<'a, TcpBuildOptsPayload> {
        if self.error.is_none() {
            if self.data.remaining() >= mem::size_of::<u16>() {
                self.data.append(&chksum.to_be_bytes());
            } else {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildOptsPayload,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildOptsPayload> {
    pub fn option(mut self, option: TcpOption) -> TcpBuilder<'a, TcpBuildOptsPayload> {
        if self.error.is_none() {
            if let Err(e) = option.encode(&mut self.data) {
                self.error = Some(e);
            }
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildOptsPayload,
        }
    }

    /// Add a payload consisting of raw bytes to the TCP packet.
    pub fn payload_raw(mut self, data: &[u8]) -> TcpBuilder<'a, TcpBuildFinal> {
        'insert_data: {
            if self.error.is_some() {
                break 'insert_data;
            }

            if self.data.remaining() < data.len() {
                self.error = Some(SerializationError::insufficient_buffer(Tcp::name()));
                break 'insert_data;
            }

            let Ok(data_len) = u16::try_from(data.len() + 8) else {
                self.error = Some(SerializationError::length_encoding(Tcp::name()));
                break 'insert_data;
            };

            let len_start = self.layer_start + 4;
            let len_end = self.layer_start + 6;

            // Set data length field
            self.data.as_mut_slice()[len_start..len_end].copy_from_slice(&data_len.to_be_bytes());

            // Set data
            self.data.append(data);
        }

        TcpBuilder {
            layer_start: self.layer_start,
            data: self.data,
            error: self.error,
            phase: TcpBuildFinal,
        }
    }

    /// Add a payload layer to the TCP packet.
    ///
    /// The TCP packet's payload is constructed via the user-provided `build_payload` closure;
    /// several consecutive layers can be constructed at once using these closures in a nested
    /// manner.
    pub fn payload(
        mut self,
        build_payload: impl FnOnce(BufferMut<'a>) -> Result<BufferMut<'a>, SerializationError>,
    ) -> TcpBuilder<'a, TcpBuildFinal> {
        let data;

        if self.error.is_some() {
            data = self.data;
        } else {
            match build_payload(self.data) {
                Ok(mut new_data) => {
                    match u16::try_from(new_data.len() - self.layer_start) {
                        Ok(data_len) => new_data.as_mut_slice()[self.layer_start + 4..self.layer_start + 6].copy_from_slice(&data_len.to_be_bytes()),
                        Err(_) => self.error = Some(SerializationError::length_encoding(Tcp::name())),
                    }
                    data = new_data;
                },
                Err(e) => {
                    self.error = Some(e);
                    data = BufferMut::new(&mut []);
                }
            }
        }

        TcpBuilder {
            data,
            layer_start: self.layer_start,
            error: self.error,
            phase: TcpBuildFinal,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildFinal> {
    #[inline]
    pub fn build(self) -> Result<BufferMut<'a>, SerializationError> {
        match self.error {
            Some(error) => Err(error),
            None => Ok(self.data),
        }
    }
}

// =============================================================================
//                         Inner Field Data Structures
// =============================================================================

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct TcpFlags: u16 {
        const R1 = 0b_0000_1000_0000_0000;
        const R2 = 0b_0000_0100_0000_0000;
        const R3 = 0b_0000_0010_0000_0000;
        const NS = 0b_0000_0001_0000_0000;
        const CWR = 0b_0000_0000_1000_0000;
        const ECE = 0b_0000_0000_0100_0000;
        const URG = 0b_0000_0000_0010_0000;
        const ACK = 0b_0000_0000_0001_0000;
        const PSH = 0b_0000_0000_0000_1000;
        const RST = 0b_0000_0000_0000_0100;
        const SYN = 0b_0000_0000_0000_0010;
        const FIN = 0b_0000_0000_0000_0001;
    }
}

impl TcpFlags {
    #[inline]
    pub fn new() -> Self {
        TcpFlags::default()
    }
}

impl From<u16> for TcpFlags {
    fn from(value: u16) -> Self {
        TcpFlags::from_bits_truncate(value)
    }
}

const MAX_TCP_OPTIONS_LEN: usize = 40;

#[derive(Clone, Debug)]
pub struct TcpOptions {
    options: Option<Vec<TcpOption>>,
    padding: Option<Vec<u8>>,
}

impl TcpOptions {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(_bytes: &[u8]) -> Self {
        // Self::from(TcpOptionsRef::from_bytes_unchecked(bytes)) TODO: uncomment
        /*
        Self {
            options: None,
            padding: None,
        }
        */
        todo!()
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        TcpOptionsRef::validate(bytes)
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        let padding_len = self.padding.as_ref().map(|p| p.len()).unwrap_or(0);
        /*let options_len = self
            .options
            .as_ref()
            .map(|opts| opts.iter().map(|opt| opt.byte_len()).sum())
            .unwrap_or(0);
        options_len + padding_len
        */
        // TODO: uncomment this
        padding_len
    }

    #[inline]
    pub fn options(&self) -> &[TcpOption] {
        match &self.options {
            None => &[],
            Some(o) => o.as_slice(),
        }
    }

    #[inline]
    pub fn options_mut(&mut self) -> &mut Option<Vec<TcpOption>> {
        &mut self.options
    }

    #[inline]
    pub fn padding(&self) -> &[u8] {
        match &self.padding {
            None => &[],
            Some(p) => p.as_slice(),
        }
    }

    #[inline]
    pub fn padding_mut(&mut self) -> &mut Option<Vec<u8>> {
        &mut self.padding
    }

    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(0); // TODO: remove
                       /*
                       match self.options.as_ref() {
                           None => (),
                           Some(options) => {
                               for option in options.iter() {
                                   //option.to_bytes_extended(bytes); TODO: uncomment this
                               }

                               match self.padding.as_ref() {
                                   None => (),
                                   Some(p) => bytes.extend(p),
                               }
                           }
                       }*/

        todo!()
    }
}

/*
impl From<&TcpOptionsRef<'_>> for TcpOptions {
    fn from(value: &TcpOptionsRef<'_>) -> Self {
        let (options, padding) = if value.iter().next().is_none() {
            (None, None)
        } else {
            let mut opts = Vec::new();
            let mut iter = value.iter();
            while let Some(opt) = iter.next() {
                opts.push(TcpOption::from(opt));
            }
            match iter.bytes {
                &[] => (Some(opts), None),
                padding => (Some(opts), Some(Vec::from(padding))),
            }
        };

        TcpOptions { options, padding }
    }
}
*/

/*
impl From<TcpOptionsRef<'_>> for TcpOptions {
    fn from(value: TcpOptionsRef<'_>) -> Self {
        Self::from(&value)
    }
}*/

#[derive(Clone, Copy, Debug)]
pub struct TcpOptionsRef<'a> {
    bytes: &'a [u8],
}

impl<'a> TcpOptionsRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        TcpOptionsRef { bytes }
    }

    pub fn validate(mut bytes: &[u8]) -> Result<(), ValidationError> {
        if bytes.is_empty() {
            return Ok(());
        }

        if bytes.len() % 4 != 0 {
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InvalidValue,
                reason: "TCP Options data length must be a multiple of 4",
            });
        }

        while let Some(option_type) = bytes.first() {
            match option_type {
                0 => break,
                1 => bytes = &bytes[1..],
                _ => match bytes.get(1) {
                    Some(0..=1) => {
                        return Err(ValidationError {
                            layer: Tcp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            reason: "TCP option length field contained too small a value",
                        })
                    }
                    Some(&len) => match bytes.get(len as usize..) {
                        Some(remaining) => bytes = remaining,
                        None => return Err(ValidationError {
                            layer: Tcp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            reason:
                                "truncated TCP option field in options--missing part of option data",
                        }),
                    },
                    None => {
                        return Err(ValidationError {
                            layer: Tcp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            reason:
                                "truncated TCP option found in options--missing option length field",
                        })
                    }
                },
            }
        }

        Ok(())
    }

    #[inline]
    pub fn iter(&self) -> TcpOptionsIterRef<'a> {
        TcpOptionsIterRef {
            curr_idx: 0,
            bytes: self.bytes,
            end_reached: false,
        }
    }

    #[inline]
    pub fn padding(&self) -> &'a [u8] {
        /*
        let mut iter = self.iter();
        // while iter.next().is_some() {} TODO: uncomment
        &iter.bytes[iter.curr_idx..]
        */
        todo!()
    }
}

pub struct TcpOptionsIterRef<'a> {
    curr_idx: usize,
    bytes: &'a [u8],
    end_reached: bool,
}

/*
impl<'a> Iterator for TcpOptionsIterRef<'a> {
    type Item = TcpOptionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.end_reached {
            return None;
        }

        match self.bytes.first() {
            Some(&r @ (0 | 1)) => {
                let option = &self.bytes[self.curr_idx..self.curr_idx + 1];
                self.curr_idx += 1;
                if r == 0 {
                    self.end_reached = true;
                }
                Some(TcpOptionRef::from_bytes_unchecked(option))
            }
            Some(&op_len) => {
                let option = &self.bytes[self.curr_idx..self.curr_idx + op_len as usize];
                self.curr_idx += op_len as usize;
                Some(TcpOptionRef::from_bytes_unchecked(option))
            }
            None => None,
        }
    }
}*/

const TCP_OPT_KIND_EOOL: u8 = 0;
const TCP_OPT_KIND_NOP: u8 = 1;
const TCP_OPT_KIND_MSS: u8 = 2;
const TCP_OPT_KIND_WSCALE: u8 = 3;
const TCP_OPT_KIND_SACK_PERMITTED: u8 = 4;
const TCP_OPT_KIND_SACK: u8 = 5;
const TCP_OPT_KIND_TIMESTAMP: u8 = 8;
const TCP_OPT_KIND_USER_TIMEOUT: u8 = 28;
const TCP_OPT_KIND_AUTHENTICATION: u8 = 29;
const TCP_OPT_KIND_MPTCP: u8 = 29;

#[derive(Clone, Debug)]
pub enum TcpOption {
    /// End of Options List.
    ///
    /// This option marks the final option in the list of TCP options; any leftover bytes following
    /// this option are considered to be padding. This value is not necessary if the final TCP
    /// option consumes all remaining bytes in the TCP options field.
    Eool,
    /// No operation.
    ///
    /// This may be used to align option fields on 32-bit boundaries to improve performance.
    Nop,
    /// Maximum Segment Size.
    ///
    /// The MSS is the maximum amount of data (in bytes) that the sender of this option will accept
    /// within a single IP segment. Note that this value only represents the MSS of the sender, not
    /// that of intermediate routers between the sender and recipient, so large MSS values may lead
    /// to IP fragmentation.
    Mss(TcpOptionMss),
    /// Window Scaling.
    ///
    /// Scales the `window` value in the TCP packet by a factor of 2^`wscale`. This option enables
    /// window sizes as large as 1 gigabyte, thereby facilitating higher bandwidth traffic over TCP.
    /// This option is only used in the SYN segment of each peer during a TCP 3-way handshake.
    Wscale(TcpOptionWscale),
    /// Selective Acknowledgement Permitted.
    ///
    /// Indicates that the sender of the TCP option supports Selective Acknowledgement. This option
    /// is only used in the SYN segment of each peer during a TCP 3-way handshake, and selective
    /// acknowledgement is only enabled if both sides indicate support for it.
    SackPermitted,
    /// Selective Acknowledgement.
    ///
    /// Indicates chunks of data that are acknowledged as being received by the peer.
    Sack(TcpOptionSack),
    /// TCP Timestamp.
    ///
    /// Indicates when a packet was sent relative to other recieved packets. The time value is not
    /// guaranteed to be aligned to the system clock.
    Timestamp(TcpOptionTimestamp),
    /// User Timeout option.
    ///
    /// Controls how long transmitted data may be left unacknowledged before a connection is
    /// dropped. See [RFC 5482](https://datatracker.ietf.org/doc/html/rfc5482) for details.
    UserTimeout(TcpOptionUserTimeout),
    /// TCP Authentication Option (TCP-AO).
    ///
    /// For additional details, see [RFC 5925](https://datatracker.ietf.org/doc/html/rfc5925).
    TcpAo(TcpOptionAuthentication),
    /// Multipath TCP (MPTCP).
    ///
    /// TODO fill out
    Mptcp(TcpOptionMultipath),
    /// Padding bytes following Eool.
    ///
    /// This is NOT an actual TCP option; rather, it is used only after [`TcpOption::Eool`] to align
    /// TCP options to a 4-byte word boundary.
    Padding(TcpOptionPadding),
    /// A TCP option with an unknown `kind` (i.e. different from listed above).
    Unknown(TcpOptionUnknown),
}

impl TcpOption {
    pub fn encode(&self, buffer: &mut BufferMut<'_>) -> Result<(), SerializationError> {
        match self {
            Self::Eool => buffer.append_or(&[0], SerializationError::insufficient_buffer(Tcp::name())),
            Self::Nop => buffer.append_or(&[1], SerializationError::insufficient_buffer(Tcp::name())),
            _ => todo!(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionMss(pub u16);

#[derive(Clone, Debug)]
pub struct TcpOptionWscale(pub u8);

#[derive(Clone, Debug)]
pub struct TcpOptionSack {
    /// The list of blocks being selectively acknowledged. Each tuple represents (begin, end)
    /// pointers to a block of data that has been acknowledged.
    pub blocks_acked: [(u32, u32); 4],
    /// The number of blocks present in `blocks_acked` (1-4).
    pub blocks_acked_cnt: usize,
}

#[derive(Clone, Debug)]
pub struct TcpOptionTimestamp {
    pub ts: u32,
    pub prev_ts: u32,
}

#[derive(Clone, Debug)]
pub struct TcpOptionUserTimeout {
    granularity: UserTimeoutGranularity,
    timeout: u16,
}

impl TcpOptionUserTimeout {
    #[inline]
    pub fn granularity(&self) -> UserTimeoutGranularity {
        self.granularity
    }

    #[inline]
    pub fn timeout(&self) -> u16 {
        self.timeout
    }

    #[inline]
    pub fn set_granularity(&mut self, granularity: UserTimeoutGranularity) {
        self.granularity = granularity;
    }

    #[inline]
    pub fn set_timeout(&self, _timeout: u16) {
        //self.timeout = cmp::min(timeout, u16::MAX >> 1); // Saturate at 15-bit maximum value
        // TODO: uncomment
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UserTimeoutGranularity {
    Minute,
    Second,
}

#[derive(Clone, Debug)]
pub struct TcpOptionAuthentication {
    pub opt_len: usize,
}

#[derive(Clone, Debug)]
pub struct TcpOptionMultipath {
    pub opt_len: usize,
}

#[derive(Clone, Debug)]
pub struct TcpOptionUnknown {
    pub kind: u8,
    pub value: Buffer<38>, // 40 bytes maximum in options, minus 2 for `kind` and `length`
}

#[derive(Clone, Debug)]
pub struct TcpOptionPadding {
    pub padding: Buffer<39>, // 40 bytes maximum in options, minus 1 for `Eool`
}

/*
impl TcpOption {
    #[inline]
    pub fn byte_len(&self) -> usize {
        match self.option_type {
            0 | 1 => 1,
            _ => 2 + self.value.as_ref().map(|v| v.len()).unwrap_or(0),
        }
    }

    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        match bytes[0] {
            0 => TcpOption::Eool,
            1 => TcpOption::Nop,
            2 => {
                let mss = TcpOptionMss(u16::from_be_bytes(bytes[2]));

                TcpOption::Mss(mss)
            }
        }
    }

    /// The length (in bytes) of the encoded TCP option.
    #[inline]
    pub fn len(&self) -> usize {
        match self.option_type {
            0 | 1 => 1,
            _ => self.value.as_ref().unwrap().len() + 2,
        }
    }

    #[inline]
    pub fn option_type(&self) -> u8 {
        self.option_type
    }

    #[inline]
    pub fn option_data(&self) -> &[u8] {
        match &self.value {
            Some(v) => v.as_slice(),
            None => &[],
        }
    }

    #[inline]
    pub fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(self.option_type);
        match self.option_type {
            0 | 1 => (),
            _ => match self.value.as_ref() {
                None => bytes.push(2),
                Some(val) => {
                    bytes.push((2 + val.len()) as u8);
                    bytes.extend(val);
                }
            },
        }
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        if let Some(TCP_OPT_KIND_EOOL | TCP_OPT_KIND_NOP) = bytes.first() {
            return if bytes.len() == 1 {
                Ok(())
            } else {
                Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::ExcessBytes(bytes.len() - 1),
                    reason: "excess bytes at end of single-byte TCP Option"
                })
            }
        }

        let (Some(kind), Some(length)) = (bytes.get(0), bytes.get(1)) else {
            Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                reason: "insufficient bytes in TCP Option for Kind/Length fields"
            })
        };

        let Some(value) = bytes.get(2..2 + length) else {
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                reason: "insufficient bytes for TCP option value"
            })
        };

        if bytes.len() != 2 + length {
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::ExcessBytes(bytes.len() - length - 2),
                reason: "excess bytes at end of TCP Option"
            })
        };

        match kind {
            TCP_OPT_KIND_MSS => if length == 2 {
                Ok(TcpOption::Mss(TcpOptionMss(u16::from_be_bytes(value.try_into().uwnrap()))))
            } else {
                Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::InvalidValue,
                    reason: "unexpected number of bytes for Maximum Segment Size TCP Option"
                })
            }
            TCP_OPT_KIND_WSCALE => if length == 1 {
                Ok(TcpOption::Wscale(TcpOptionWscale(value[0])))
            } else {
                Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::InvalidValue,
                    reason: "unexpected number of bytes for Window Scale TCP Option"
                })
            }
            TCP_OPT_KIND_SACK_PERMITTED => if length == 0 {
                Ok(TcpOption::SackPermitted)
            } else {
                Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::InvalidValue,
                    reason: "unexpected number of bytes for Sack Permitted TCP Option"
                })
            }
            TCP_OPT_KIND_SACK => todo!(), /* if length % 8 == 0 && length > 0 && length <= 32 {
                for _ in 0..length / 8 {
                    todo!()
                }
            } */
            TCP_OPT_KIND_TIMESTAMP => todo!(),
            TCP_OPT_KIND_USER_TIMEOUT => todo!(),
            TCP_OPT_KIND_AUTHENTICATION => todo!(),
            TCP_OPT_KIND_MPTCP => todo!(),
            Some(_) => match bytes.get(1) {
                Some(&len @ 2..) if bytes.len() >= len as usize => match bytes.len().checked_sub(len as usize) {
                    Some(0) => Ok(()),
                    Some(remaining) => Err(ValidationError {
                        layer: Tcp::name(),
                        class: ValidationErrorClass::ExcessBytes(remaining),
                        reason: "excess bytes at end of sized TCP option",
                    }),
                    None => Err(ValidationError {
                        layer: Tcp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        reason: "length of TCP Option data exceeded available bytes"
                    }),
                },
                _ => Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::InvalidValue,
                    reason: "insufficient bytes available to read TCP Option--missing length byte field"
                }),
            },
            None => Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InvalidValue,
                reason: "insufficient bytes available to read TCP Option--missing option_type byte field",
            })
        }
    }
}
*/

/*
impl From<&TcpOptionRef<'_>> for TcpOption {
    fn from(value: &TcpOptionRef<'_>) -> Self {
        TcpOption {
            option_type: value.option_type(),
            value: match value.option_type() {
                0 | 1 => None,
                _ => Some(Vec::from(value.option_data())),
            },
        }
    }
}

impl From<TcpOptionRef<'_>> for TcpOption {
    fn from(value: TcpOptionRef<'_>) -> Self {
        Self::from(&value)
    }
}
*/

/*
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match bytes.first() {
            Some(0 | 1) => if bytes.len() == 1 {
                Ok(())
            } else {
                Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::ExcessBytes(bytes.len() - 1),
                    reason: "excess bytes at end of single-byte TCP option"
                })
            },
            Some(_) => match bytes.get(1) {
                Some(&len @ 2..) if bytes.len() >= len as usize => match bytes.len().checked_sub(len as usize) {
                    Some(0) => Ok(()),
                    Some(remaining) => Err(ValidationError {
                        layer: Tcp::name(),
                        class: ValidationErrorClass::ExcessBytes(remaining),
                        reason: "excess bytes at end of sized TCP option",
                    }),
                    None => Err(ValidationError {
                        layer: Tcp::name(),
                        class: ValidationErrorClass::InvalidValue,
                        reason: "length of TCP Option data exceeded available bytes"
                    }),
                },
                _ => Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::InvalidValue,
                    reason: "insufficient bytes available to read TCP Option--missing length byte field"
                }),
            },
            None => Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InvalidValue,
                reason: "insufficient bytes available to read TCP Option--missing option_type byte field",
            })
        }
    }
*/
