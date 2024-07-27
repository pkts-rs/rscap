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

pub mod mptcp;

use core::{cmp, mem, slice};

use crate::layers::dev_traits::*;
use crate::layers::ip::{Ipv4, Ipv6, DATA_PROTO_TCP};
use crate::layers::traits::*;
use crate::{utils, IndexedWritable, PacketWriter};
use crate::layers::*;

use bitflags::bitflags;

use pkts_common::{Buffer, BufferMut};
use pkts_macros::{Layer, LayerRef, StatelessLayer};

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

pub const TCP_OPT_KIND_EOOL: u8 = 0;
pub const TCP_OPT_KIND_NOP: u8 = 1;
pub const TCP_OPT_KIND_MSS: u8 = 2;
pub const TCP_OPT_KIND_WSCALE: u8 = 3;
pub const TCP_OPT_KIND_SACK_PERMITTED: u8 = 4;
pub const TCP_OPT_KIND_SACK: u8 = 5;
pub const TCP_OPT_KIND_TIMESTAMP: u8 = 8;
pub const TCP_OPT_KIND_MD5: u8 = 19;
pub const TCP_OPT_KIND_USER_TIMEOUT: u8 = 28;
pub const TCP_OPT_KIND_AUTHENTICATION: u8 = 29;
pub const TCP_OPT_KIND_MPTCP: u8 = 30;

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
            options: TcpOptions(Vec::new()), // TcpOptions::from(tcp.options()), TODO: uncomment
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
        u16::from_be_bytes(utils::to_array(self.data, 0).unwrap())
    }

    /// The destination port of the TCP packet.
    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 2).unwrap())
    }

    /// The sequence number of the TCP packet.
    #[inline]
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 4).unwrap())
    }

    /// The acknowledgement number of the TCP packet.
    #[inline]
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes(utils::to_array(self.data, 8).unwrap())
    }

    /// Indicates the first byte of the data payload for the TCP packet.
    ///
    /// Note that this offset is a multiple of 4 bytes, meaning that a data offset value of 5 would
    /// correspond to a 20-byte data offset.
    #[inline]
    pub fn data_offset(&self) -> usize {
        (self.data[12] >> 4) as usize
    }

    /// The flags of the TCP packet.
    #[inline]
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::from_bits_truncate(u16::from_be_bytes(utils::to_array(self.data, 12).unwrap()))
    }

    /// The congestion window (cwnd) advertised by the TCP packet.
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 14).unwrap())
    }

    /// The checksum of the packet, calculated across the entirity of the packet's header and
    /// payload data.
    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 16).unwrap())
    }

    /// A pointer to the offset of data considered to be urgent within the packet.
    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        u16::from_be_bytes(utils::to_array(self.data, 18).unwrap())
    }

    /// The optional parameters, or TCP Options, of the TCP packet.
    #[inline]
    pub fn options(&self) -> TcpOptionsRef<'a> {
        let end = cmp::max(self.data_offset(), 5) * 4;
        TcpOptionsRef::from_bytes_unchecked(&self.data[20..end])
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
                    #[cfg(feature = "error_string")]
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
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes for TCP packet header",
            });
        }

        if header_len < 20 {
            // Header length field must be at least 5 (so that corresponding header length is min required 20 bytes)
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InvalidValue,
                #[cfg(feature = "error_string")]
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
    #[allow(unused)]
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

    /// Sets the source port to be used for the TCP packet.
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
    /// Sets the destination port to be used for the TCP packet.
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
    /// Sets the sequence number to be used for the TCP packet.
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
    /// Sets the acknowledgement number to be used for the TCP packet.
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
    /// Sets the TCP flags to be used for the TCP packet.
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
    /// Sets the congestion window to be used for the TCP packet.
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
    /// Sets the checksum of the TCP packet.
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
    /// Adds a TCP option to the TCP packet.
    pub fn option(mut self, option: TcpOption) -> TcpBuilder<'a, TcpBuildOptsPayload> {
        if self.error.is_none() {
            if let Err(e) = option.to_bytes_extended(&mut self.data) {
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

    /// Sets the application-layer payload of the TCP packet using raw bytes.
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

    /// Sets the application-layer payload of the TCP packet using another builder routine.
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
                        Ok(data_len) => new_data.as_mut_slice()
                            [self.layer_start + 4..self.layer_start + 6]
                            .copy_from_slice(&data_len.to_be_bytes()),
                        Err(_) => {
                            self.error = Some(SerializationError::length_encoding(Tcp::name()))
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

        TcpBuilder {
            data,
            layer_start: self.layer_start,
            error: self.error,
            phase: TcpBuildFinal,
        }
    }
}

impl<'a> TcpBuilder<'a, TcpBuildFinal> {
    /// Completes the construction of a TCP packet.
    ///
    /// If an error occurred while adding any of the above fields, this will return an error;
    /// otherwise, it will successfully return a buffer containing a valid TCP packet.
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

#[derive(Clone, Debug)]
pub struct TcpOptions(Vec<TcpOption>);

impl TcpOptions {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        let mut data = bytes;
        let mut eool_reached = false;
        let mut options = Vec::new();

        while !data.is_empty() {
            if eool_reached {
                let mut padding = Buffer::new();
                padding.append(data);

                options.push(TcpOption::Padding(TcpOptionPadding {
                    padding,
                }));

                break
            }

            match data[0] {
                TCP_OPT_KIND_EOOL => {
                    options.push(TcpOption::Eool);
                    data = &data[1..];
                    eool_reached = true;
                }
                TCP_OPT_KIND_NOP => {
                    options.push(TcpOption::Nop);
                    data = &data[1..];
                }
                _ => {
                    let (opt_data, rem) = data.split_at(data[1] as usize);
                    options.push(TcpOption::from_bytes_unchecked(opt_data));
                    data = rem;
                }
            }
        }

        TcpOptions(options)
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        TcpOptionsRef::validate(bytes)
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        self.0.iter().map(|o| o.byte_len()).sum()
    }

    #[inline]
    pub fn options(&self) -> &[TcpOption] {
        self.0.as_slice()
    }

    #[inline]
    pub fn options_mut(&mut self) -> &mut Vec<TcpOption> {
        &mut self.0
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
                #[cfg(feature = "error_string")]
                reason: "TCP Options data length must be a multiple of 4",
            });
        }

        while let Some(option_type) = bytes.first() {
            match *option_type {
                TCP_OPT_KIND_EOOL => {
                    for padding_byte in &bytes[1..] {
                        if *padding_byte != 0 {
                            return Err(ValidationError {
                                layer: Tcp::name(),
                                class: ValidationErrorClass::UnusualPadding,
                                #[cfg(feature = "error_string")]
                                reason: "TCP option padding had non-zero value",
                            })
                        }
                    }

                    break
                }
                TCP_OPT_KIND_NOP => bytes = &bytes[1..],
                _ => match bytes.get(1) {
                    None => {
                        return Err(ValidationError {
                            layer: Tcp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason:
                                "truncated TCP option found in options--missing option length field",
                        })
                    }
                    Some(0..=1) => {
                        return Err(ValidationError {
                            layer: Tcp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason: "TCP option length was less than minimum required",
                        })
                    }
                    Some(&len) => match bytes.get(len as usize..) {
                        Some(remaining) => bytes = remaining,
                        None => return Err(ValidationError {
                            layer: Tcp::name(),
                            class: ValidationErrorClass::InvalidValue,
                            #[cfg(feature = "error_string")]
                            reason:
                                "truncated TCP option field in options--missing part of option data",
                        }),
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
}

pub struct TcpOptionsIterRef<'a> {
    curr_idx: usize,
    bytes: &'a [u8],
    end_reached: bool,
}

impl<'a> Iterator for TcpOptionsIterRef<'a> {
    type Item = TcpOption;

    fn next(&mut self) -> Option<Self::Item> {
        if self.end_reached {
            if self.bytes[self.curr_idx..].is_empty() {
                return None
            } else {
                let mut padding = Buffer::new();
                padding.append(&self.bytes[self.curr_idx..]);
                self.curr_idx = self.bytes.len();

                return Some(TcpOption::Padding(TcpOptionPadding { padding }))
            }
        }

        match self.bytes.first() {
            Some(&r @ (TCP_OPT_KIND_EOOL | TCP_OPT_KIND_NOP)) => {
                let option = &self.bytes[self.curr_idx..self.curr_idx + 1];
                self.curr_idx += 1;
                if r == 0 {
                    self.end_reached = true;
                }
                Some(TcpOption::from_bytes_unchecked(option))
            }
            Some(&op_len) => {
                let option = &self.bytes[self.curr_idx..self.curr_idx + op_len as usize];
                self.curr_idx += op_len as usize;
                Some(TcpOption::from_bytes_unchecked(option))
            }
            None => None,
        }
    }
}

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

    Md5(TcpOptionMd5),
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
    Mptcp(mptcp::Mptcp),
    /// Padding bytes following Eool.
    ///
    /// This is NOT an official TCP option; rather, it is used after [`TcpOption::Eool`] to align
    /// TCP options to a 4-byte word boundary.
    Padding(TcpOptionPadding),
    /// A TCP option with an unknown `kind` (i.e. different from listed above).
    Unknown(TcpOptionUnknown),
}

impl TcpOption {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        
        match self {
            Self::Eool | Self::Nop => writer.write(&[0]),
            Self::Mss(mss) => mss.to_bytes_extended(writable),
            Self::Wscale(wscale) => wscale.to_bytes_extended(writable),
            Self::SackPermitted => writer.write(&[TCP_OPT_KIND_SACK_PERMITTED, 2]),
            Self::Sack(sack) => sack.to_bytes_extended(writable),
            Self::Timestamp(timestamp) => timestamp.to_bytes_extended(writable),
            Self::Md5(md5) => md5.to_bytes_extended(writable),
            Self::UserTimeout(timeout) => timeout.to_bytes_extended(writable),
            Self::TcpAo(auth) => auth.to_bytes_extended(writable),
            Self::Mptcp(mptcp) => mptcp.to_bytes_extended(writable),
            Self::Padding(padding) => padding.to_bytes_extended(writable),
            Self::Unknown(unknown) => unknown.to_bytes_extended(writable),
        }
    }

    pub fn validate(data: &[u8]) -> Result<(), ValidationError> {
    let Some(&kind) = data.get(0) else {
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in TCP option for `kind` field",
            })
        };

        match kind {
            TCP_OPT_KIND_EOOL => if data.len() > 1 {
                Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::ExcessBytes(data.len() - 1),
                    reason: "trailing bytes after TCP EOOL Option",
                })
            } else {
                Ok(())
            },
            TCP_OPT_KIND_NOP => if data.len() > 1 {
                Err(ValidationError {
                    layer: Tcp::name(),
                    class: ValidationErrorClass::ExcessBytes(data.len() - 1),
                    reason: "trailing bytes after TCP NOP Option",
                })
            } else {
                Ok(())
            },
            _ => todo!()
        }
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        if data == &[TCP_OPT_KIND_EOOL] {
            return Self::Eool
        }

        if data == &[TCP_OPT_KIND_NOP] {
            return Self::Nop
        }

        debug_assert!(data.len() == data[1] as usize);

        match data[0] {
            TCP_OPT_KIND_MSS => Self::Mss(TcpOptionMss::from_bytes_unchecked(data)),
            TCP_OPT_KIND_WSCALE => Self::Wscale(TcpOptionWscale::from_bytes_unchecked(data)),
            TCP_OPT_KIND_SACK_PERMITTED => Self::SackPermitted,
            TCP_OPT_KIND_SACK => Self::Sack(TcpOptionSack::from_bytes_unchecked(data)),
            TCP_OPT_KIND_TIMESTAMP => Self::Timestamp(TcpOptionTimestamp::from_bytes_unchecked(data)),
            TCP_OPT_KIND_MD5 => Self::Md5(TcpOptionMd5::from_bytes_unchecked(data)),
            TCP_OPT_KIND_USER_TIMEOUT => Self::UserTimeout(TcpOptionUserTimeout::from_bytes_unchecked(data)),
            TCP_OPT_KIND_AUTHENTICATION => Self::TcpAo(TcpOptionAuthentication::from_bytes_unchecked(data)),
            TCP_OPT_KIND_MPTCP => Self::Mptcp(mptcp::Mptcp::from_bytes_unchecked(data)),
            _ => Self::Unknown(TcpOptionUnknown::from_bytes_unchecked(data)),
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            TcpOption::Eool => 1,
            TcpOption::Nop => 1,
            TcpOption::Mss(o) => o.byte_len(),
            TcpOption::Wscale(o) => o.byte_len(),
            TcpOption::SackPermitted => 2,
            TcpOption::Sack(o) => o.byte_len(),
            TcpOption::Timestamp(o) => o.byte_len(),
            TcpOption::Md5(o) => o.byte_len(),
            TcpOption::UserTimeout(o) => o.byte_len(),
            TcpOption::TcpAo(o) => o.byte_len(),
            TcpOption::Mptcp(o) => o.byte_len(),
            TcpOption::Padding(o) => o.byte_len(),
            TcpOption::Unknown(o) => o.byte_len(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionMss(u16);

impl TcpOptionMss {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MSS, self.byte_len() as u8])?;
        writer.write(&self.0.to_be_bytes())   
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert!(data.len() == 4);
        Self(u16::from_be_bytes(utils::to_array(data, 2).unwrap()))
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        4
    }

    #[inline]
    pub fn mss(&self) -> u16 {
        self.0
    }

    #[inline]
    pub fn set_mss(&mut self, mss: u16) {
        self.0 = mss;
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionWscale(u8);

impl TcpOptionWscale {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_WSCALE, self.byte_len() as u8])?;
        writer.write(&[self.0])
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert_eq!(data.len(), 3);
        Self(data[2])
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        3
    }

    pub fn wscale(&self) -> u8 {
        self.0
    }

    pub fn set_wscale(&mut self, wscale: u8) {
        self.0 = wscale;
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionSack {
    /// The list of blocks being selectively acknowledged. Each tuple represents (begin, end)
    /// pointers to a block of data that has been acknowledged.
    blocks_acked: Buffer<(u32, u32), 4>,
}

impl TcpOptionSack {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_SACK, self.byte_len() as u8])?;
        for block in self.blocks_acked.as_slice() {
            writer.write(&block.0.to_be_bytes())?;
            writer.write(&block.1.to_be_bytes())?;
        }

        Ok(())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert_eq!(data[0], TCP_OPT_KIND_SACK);
        debug_assert_eq!(data[1] % 4, 0);
        debug_assert!(data[1] > 2 && data[1] <= 34);

        let mut buf = Buffer::new();
        let mut idx = 2;

        while idx < data[1] as usize {
            let sack_start = u32::from_be_bytes(utils::to_array(data, idx).unwrap());
            let sack_end = u32::from_be_bytes(utils::to_array(data, idx + 4).unwrap());
            buf.append(&[(sack_start, sack_end)]);
            idx += 8;
        }

        Self {
            blocks_acked: buf,
        }
    }

    pub fn byte_len(&self) -> usize {
        2 + 8 * self.blocks_acked.len()
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionTimestamp {
    pub ts: u32,
    pub prev_ts: u32,
}

impl TcpOptionTimestamp {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_TIMESTAMP, self.byte_len() as u8])?;
        writer.write(&self.ts.to_be_bytes())?;
        writer.write(&self.prev_ts.to_be_bytes())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert_eq!(data[0], TCP_OPT_KIND_TIMESTAMP);
        debug_assert_eq!(data[1], 10);
        let ts = u32::from_be_bytes(utils::to_array(data, 2).unwrap());
        let prev_ts = u32::from_be_bytes(utils::to_array(data, 6).unwrap());

        Self {
            ts,
            prev_ts,
        }
    }

    pub fn byte_len(&self) -> usize {
        10
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionMd5 {
    digest: [u8; 16],
}

impl TcpOptionMd5 {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MD5, self.byte_len() as u8])?;
        writer.write(&self.digest)
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert_eq!(data[0], TCP_OPT_KIND_MD5);
        debug_assert_eq!(data[1], 18);

        Self {
            digest: utils::to_array(data, 2).unwrap(),
        }
    }

    pub fn byte_len(&self) -> usize {
        18
    }

    #[inline]
    pub fn digest(&self) -> [u8; 16] {
        self.digest
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionUserTimeout {
    granularity: UserTimeoutGranularity,
    timeout: u16,
}

impl TcpOptionUserTimeout {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_USER_TIMEOUT, self.byte_len() as u8])?;

        let optval = self.timeout | match self.granularity {
            UserTimeoutGranularity::Minute => 0b_1000_0000_0000_0000,
            UserTimeoutGranularity::Second => 0,
        };
        writer.write(&optval.to_be_bytes())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert_eq!(data[0], TCP_OPT_KIND_TIMESTAMP);
        debug_assert_eq!(data[1], 4);

        let timeout = u16::from_be_bytes(utils::to_array(data, 2).unwrap());
        let granularity = match (timeout & 0b_1000_0000_0000_0000) > 0 {
            true => UserTimeoutGranularity::Minute,
            false => UserTimeoutGranularity::Second,
        };

        Self {
            timeout: timeout & !0b_1000_0000_0000_0000,
            granularity,
        }
    }

    pub fn byte_len(&self) -> usize {
        4
    }

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
    key_id: u8,
    next_key_id: u8,
    mac: Buffer<u8, 36>,
}

impl TcpOptionAuthentication {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_AUTHENTICATION, self.byte_len() as u8])?;
        writer.write(&[self.key_id, self.next_key_id])?;
        writer.write(self.mac.as_slice())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert_eq!(data[0], TCP_OPT_KIND_AUTHENTICATION);
        debug_assert!(data[1] >= 4 || data[1] <= 40);

        let mut mac = Buffer::new();
        mac.append(&data[4..data[1] as usize]);

        Self {
            key_id: data[2],
            next_key_id: data[3],
            mac,
        }
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        4 + self.mac.len()
    }

    #[inline]
    pub fn key_id(&self) -> u8 {
        self.key_id
    }

    #[inline]
    pub fn set_key_id(&mut self, key_id: u8) {
        self.key_id = key_id;
    }

    #[inline]
    pub fn next_key_id(&self) -> u8 {
        self.next_key_id
    }

    #[inline]
    pub fn set_next_key_id(&mut self, key_id: u8) {
        self.next_key_id = key_id;
    }

    #[inline]
    pub fn mac(&self) -> &Buffer<u8, 36> {
        &self.mac
    }

    #[inline]
    pub fn mac_mut(&mut self) -> &mut Buffer<u8, 36> {
        &mut self.mac
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionUnknown {
    pub kind: u8,
    pub value: Buffer<u8, 38>, // 40 bytes maximum in options, minus 2 for `kind` and `length`
}

impl TcpOptionUnknown {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[self.kind, self.byte_len() as u8])?;
        writer.write(self.value.as_slice())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert!(data[1] >= 2);

        let mut value = Buffer::new();
        value.append(&data[2..data[1] as usize]);

        Self {
            kind: data[0],
            value,
        }
    }

    pub fn validate(data: &[u8]) -> Result<(), ValidationError> {
        let Some(&_optlen) = data.get(1) else {
            return Err(ValidationError {
                layer: Tcp::name(),
                class: ValidationErrorClass::InsufficientBytes,
                #[cfg(feature = "error_string")]
                reason: "insufficient bytes in TCP option for `length` field",
            })
        };

        todo!()
    }
}

impl TcpOptionUnknown {
    pub fn byte_len(&self) -> usize {
        2 + self.value.len()
    }
}

#[derive(Clone, Debug)]
pub struct TcpOptionPadding {
    pub padding: Buffer<u8, 39>, // 40 bytes maximum in options, minus 1 for `Eool`
}

impl TcpOptionPadding {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(self.padding.as_slice())
    }

    pub fn byte_len(&self) -> usize {
        self.padding.len()
    }
}
