// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me@nathanielbennett.com>

//! The Transmission Control Protocol (TCP) and related data structures.
//!
//!

use crate::layers::ip::{Ipv4, Ipv6, DATA_PROTO_TCP};
use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::layers::*;
use crate::utils;

use pkts_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use core::cmp;
use core::iter::Iterator;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(TcpMetadata)]
#[ref_type(TcpRef)]
pub struct Tcp {
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    reserved: u8,
    flags: TcpFlags,
    window: u16,
    chksum: Option<u16>,
    urgent_ptr: u16,
    options: TcpOptions,
    payload: Option<Box<dyn LayerObject>>,
}

impl Tcp {
    #[inline]
    pub fn sport(&self) -> u16 {
        self.sport
    }

    #[inline]
    pub fn set_sport(&mut self, sport: u16) {
        self.sport = sport;
    }

    #[inline]
    pub fn dport(&self) -> u16 {
        self.dport
    }

    #[inline]
    pub fn set_dport(&mut self, dport: u16) {
        self.dport = dport;
    }

    #[inline]
    pub fn seq(&self) -> u32 {
        self.seq
    }

    #[inline]
    pub fn set_seq(&mut self, seq: u32) {
        self.seq = seq;
    }

    #[inline]
    pub fn ack(&self) -> u32 {
        self.ack
    }

    #[inline]
    pub fn set_ack(&mut self, ack: u32) {
        self.ack = ack;
    }

    #[inline]
    pub fn data_offset(&self) -> usize {
        let options_len = self.options.byte_len();
        5 + (options_len / 4) // TODO: error condition here
    }

    #[inline]
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    #[inline]
    pub fn set_reserved(&mut self, reserved: u8) {
        self.reserved = (reserved & 0b_0000_1110) >> 1;
    }

    #[inline]
    pub fn flags(&self) -> TcpFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: TcpFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn window(&self) -> u16 {
        self.window
    }

    #[inline]
    pub fn set_window(&mut self, window: u16) {
        self.window = window;
    }

    /// Retrieves the assigned checksum for the packet, or `None` if no checksum has explicitly
    /// been assigned to the packet.
    ///
    /// By default, the TCP checksum is automatically calculated when a [`Tcp`] instance is
    /// converted to bytes, unless a checksum is pre-assigned to the instance prior to conversion.
    /// If a checksum has already been assigned to the packet, this method will return it;
    /// otherwise, it will return `None`. This means that a [`Tcp`] instance created from bytes
    /// or from a [`TcpRef`] instance will still have a checksum of `None` by default, regardless
    /// of the checksum value of the underlying bytes it was created from.
    #[inline]
    pub fn chksum(&self) -> Option<u16> {
        self.chksum
    }

    /// Assigns a checksum to be used for the packet.
    ///
    /// By default, the TCP checksum is automatically calculated when a [`Tcp`] instance is
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
    /// [`Tcp`] instance whenever the packet is converted to bytes. You shouldn't need to call
    /// this method unless you've previously explicitly assigned a checksum to the packet--either
    /// through a call to [`Tcp::set_chksum()`] or through a Builder pattern. Packets converted
    /// from bytes into [`Tcp`] instances from bytes or from a [`TcpRef`] instance will have a
    /// checksum of `None` by default.
    #[inline]
    pub fn clear_chksum(&mut self) {
        self.chksum = None;
    }

    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        self.urgent_ptr
    }

    #[inline]
    pub fn set_urgent_ptr(&mut self, urgent_ptr: u16) {
        self.urgent_ptr = urgent_ptr;
    }

    #[inline]
    pub fn options(&self) -> &TcpOptions {
        &self.options
    }

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
        ret.expect("remove_payload() called on TCP layer when layer had no payload")
    }
}

impl ToBytes for Tcp {
    #[inline]
    fn to_bytes_chksummed(&self, bytes: &mut Vec<u8>, prev: Option<(LayerId, usize)>) {
        let start = bytes.len();
        bytes.extend(self.sport.to_be_bytes());
        bytes.extend(self.dport.to_be_bytes());
        bytes.extend(self.seq.to_be_bytes());
        bytes.extend(self.ack.to_be_bytes());
        bytes.push(
            ((self.data_offset() as u8) << 4)
                | (self.reserved << 1)
                | ((self.flags.data >> 8) as u8),
        );
        bytes.push((self.flags.data & 0x00FF) as u8);
        bytes.extend(self.window.to_be_bytes());
        bytes.extend(self.chksum.unwrap_or(0).to_be_bytes());
        bytes.extend(self.urgent_ptr.to_be_bytes());
        match self.payload.as_ref() {
            None => (),
            Some(p) => p.to_bytes_chksummed(bytes, Some((Self::layer_id(), start))),
        }

        if self.chksum.is_none() {
            if let Some((id, prev_idx)) = prev {
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
                    return; // Leave the checksum as 0--we don't have an IPv4/IPv6 pseudo-header, so we can't calculate it
                };

                let chksum_field: &mut [u8; 2] =
                    &mut bytes[start + 16..start + 18].try_into().unwrap();
                *chksum_field = new_chksum.to_be_bytes();
            }
            // else don't bother calculating the checksum
        }
    }
}

impl FromBytesCurrent for Tcp {
    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let tcp = TcpRef::from_bytes_unchecked(bytes);
        Tcp {
            sport: tcp.sport(),
            dport: tcp.dport(),
            seq: tcp.seq(),
            ack: tcp.ack(),
            reserved: tcp.reserved(),
            flags: tcp.flags(),
            window: tcp.window(),
            chksum: None,
            urgent_ptr: tcp.urgent_ptr(),
            options: TcpOptions::from(tcp.options()),
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

impl CanSetPayload for Tcp {
    #[inline]
    fn can_set_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        true // any protocol may be served over TCP
    }
}

#[derive(Clone, Copy, Debug, LayerRef, StatelessLayer)]
#[owned_type(Tcp)]
#[metadata_type(TcpMetadata)]
pub struct TcpRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> TcpRef<'a> {
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("insufficient bytes in TCP layer to retrieve Source Port field"),
        )
    }

    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in TCP layer to retrieve Destination Port field"),
        )
    }

    #[inline]
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in TCP layer to retrieve Sequence Number field"),
        )
    }

    #[inline]
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in TCP layer to retrieve Acknowledgement Number field"),
        )
    }

    #[inline]
    pub fn data_offset(&self) -> usize {
        (self
            .data
            .get(12)
            .expect("insufficient bytes in TCP layer to retrieve Data Offset field")
            >> 4) as usize
    }

    #[inline]
    pub fn reserved(&self) -> u8 {
        (self
            .data
            .get(12)
            .expect("insufficient bytes in TCP layer to retrieve Reserved field")
            & 0b_0000_1110)
            >> 1
    }

    #[inline]
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::from(u16::from_be_bytes(
            utils::to_array(self.data, 12)
                .expect("insufficient bytes in TCP layer to retrieve TCP Flags"),
        ))
    }

    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 14)
                .expect("insufficient bytes in TCP layer to retrieve Window Size field"),
        )
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in TCP layer to retrieve Checksum field"),
        )
    }

    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in TCP layer to retrieve Urgent Pointer field"),
        )
    }

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

impl LayerOffset for TcpRef<'_> {
    #[inline]
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
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let header_len = match curr_layer.get(12) {
            None => {
                return Err(ValidationError {
                    layer: Tcp::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
                    reason:
                        "packet too short for TCP frame--missing Data Offset byte in TCP header",
                })
            }
            Some(l) => (l >> 4) as usize * 4,
        };

        if curr_layer.len() < header_len {
            return Err(ValidationError {
                layer: Tcp::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes for TCP packet header",
            });
        }

        if header_len < 20 {
            // Header length field must be at least 5 (so that corresponding header length is min required 20 bytes)
            return Err(ValidationError {
                layer: Tcp::name(),
                err_type: ValidationErrorType::InvalidValue,
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

impl<'a> From<&'a TcpMut<'a>> for TcpRef<'a> {
    #[inline]
    fn from(value: &'a TcpMut<'a>) -> Self {
        TcpRef {
            data: &value.data[..value.len],
        }
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[ref_type(TcpRef)]
#[owned_type(Tcp)]
#[metadata_type(TcpMetadata)]
pub struct TcpMut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    len: usize,
}

impl<'a> TcpMut<'a> {
    #[inline]
    pub fn sport(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 0)
                .expect("insufficient bytes in TcpMut to retrieve Source Port field"),
        )
    }

    #[inline]
    pub fn set_sport(&mut self, sport: u16) {
        let arr = utils::get_mut_array(self.data, 0)
            .expect("insufficient bytes in TcpMut to set Source Port field");
        *arr = sport.to_be_bytes()
    }

    #[inline]
    pub fn dport(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 2)
                .expect("insufficient bytes in TcpMut to retrieve Destination Port field"),
        )
    }

    #[inline]
    pub fn set_dport(&mut self, dport: u16) {
        let arr = utils::get_mut_array(self.data, 2)
            .expect("insufficient bytes in TcpMut to set Destination Port field");
        *arr = dport.to_be_bytes()
    }

    #[inline]
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in TcpMut to retrieve Sequence Number field"),
        )
    }

    #[inline]
    pub fn set_seq(&mut self, seq: u32) {
        let arr = utils::get_mut_array(self.data, 4)
            .expect("insufficient bytes in TcpMut to set Destination Port field");
        *arr = seq.to_be_bytes()
    }

    #[inline]
    pub fn ack(&self) -> u32 {
        u32::from_be_bytes(
            utils::to_array(self.data, 4)
                .expect("insufficient bytes in TcpMut to retrieve Acknowledgement Number field"),
        )
    }

    #[inline]
    pub fn set_ack(&mut self, ack: u32) {
        let arr = utils::get_mut_array(self.data, 8)
            .expect("insufficient bytes in TcpMut to set Destination Port field");
        *arr = ack.to_be_bytes()
    }

    #[inline]
    pub fn data_offset(&self) -> usize {
        (self
            .data
            .get(12)
            .expect("insufficient bytes in TcpMut to retrieve Data Offset field")
            >> 4) as usize
    }

    #[inline]
    pub fn set_data_offset(&mut self, offset: u8) {
        debug_assert!(offset <= 0b_0000_1111);
        let off_ref = self
            .data
            .get_mut(12)
            .expect("insufficient bytes in TcpMut to set Data Offset field");
        *off_ref &= 0b_0000_1111;
        *off_ref |= offset << 4;
    }

    #[inline]
    pub fn reserved(&self) -> u8 {
        (self
            .data
            .get(12)
            .expect("insufficient bytes in TcpMut to retrieve Reserved field")
            & 0b_0000_1110)
            >> 1
    }

    #[inline]
    pub fn set_reserved(&mut self, reserved: u8) {
        debug_assert!(reserved <= 0b_0000_0111);
        let off_ref = self
            .data
            .get_mut(12)
            .expect("insufficient bytes in TcpMut to set Reserved field");
        *off_ref &= 0b_1111_0001;
        *off_ref |= reserved << 1;
    }

    #[inline]
    pub fn flags(&self) -> TcpFlags {
        TcpFlags::from(u16::from_be_bytes(
            utils::to_array(self.data, 12)
                .expect("insufficient bytes in TcpMut to retrieve TCP Flags"),
        ))
    }

    #[inline]
    pub fn set_flags(&mut self, flags: TcpFlags) {
        let arr = utils::get_mut_array::<2>(self.data, 4)
            .expect("insufficient bytes in TcpMut to set TCP Flags");
        arr[0] &= 0b_1111_1110;
        arr[0] |= ((flags.data >> 8) as u8) & 0b_0000_0001;
        arr[1] = (flags.data & 0x00FF) as u8;
    }

    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 14)
                .expect("insufficient bytes in TcpMut to retrieve Window Size field"),
        )
    }

    #[inline]
    pub fn set_window(&mut self, window: u16) {
        let arr = utils::get_mut_array(self.data, 4)
            .expect("insufficient bytes in TcpMut to set Window Size field");
        *arr = window.to_be_bytes()
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in TcpMut to retrieve Checksum field"),
        )
    }

    /// Sets the one's complement checksum to be used for the packet.
    ///
    /// Checksums are _not_ automatically generated for [`TcpMut`] instances,
    /// so any changes in a TCP packet's contents--including source or destination
    /// IP address or IP protocol type--should be followed by a corresponding change
    /// in the checksum as well. Checksums _are_ automatically generated for [`Tcp`]
    /// instances, so consider using it instead of this interface if ease of use is
    /// more of a priority than raw speed and performance.
    #[inline]
    pub fn set_chksum(&mut self, chksum: u16) {
        let arr = utils::get_mut_array(self.data, 8)
            .expect("insufficient bytes in TcpMut to set Checksum field");
        *arr = chksum.to_be_bytes()
    }

    #[inline]
    pub fn urgent_ptr(&self) -> u16 {
        u16::from_be_bytes(
            utils::to_array(self.data, 16)
                .expect("insufficient bytes in TcpMut to retrieve Urgent Pointer field"),
        )
    }

    #[inline]
    pub fn set_urgent_ptr(&mut self, urgent_ptr: u16) {
        let arr = utils::get_mut_array(self.data, 8)
            .expect("insufficient bytes in TcpMut to set Urgent Pointer field");
        *arr = urgent_ptr.to_be_bytes()
    }

    #[inline]
    pub fn options(&'a self) -> TcpOptionsRef<'a> {
        let end = cmp::max(self.data_offset(), 5) * 4;
        TcpOptionsRef::from_bytes_unchecked(
            self.data
                .get(20..end)
                .expect("insufficient bytes in TcpMut to retrieve TCP Options"),
        )
    }

    /*
    #[inline]
    pub fn set_options(&mut self, options: TcpOptionsRef<'_>) {
        todo!()
    }
    */
}

impl<'a> FromBytesMut<'a> for TcpMut<'a> {
    #[inline]
    fn from_bytes_trailing_unchecked(bytes: &'a mut [u8], length: usize) -> Self {
        TcpMut {
            len: length,
            data: bytes,
        }
    }
}

// =============================================================================
//                         Inner Field Data Structures
// =============================================================================

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpFlags {
    data: u16,
}

const NS_BIT: u16 = 0b_0000_0001_0000_0000;
const CWR_BIT: u16 = 0b_0000_0000_1000_0000;
const ECE_BIT: u16 = 0b_0000_0000_0100_0000;
const URG_BIT: u16 = 0b_0000_0000_0010_0000;
const ACK_BIT: u16 = 0b_0000_0000_0001_0000;
const PSH_BIT: u16 = 0b_0000_0000_0000_1000;
const RST_BIT: u16 = 0b_0000_0000_0000_0100;
const SYN_BIT: u16 = 0b_0000_0000_0000_0010;
const FIN_BIT: u16 = 0b_0000_0000_0000_0001;

impl TcpFlags {
    #[inline]
    pub fn new() -> Self {
        TcpFlags::default()
    }

    #[inline]
    pub fn ns(&self) -> bool {
        self.data & NS_BIT > 0
    }

    #[inline]
    pub fn set_ns(&mut self, ns: bool) {
        if ns {
            self.data |= NS_BIT;
        } else {
            self.data &= !NS_BIT;
        }
    }

    #[inline]
    pub fn cwr(&self) -> bool {
        self.data & CWR_BIT > 0
    }

    #[inline]
    pub fn set_cwr(&mut self, cwr: bool) {
        if cwr {
            self.data |= CWR_BIT;
        } else {
            self.data &= !CWR_BIT;
        }
    }

    #[inline]
    pub fn ece(&self) -> bool {
        self.data & ECE_BIT > 0
    }

    #[inline]
    pub fn set_ece(&mut self, ece: bool) {
        if ece {
            self.data |= ECE_BIT;
        } else {
            self.data &= !ECE_BIT;
        }
    }

    #[inline]
    pub fn urg(&self) -> bool {
        self.data & URG_BIT > 0
    }

    #[inline]
    pub fn set_urg(&mut self, urg: bool) {
        if urg {
            self.data |= URG_BIT;
        } else {
            self.data &= !URG_BIT;
        }
    }

    #[inline]
    pub fn ack(&self) -> bool {
        self.data & ACK_BIT > 0
    }

    #[inline]
    pub fn set_ack(&mut self, ack: bool) {
        if ack {
            self.data |= ACK_BIT;
        } else {
            self.data &= !ACK_BIT;
        }
    }

    #[inline]
    pub fn psh(&self) -> bool {
        self.data & PSH_BIT > 0
    }

    #[inline]
    pub fn set_psh(&mut self, psh: bool) {
        if psh {
            self.data |= PSH_BIT;
        } else {
            self.data &= !PSH_BIT;
        }
    }

    #[inline]
    pub fn rst(&self) -> bool {
        self.data & RST_BIT > 0
    }

    #[inline]
    pub fn set_rst(&mut self, rst: bool) {
        if rst {
            self.data |= RST_BIT;
        } else {
            self.data &= !RST_BIT;
        }
    }

    #[inline]
    pub fn syn(&self) -> bool {
        self.data & SYN_BIT > 0
    }

    #[inline]
    pub fn set_syn(&mut self, syn: bool) {
        if syn {
            self.data |= SYN_BIT;
        } else {
            self.data &= !SYN_BIT;
        }
    }

    #[inline]
    pub fn fin(&self) -> bool {
        self.data & FIN_BIT > 0
    }

    #[inline]
    pub fn set_fin(&mut self, ns: bool) {
        if ns {
            self.data |= FIN_BIT;
        } else {
            self.data &= !FIN_BIT;
        }
    }
}

impl From<u16> for TcpFlags {
    fn from(value: u16) -> Self {
        TcpFlags {
            data: value & 0b_0000_0001_1111_1111,
        }
    }
}

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
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(TcpOptionsRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        TcpOptionsRef::validate(bytes)
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        let padding_len = self.padding.as_ref().map(|p| p.len()).unwrap_or(0);
        let options_len = self
            .options
            .as_ref()
            .map(|opts| opts.iter().map(|opt| opt.byte_len()).sum())
            .unwrap_or(0);
        options_len + padding_len
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
        match self.options.as_ref() {
            None => (),
            Some(options) => {
                for option in options.iter() {
                    option.to_bytes_extended(bytes);
                }

                match self.padding.as_ref() {
                    None => (),
                    Some(p) => bytes.extend(p),
                }
            }
        }
    }
}

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

impl From<TcpOptionsRef<'_>> for TcpOptions {
    fn from(value: TcpOptionsRef<'_>) -> Self {
        Self::from(&value)
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
                err_type: ValidationErrorType::InvalidValue,
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
                            err_type: ValidationErrorType::InvalidValue,
                            reason: "TCP option length field contained too small a value",
                        })
                    }
                    Some(&len) => match bytes.get(len as usize..) {
                        Some(remaining) => bytes = remaining,
                        None => return Err(ValidationError {
                            layer: Tcp::name(),
                            err_type: ValidationErrorType::InvalidValue,
                            reason:
                                "truncated TCP option field in options--missing part of option data",
                        }),
                    },
                    None => {
                        return Err(ValidationError {
                            layer: Tcp::name(),
                            err_type: ValidationErrorType::InvalidValue,
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
        let mut iter = self.iter();
        while iter.next().is_some() {}
        &iter.bytes[iter.curr_idx..]
    }
}

pub struct TcpOptionsIterRef<'a> {
    curr_idx: usize,
    bytes: &'a [u8],
    end_reached: bool,
}

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
}

#[derive(Clone, Debug)]
pub struct TcpOption {
    option_type: u8,
    value: Option<Vec<u8>>,
}

impl TcpOption {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        TcpOption {
            option_type: bytes[0],
            value: if bytes[0] == TcpOptionType::Eool as u8 || bytes[0] == TcpOptionType::Noop as u8
            {
                None
            } else {
                Some(Vec::from(&bytes[2..(bytes[1] as usize)]))
            },
        }
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        TcpOptionRef::validate(bytes)
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        match self.option_type {
            0 | 1 => 1,
            _ => 2 + self.value.as_ref().map(|v| v.len()).unwrap_or(0),
        }
    }

    #[inline]
    pub fn option_type(&self) -> u8 {
        self.option_type
    }

    #[inline]
    pub fn option_length(&self) -> usize {
        match self.option_type {
            0 | 1 => 1,
            _ => self.value.as_ref().unwrap().len() + 2,
        }
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
}

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

pub struct TcpOptionRef<'a> {
    bytes: &'a [u8],
}

impl<'a> TcpOptionRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        TcpOptionRef { bytes }
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match bytes.first() {
            Some(0 | 1) => if bytes.len() == 1 {
                Ok(())
            } else {
                Err(ValidationError {
                    layer: Tcp::name(),
                    err_type: ValidationErrorType::ExcessBytes(bytes.len() - 1),
                    reason: "excess bytes at end of single-byte TCP option"
                })
            },
            Some(_) => match bytes.get(1) {
                Some(&len @ 2..) if bytes.len() >= len as usize => match bytes.len().checked_sub(len as usize) {
                    Some(0) => Ok(()),
                    Some(remaining) => Err(ValidationError {
                        layer: Tcp::name(),
                        err_type: ValidationErrorType::ExcessBytes(remaining),
                        reason: "excess bytes at end of sized TCP option",
                    }),
                    None => Err(ValidationError {
                        layer: Tcp::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "length of TCP Option data exceeded available bytes"
                    }),
                },
                _ => Err(ValidationError {
                    layer: Tcp::name(),
                    err_type: ValidationErrorType::InvalidValue,
                    reason: "insufficient bytes available to read TCP Option--missing length byte field"
                }),
            },
            None => Err(ValidationError {
                layer: Tcp::name(),
                err_type: ValidationErrorType::InvalidValue,
                reason: "insufficient bytes available to read TCP Option--missing option_type byte field",
            })
        }
    }

    #[inline]
    pub fn option_len(&self) -> usize {
        self.bytes.len()
    }

    #[inline]
    pub fn option_type(&self) -> u8 {
        self.bytes[0]
    }

    #[inline]
    pub fn option_data(&self) -> &[u8] {
        match &self.bytes[0] {
            0 | 1 => &[],
            _ => &self.bytes[2..self.bytes[1] as usize],
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpOptionType {
    Eool = 0,
    Noop = 1,
    Mss = 2,
    Wscale = 3,
    SackPermitted = 4,
    Sack = 5,
    Timestamp = 8,
}
