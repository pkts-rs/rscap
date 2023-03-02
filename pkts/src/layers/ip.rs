// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me@nathanielbennett.com>

use core::iter::Iterator;
use core::fmt::Debug;
use core::{cmp, mem};

use pkts_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::error::*;

use super::sctp::{SctpRef, Sctp};
use super::tcp::{Tcp, TcpRef};
use super::udp::{Udp, UdpRef};
use super::{Raw, RawRef};

/// The Version number of an Internet Protocol (IP) packet.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpVersion {
    /// Reserved (0x0); Internet Protocol, pre-v4
    R0 = 0,
    /// Unassigned (0x1)
    U1 = 1,
    /// Unassigned (0x2)
    U2 = 2,
    /// Unassigned (0x3)
    U3 = 3,
    /// Internet Protocol, Version 4 (see RFC 760)
    Ipv4 = 4,
    /// Internet Stream Protocol (ST or ST-II) (see RFC 1819)
    St = 5,
    /// Internet Protocol, Version 6 (see RFC 2460)
    Ipv6 = 6,
    /// TP/IX The Next Internet (IPv7) (see RVC 1475)
    Tpix = 7,
    /// P Internet Protocol (see RFC 1621)
    Pip = 8,
    /// TCP and UDP over Bigger Addresses (TUBA) (see RFC 1347)
    Tuba = 9,
    /// Unassigned (0xA)
    U10 = 10,
    /// Unassigned (0xB)
    U11 = 11,
    /// Unassigned (0xC)
    U12 = 12,
    /// Unassigned (0xD)
    U13 = 13,
    /// Unassigned (0xE)
    U14 = 14,
    /// Reserved (0xF); version field sentinel value
    R15 = 15,
}

impl From<u8> for IpVersion {
    /// Uses the least significant 4 bytes of `value` to determine the internet protocol version.
    #[inline]
    fn from(value: u8) -> Self {
        // SAFETY: all enum variants from 0x00 to 0x0F are defined
        unsafe { mem::transmute(value & 0x0F) }
    }
}

/// An IPv4 (Internet Protocol version 4) packet.
#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(Ipv4Metadata)]
#[ref_type(Ipv4Ref)]
pub struct Ipv4 {
    // version, ihl, length, protocol, and checksum all calculated dynamically
    dscp: DiffServ, // also known as ToS
    ecn: Ecn,
    id: u16,
    flags: Ipv4Flags,
    frag_offset: u16,
    ttl: u8,
    chksum: u16,
    saddr: u32,
    daddr: u32,
    options: Ipv4Options,
    payload: Option<Box<dyn LayerObject>>,
}

impl Ipv4 {
    #[inline]
    pub fn ihl(&self) -> u8 {
        self.options.byte_len() as u8 // TODO: use expect() here
    }

    #[inline]
    pub fn dscp(&self) -> DiffServ {
        self.dscp
    }

    #[inline]
    pub fn set_dscp(&mut self, dscp: DiffServ) {
        self.dscp = dscp;
    }

    #[inline]
    pub fn ecn(&self) -> Ecn {
        self.ecn
    }

    #[inline]
    pub fn set_ecn(&mut self, ecn: Ecn) {
        self.ecn = ecn;
    }

    #[inline]
    pub fn total_length(&self) -> u16 {
        todo!()
    }

    #[inline]
    pub fn identifier(&self) -> u16 {
        self.id
    }

    #[inline]
    pub fn set_identifier(&mut self, id: u16) {
        self.id = id;
    }

    #[inline]
    pub fn flags(&self) -> Ipv4Flags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: Ipv4Flags) {
        self.flags = flags;
    }

    #[inline]
    pub fn frag_offset(&self) -> u16 {
        self.frag_offset
    }

    #[inline]
    pub fn set_frag_offset(&mut self, offset: u16) {
        assert!(offset <= 0b_0001_1111_1111_1111);
        self.frag_offset = offset;
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.ttl
    }

    #[inline]
    pub fn set_ttl(&mut self, ttl: u8) {
        self.ttl = ttl;
    }

    #[inline]
    pub fn protocol(&self) -> Ipv4DataProtocol {
        match self.payload.as_ref() {
            None => Ipv4DataProtocol::Exp1,
            Some(p) => {
                let payload_metadata = p
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn Ipv4PayloadMetadata>()
                    .expect("unknown payload protocol found in IPv4 packet");
                payload_metadata.ip_data_protocol()
            }
        }
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        self.chksum
    }

    #[inline]
    pub fn set_chksum(&mut self, chksum: u16) {
        self.chksum = chksum;
    }

    #[inline]
    pub fn saddr(&self) -> u32 {
        self.saddr
    }

    #[inline]
    pub fn set_saddr(&mut self, saddr: u32) {
        self.saddr = saddr;
    }

    #[inline]
    pub fn daddr(&self) -> u32 {
        self.daddr
    }

    #[inline]
    pub fn set_daddr(&mut self, daddr: u32) {
        self.daddr = daddr;
    }
}

impl CanSetPayload for Ipv4 {
    #[inline]
    fn can_set_payload_default(&self, payload: &dyn LayerObject) -> bool {
        payload
            .layer_metadata()
            .as_any()
            .downcast_ref::<&dyn Ipv4PayloadMetadata>()
            .is_some()
    }
}

impl FromBytesCurrent for Ipv4 {
    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let ipv4 = Ipv4Ref::from_bytes_unchecked(bytes);
        Ipv4 {
            dscp: ipv4.dscp(),
            ecn: ipv4.ecn(),
            id: ipv4.identifier(),
            flags: ipv4.flags(),
            frag_offset: ipv4.frag_offset(),
            ttl: ipv4.ttl(),
            chksum: ipv4.chksum(),
            saddr: ipv4.saddr(),
            daddr: ipv4.daddr(),
            options: Ipv4Options::from(ipv4.options()),
            payload: None,
        }
    }

    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        let ipv4 = Ipv4Ref::from_bytes_unchecked(bytes);
        if ipv4.payload_raw().is_empty() {
            self.payload = None;
        } else {
            self.payload = match ipv4.protocol() {
                Ipv4DataProtocol::Tcp => {
                    Some(Box::new(Tcp::from_bytes_unchecked(ipv4.payload_raw())))
                }
                Ipv4DataProtocol::Udp => {
                    Some(Box::new(Udp::from_bytes_unchecked(ipv4.payload_raw())))
                }
                Ipv4DataProtocol::Sctp => {
                    Some(Box::new(Sctp::from_bytes_unchecked(ipv4.payload_raw())))
                }
                /* Add additional protocols here */
                _ => Some(Box::new(Raw::from_bytes_unchecked(ipv4.payload_raw()))),
            };
        }
    }
}

impl LayerLength for Ipv4 {
    /// The total length (in bytes) of the Ipv4 header and payload.
    fn len(&self) -> usize {
        20 + self.options.byte_len()
            + match self.payload.as_ref() {
                Some(p) => p.len(),
                None => 0,
            }
    }
}

impl LayerObject for Ipv4 {
    #[inline]
    fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
        self.payload.as_deref()
    }

    #[inline]
    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        self.payload.as_deref_mut()
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
        ret.expect("remove_payload() called on IPv4 layer when layer had no payload")
    }
}

impl ToBytes for Ipv4 {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.push(0x40 | (5 + (self.options.byte_len() / 4) as u8));
        bytes.push((self.dscp.dscp() << 2) | self.ecn as u8);
        bytes.extend(u16::try_from(self.len()).unwrap_or(0xFFFF).to_be_bytes()); // WARNING: packets with contents greater than 65535 bytes will have their length field truncated
        bytes.extend(self.id.to_be_bytes());
        bytes.extend((((self.flags.flags as u16) << 8) | self.frag_offset).to_be_bytes());
        bytes.push(self.ttl);
        bytes.push(
            self.payload
                .as_ref()
                .map(|p| {
                    p.layer_metadata()
                        .as_any()
                        .downcast_ref::<&dyn Ipv4PayloadMetadata>()
                        .map(|m| m.ip_data_protocol())
                        .expect("unknown payload protocol found in IPv4 packet")
                })
                .unwrap_or(Ipv4DataProtocol::Exp1) as u8,
        ); // 0xFD when no payload specified
        bytes.extend(self.chksum.to_be_bytes());
        bytes.extend(self.saddr.to_be_bytes());
        bytes.extend(self.daddr.to_be_bytes());
        self.options.to_bytes_extended(bytes);
        if let Some(payload) = self.payload.as_ref() {
            payload.to_bytes_extended(bytes)
        }
    }
}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Ipv4)]
#[metadata_type(Ipv4Metadata)]
pub struct Ipv4Ref<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> Ipv4Ref<'a> {
    #[inline]
    pub fn version(&self) -> u8 {
        self.data
            .first()
            .expect("insufficient bytes in Ipv4Ref to retrieve IP Version field")
            >> 4
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        self.data
            .first()
            .expect("insufficient bytes in Ipv4Ref to retrieve Internet Header Length field")
            & 0x0F
    }

    #[inline]
    pub fn dscp(&self) -> DiffServ {
        DiffServ::from(*self.data.get(1).expect("insufficient bytes in Ipv4Ref to retrieve Differentiated Services Code Point (DSCP) field"))
    }

    #[inline]
    pub fn ecn(&self) -> Ecn {
        Ecn::from(*self.data.get(1).expect(
            "insufficient bytes in Ipv4Ref to retrieve Explicit Congestion Notification field",
        ))
    }

    #[inline]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.data[2..4].try_into().unwrap())
    }

    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes(self.data[4..6].try_into().unwrap())
    }

    #[inline]
    pub fn flags(&self) -> Ipv4Flags {
        Ipv4Flags::from(self.data[6])
    }

    #[inline]
    pub fn frag_offset(&self) -> u16 {
        u16::from_be_bytes(self.data[6..8].try_into().unwrap()) & 0b0001111111111111
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    #[inline]
    pub fn protocol(&self) -> Ipv4DataProtocol {
        self.data[9].into()
    }

    #[inline]
    pub fn protocol_raw(&self) -> u8 {
        self.data[9]
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(self.data[10..12].try_into().unwrap())
    }

    #[inline]
    pub fn saddr(&self) -> u32 {
        u32::from_be_bytes(self.data[12..16].try_into().unwrap())
    }

    #[inline]
    pub fn daddr(&self) -> u32 {
        u32::from_be_bytes(self.data[16..20].try_into().unwrap())
    }

    #[inline]
    pub fn options(&self) -> Ipv4OptionsRef<'a> {
        let options_end = core::cmp::min(self.data[0] & 0x0F, 5) as usize * 4;
        Ipv4OptionsRef::from_bytes_unchecked(&self.data[20..options_end])
    }

    #[inline]
    pub fn payload_raw(&self) -> &[u8] {
        &self.data[self.ihl() as usize * 4..]
    }
}

impl<'a> FromBytesRef<'a> for Ipv4Ref<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        Ipv4Ref { data: packet }
    }
}

impl LayerOffset for Ipv4Ref<'_> {
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        let ihl = match bytes.first() {
            Some(l) => cmp::max((l & 0x0F) as usize, 5) * 4,
            None => return None,
        };

        match bytes.get(9).map(|&b| Ipv4DataProtocol::from(b)) {
            Some(Ipv4DataProtocol::Tcp) => {
                if layer_type == TcpRef::layer_id_static() {
                    Some(ihl)
                } else {
                    TcpRef::payload_byte_index_default(&bytes[ihl..], layer_type).map(|val| ihl + val)
                }
            }
            Some(Ipv4DataProtocol::Udp) => {
                if layer_type == UdpRef::layer_id_static() {
                    Some(ihl)
                } else {
                    UdpRef::payload_byte_index_default(&bytes[ihl..], layer_type).map(|val| ihl + val)
                }
            }
            Some(Ipv4DataProtocol::Sctp) => {
                if layer_type == SctpRef::layer_id_static() {
                    Some(ihl)
                } else {
                    SctpRef::payload_byte_index_default(&bytes[ihl..], layer_type).map(|val| ihl + val)
                }
            }
            _ => {
                if layer_type == RawRef::layer_id_static() {
                    Some(ihl)
                } else {
                    None
                }
            }
        }
    }
}

impl Validate for Ipv4Ref<'_> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let (version, ihl) =
            match curr_layer.first() {
                None => return Err(ValidationError {
                    layer: Ipv4::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
                    reason:
                        "packet too short for Ipv4 frame--missing version/IHL byte in Ipv4 header",
                }),
                Some(&b) => (b >> 4, (b & 0x0F) as usize * 4),
            };

        let total_length = match curr_layer
            .get(2..4)
            .and_then(|s| <[u8; 2]>::try_from(s).ok())
        {
            None => {
                return Err(ValidationError {
                    layer: Ipv4::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
                    reason:
                        "packet too short for Ipv4 frame--missing length field bytes in Ipv4 header",
                })
            }
            Some(s) => u16::from_be_bytes(s) as usize,
        };

        if total_length > curr_layer.len() {
            return Err(ValidationError {
                layer: Ipv4::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "total packet length reported in Ipv4 header exceeded the available bytes",
            });
        }

        // Now that InvalidSize errors have been checked, we validate values
        if version != 4 {
            // Version number not 4 (required for Ipv4)
            return Err(ValidationError {
                layer: Ipv4::name(),
                err_type: ValidationErrorType::InvalidValue,
                reason: "version number of Ipv4 header was not equal to 0x04",
            });
        }

        if ihl < 20 {
            // Header length field must be at least 5 (so that corresponding header length is min required 20 bytes)
            return Err(ValidationError {
                layer: Ipv4Ref::name(),
                err_type: ValidationErrorType::InvalidValue,
                reason: "invalid Ipv4 header length value (IHL must be a value of 5 or more)",
            });
        }

        // Validate Ipv4 Options
        let mut remaining_header = &curr_layer[20..ihl];
        while let Some((&option_type, next)) = remaining_header.split_first() {
            match option_type {
                0 => break, // Eool
                1 => remaining_header = next, // Nop
                _ => match remaining_header.get(1) {
                    None => return Err(ValidationError {
                        layer: Ipv4Ref::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "length field missing from Ipv4 Option",
                    }),
                    Some(0..=1) => return Err(ValidationError {
                        layer: Ipv4Ref::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid value in Ipv4 Option length field (must be at least 2)",
                    }),
                    Some(&l) => remaining_header = match remaining_header.get(l as usize..) {
                        None => return Err(ValidationError {
                        layer: Ipv4Ref::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "invalid length field in Ipv4 Option--insufficient option bytes available for specified length",
                        }),
                        Some(r) => r,
                    },
                }
            }
        }

        // Lastly, validate for ExcessBytes
        if total_length < curr_layer.len() {
            Err(ValidationError {
                layer: Ipv4Ref::name(),
                err_type: ValidationErrorType::ExcessBytes(curr_layer.len() - total_length),
                reason:
                    "invalid length field in Ipv4 header--extra bytes remaining at end of packet",
            })
        } else {
            Ok(())
        }
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        let ihl =
            match curr_layer.first() {
                Some(l) => (l & 0x0F) as usize * 4,
                None => return Err(ValidationError {
                    layer: Ipv4Ref::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
                    reason:
                        "packet too short for Ipv4 frame--missing version/IHL byte in Ipv4 header",
                }),
            };

        let next_layer =
            match curr_layer.get(ihl..) {
                Some(l) => l,
                None => return Err(ValidationError {
                    layer: Ipv4Ref::name(),
                    err_type: ValidationErrorType::InsufficientBytes,
                    reason:
                        "packet too short for Ipv4 frame--insufficient bytes available for header",
                }),
            };

        match curr_layer.get(9).map(|&b| Ipv4DataProtocol::from(b)) {
            Some(Ipv4DataProtocol::Tcp) => TcpRef::validate(next_layer),
            Some(Ipv4DataProtocol::Udp) => UdpRef::validate(next_layer),
            Some(Ipv4DataProtocol::Sctp) => SctpRef::validate(next_layer),
            /* Add more Layer types here */
            _ => RawRef::validate(next_layer),
        }
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[owned_type(Ipv4)]
#[ref_type(Ipv4Ref)]
#[metadata_type(Ipv4Metadata)]
pub struct Ipv4Mut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    len: usize,
}

impl<'a> From<&'a Ipv4Mut<'a>> for Ipv4Ref<'a> {
    #[inline]
    fn from(value: &'a Ipv4Mut<'a>) -> Self {
        Ipv4Ref {
            data: &value.data[..value.len],
        }
    }
}

impl<'a> FromBytesMut<'a> for Ipv4Mut<'a> {
    #[inline]
    fn from_bytes_trailing_unchecked(bytes: &'a mut [u8], length: usize) -> Self {
        Ipv4Mut {
            data: bytes,
            len: length,
        }
    }
}

impl<'a> Ipv4Mut<'a> {
    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    #[inline]
    pub fn set_version_unchecked(&mut self, version: IpVersion) {
        self.data[0] &= 0x0F;
        self.data[0] |= (version as u8) << 4;
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        self.data[0] & 0x0F
    }

    #[inline]
    pub fn set_ihl_unchecked(&mut self, ihl: u8) {
        self.data[0] &= 0xF0;
        self.data[0] |= ihl & 0x0F;
    }

    #[inline]
    pub fn dscp(&self) -> DiffServ {
        DiffServ::from(self.data[1])
    }

    #[inline]
    pub fn set_dscp(&mut self, dscp: DiffServ) {
        self.data[1] &= 0b0000_0011;
        self.data[1] |= dscp.dscp & 0b1111_1100;
    }

    #[inline]
    pub fn ecn(&self) -> Ecn {
        Ecn::from(self.data[1])
    }

    #[inline]
    pub fn set_ecn(&mut self, ecn: Ecn) {
        self.data[1] &= 0b1111_1100;
        self.data[1] |= ecn as u8 & 0b0000_0011;
    }

    #[inline]
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes(self.data[2..4].try_into().unwrap())
    }

    #[inline]
    pub fn set_total_length(&mut self, len: u16) {
        self.data[2] = (len >> 8) as u8;
        self.data[3] = (len & 0xFF) as u8;
    }

    #[inline]
    pub fn identifier(&self) -> u16 {
        u16::from_be_bytes(self.data[4..6].try_into().unwrap())
    }

    #[inline]
    pub fn set_identifier(&mut self, id: u16) {
        self.data[4] = (id >> 8) as u8;
        self.data[5] = (id & 0x00FF) as u8;
    }

    #[inline]
    pub fn flags(&self) -> Ipv4Flags {
        Ipv4Flags::from(self.data[6])
    }

    #[inline]
    pub fn set_flags(&mut self, flags: Ipv4Flags) {
        self.data[6] &= 0b_0001_1111;
        self.data[6] |= flags.flags;
    }

    #[inline]
    pub fn frag_offset(&self) -> u16 {
        u16::from_be_bytes(self.data[6..8].try_into().unwrap()) & 0b_0001_1111_1111_1111
    }

    #[inline]
    pub fn set_frag_offset(&mut self, offset: u16) {
        self.data[6] &= 0b_1110_0000;
        self.data[6] |= ((offset << 8) as u8) & 0b_0001_1111;
        self.data[7] = (offset & 0x00FF) as u8;
    }

    #[inline]
    pub fn ttl(&self) -> u8 {
        self.data[8]
    }

    #[inline]
    pub fn set_ttl(&mut self, ttl: u8) {
        self.data[8] = ttl;
    }

    #[inline]
    pub fn set_protocol(&mut self, proto: Ipv4DataProtocol) {
        self.data[9] = proto as u8;
    }

    #[inline]
    pub fn protocol_raw(&self) -> u8 {
        self.data[9]
    }

    #[inline]
    pub fn set_protocol_raw(&mut self, proto: u8) {
        self.data[9] = proto;
    }

    #[inline]
    pub fn chksum(&self) -> u16 {
        u16::from_be_bytes(self.data[10..12].try_into().unwrap())
    }

    #[inline]
    pub fn set_chksum(&mut self, chksum: u16) {
        self.data[10] = (chksum >> 8) as u8;
        self.data[11] = (chksum & 0x00FF) as u8;
    }

    #[inline]
    pub fn saddr(&self) -> u32 {
        u32::from_be_bytes(self.data[12..16].try_into().unwrap())
    }

    #[inline]
    pub fn set_saddr(&mut self, saddr: u32) {
        self.data[12] = (saddr >> 24) as u8;
        self.data[13] = ((saddr >> 16) & 0x000000FF) as u8;
        self.data[14] = ((saddr >> 8) & 0x000000FF) as u8;
        self.data[15] = (saddr & 0x000000FF) as u8;
    }

    #[inline]
    pub fn daddr(&self) -> u32 {
        u32::from_be_bytes(self.data[16..20].try_into().unwrap())
    }

    #[inline]
    pub fn set_daddr(&mut self, daddr: u32) {
        self.data[16] = (daddr >> 24) as u8;
        self.data[17] = ((daddr >> 16) & 0x000000FF) as u8;
        self.data[18] = ((daddr >> 8) & 0x000000FF) as u8;
        self.data[19] = (daddr & 0x000000FF) as u8;
    }

    #[inline]
    pub fn options(&'a self) -> Ipv4OptionsRef<'a> {
        let options_end = core::cmp::min(self.ihl(), 5) as usize * 4;
        Ipv4OptionsRef::from_bytes_unchecked(&self.data[20..options_end])
    }

    #[inline]
    pub fn options_mut(&'a mut self) -> Ipv4OptionsMut<'a> {
        let options_end = core::cmp::min(self.ihl(), 5) as usize * 4;
        Ipv4OptionsMut::from_bytes_unchecked(&mut self.data[20..options_end])
    }

    /*
    pub fn set_options(&mut self, options: Ipv4OptionRef<'_>) {
        todo!()
    }
    */

    #[inline]
    pub fn payload(&self) -> &[u8] {
        &self.data[self.ihl() as usize * 4..]
    }

    pub fn set_payload_unchecked(&mut self, payload: &[u8]) {
        let payload_idx = self.ihl() as usize * 4;
        let payload_destination = self
            .data
            .get_mut(payload_idx..payload_idx + payload.len())
            .expect("insufficient bytes in Ipv4Mut buffer to set payload");
        for (&src, dst) in payload.iter().zip(payload_destination) {
            *dst = src;
        }
        self.len = payload_idx + payload.len();
    }
}

// =============================================================================
//                              INTERNAL FIELDS
// =============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiffServ {
    dscp: u8,
}

impl From<u8> for DiffServ {
    fn from(value: u8) -> Self {
        DiffServ { dscp: value >> 2 }
    }
}

impl DiffServ {
    pub fn dscp(&self) -> u8 {
        self.dscp
    }
}

/// Explicit Congestion Notification (ECN) values available in an Ipv4 packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ecn {
    /// Non ECN-Capable Transport
    NonEct = 0b00,
    /// ECN Capable Transport, ECT(0)
    Ect0 = 0b10,
    /// ECN Capable Transport, ECT(1)
    Ect1 = 0b01,
    /// Congestion Encountered
    CgstEnc = 0b11,
}

impl From<u8> for Ecn {
    /// Converts the least significant two bits of the given byte into Explicit Congestion
    /// Notification flags.
    fn from(value: u8) -> Self {
        match (value & 0b10 > 0, value & 0b01 > 0) {
            (false, false) => Ecn::NonEct,
            (false, true) => Ecn::Ect0,
            (true, false) => Ecn::Ect1,
            (true, true) => Ecn::CgstEnc,
        }
    }
}

const RESERVED_BIT: u8 = 0b10000000;
const DONT_FRAGMENT_BIT: u8 = 0b01000000;
const MORE_FRAGMENTS_BIT: u8 = 0b00100000;

/// Flags available in an IPv4 packet
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipv4Flags {
    flags: u8,
}

impl Ipv4Flags {
    pub fn reserved(&self) -> bool {
        self.flags & RESERVED_BIT > 0
    }

    pub fn set_reserved(&mut self, reserved: bool) {
        if reserved {
            self.flags |= RESERVED_BIT
        } else {
            self.flags &= !RESERVED_BIT
        }
    }

    pub fn dont_fragment(&self) -> bool {
        self.flags & DONT_FRAGMENT_BIT > 0
    }

    pub fn set_dont_fragment(&mut self, dont_fragment: bool) {
        if dont_fragment {
            self.flags |= DONT_FRAGMENT_BIT
        } else {
            self.flags &= !DONT_FRAGMENT_BIT
        }
    }

    pub fn more_fragments(&self) -> bool {
        self.flags & MORE_FRAGMENTS_BIT > 0
    }

    pub fn set_more_fragments(&mut self, more_fragments: bool) {
        if more_fragments {
            self.flags |= MORE_FRAGMENTS_BIT
        } else {
            self.flags &= !MORE_FRAGMENTS_BIT
        }
    }
}

impl From<u8> for Ipv4Flags {
    /// Converts the most significant 3 bits of the given byte into Ipv4-specific flags.
    fn from(value: u8) -> Self {
        Ipv4Flags {
            flags: value & 0b11100000,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Ipv4DataProtocol {
    /// IPv6 Hop-by-Hop Option (see RFC 8200)
    HopOpt = 0x00,
    /// Internet Control Message Protocol (see RFC 792)
    Icmp = 0x01,
    /// Internet Group Management Protocol (see RFC 1112)
    Igmp = 0x02,
    /// Gateway-to-Gateway Protocol (see RFC 823)
    Ggp = 0x03,
    /// IP in IP encapsulation (see [`Ipv4`], [`Ipv6`], RFC 2003)
    IpInIp = 0x04,
    /// Internet Stream Protocol (see RFC 1190 and RFC 1819)
    St = 0x05,
    /// Transmission Control Protocol (see [`Tcp`], RFC 793)
    Tcp = 0x06,
    /// Core-Based Trees (see RFC 2189)
    Cbt = 0x07,
    /// Exterior Gateway Protocol (see RFC 888)
    Egp = 0x08,
    /// Interior gateway Protocol
    Igp = 0x09,
    /// BBN RCC Monitoringdata[0] & 0x0F
    BbnRccMon = 0x0A,
    /// Network Voide Protocol (see RFC 741)
    Nvp2 = 0x0B,
    /// Xerox PUP
    Pup = 0x0C,
    /// ARGUS
    Argus = 0x0D,
    /// EMCON
    Emcon = 0x0E,
    /// Cross-Net Debugger (see IEN 158)
    Xnet = 0x0F,
    /// CHAOS
    Chaos = 0x10,
    /// User Datagram Protocol (see [`Udp`], RFC 741)
    Udp = 0x11,
    /// Multiplexing (see IEN 90)
    Mux = 0x12,
    /// DCN Measurement Subsystems
    DcnMeas = 0x13,
    /// Host Monitoring Protocol (see RFC 869)
    Hmp = 0x14,
    /// Packet Radio Measurement
    Prm = 0x15,
    /// XEROX NS IDP
    XnsIdp = 0x16,
    /// Trunk-1
    Trunk1 = 0x17,
    /// Trunk-2
    Trunk2 = 0x18,
    /// Leaf-1
    Leaf1 = 0x19,
    /// Leaf-2
    Leaf2 = 0x1A,
    /// Reliable Data Protocol (see RFC 908)
    Rdp = 0x1B,
    /// Internet Reliable Transaction Protocol (see RFC 938)
    Irtp = 0x1C,
    /// ISO Transport Protocol Class 4 (see RFC 905)
    IsoTp4 = 0x1D,
    /// Bulk Data Transfer Protocol (see RFC 998)
    NetBlt = 0x1E,
    /// MFE Network Services Protocol
    MfeNsp = 0x1F,
    /// MERIT Internodal Protocol
    MeritInp = 0x20,
    /// Datagram Congestion Control Protocol (see RFC 4340)
    Dccp = 0x21,
    /// Third Party Connect Protocol
    Tpcp = 0x22,
    /// Inter-Domain Policy Routing Protocol (see RFC 1479)
    Idpr = 0x23,
    /// Xpress Transport Protocol
    Xtp = 0x24,
    /// Datagram Delivery Protocol
    Ddp = 0x25,
    /// IDPR Control Message Transport Protocol
    IdprCmtp = 0x26,
    /// TP++ Transport Protocol
    TpPlusPlus = 0x27,
    /// IL Transport Protocol
    Il = 0x28,
    /// IPv6 Encapsulation--6to4 and 6in4 (see RFC 2473)
    Ipv6 = 0x29,
    /// Source Demand Routing Protocol (see RFC 1940)
    Sdrp = 0x2A,
    /// Routing Header for IPv6 (see RFC 8200)
    Ipv6Route = 0x2B,
    /// Fragment Header for IPv6 (see RFC 8200)
    Ipv6Frag = 0x2C,
    /// Inter-Domain Routing Protocol
    Idrp = 0x2D,
    /// Resource Reservation Protocol (see RFC 2205)
    Rsvp = 0x2E,
    /// Generic Routing Encapsulation (see RFC 2784, RFC 2890)
    Gre = 0x2F,
    /// Dynamic Source Routing Protocol (see RFC 4728)
    Dsr = 0x30,
    /// Burroughs Network Architecture
    Bna = 0x31,
    /// Encapsulating Security Payload (see RFC 4303)
    Esp = 0x32,
    /// Authentication Header (see RFC 4302)
    Ah = 0x33,
    /// Integrated Net Layer Security Protocol
    Inlsp = 0x34,
    /// SwIPe (see RFC 5237)
    Swipe = 0x35,
    /// NBMA Address Resolution Protocol (see RFC 1735)
    Narp = 0x36,
    /// IP Mobility (Min Encap) (see RFC 2004)
    Mobile = 0x37,
    /// Transport Layer Security Protocol (using Kryptonet key management)
    Tlsp = 0x38,
    /// Simple Key-Management for Internet Protocol (see RFC 2356)
    Skip = 0x39,
    /// ICMP for IPv6 (see RFC 4443, RFC 4884)
    Ipv6Icmp = 0x3A,
    /// No Next Header for IPv6 (see RFC 8200)
    Ipv6NoNxt = 0x3B,
    /// Destination Options for IPv6 (see RFC 8200)
    Ipv6Opts = 0x3C,
    /// Any host internal protocol
    AnyHostInternal = 0x3D,
    /// CFTP
    Cftp = 0x3E,
    /// Any local network
    AnyLocalNetwork = 0x3F,
    /// SATNET and Backroom EXPAK
    SatExpak = 0x40,
    /// Kryptolan
    KryptoLan = 0x41,
    /// MIT Remote Virtual Disk Protocol
    Rvd = 0x42,
    /// Internet Pluribus Packet Core
    Ippc = 0x43,
    /// Any distributed file system
    AnyDistributedFileSystem = 0x44,
    /// SATNET Monitoring
    SatMon = 0x45,
    /// VISA Protocol
    Visa = 0x46,
    /// Internet Packet Core Utility
    Ipcu = 0x47,
    /// Computer Protocol Network Executive
    Cpnx = 0x48,
    /// Computer Protocol Heart Beat
    Cphb = 0x49,
    /// Wang Span Network
    Wsn = 0x4A,
    /// Packet Video Protocol
    Pvp = 0x4B,
    /// Backroom SATNET Monitoring
    BrSatMon = 0x4C,
    /// SUN ND PROTOCOL-Temporary
    SunNd = 0x4D,
    /// WIDEBAND Monitoring
    WbMon = 0x4E,
    /// WIDEBAND EXPAK
    WbExpak = 0x4F,
    /// International Organization for Standardization Internet Protocol
    IsoIp = 0x50,
    /// Versatile Message Transaction Protocol (see RFC 1045)
    Vmtp = 0x51,
    /// Secure Versatile Message Transaction Protocol (see RFC 1045)
    SecureVmtp = 0x52,
    /// VINES
    Vines = 0x53,
    /// Time-Triggered Protocol
    Ttp = 0x54,
    /// NSFNET-IGP
    NsfnetIgp = 0x55,
    /// Dissimilar Gateway Protocol
    Dgp = 0x56,
    /// TCF
    Tcf = 0x57,
    /// EIGRP Informational (see RFC 7868)
    Eigrp = 0x58,
    /// Open Shortest Path First (see RFC 2328)
    Ospf = 0x59,
    /// Sprite RPC Protocol
    SpriteRpc = 0x5A,
    /// Locus Address Resolution Protocol
    Larp = 0x5B,
    /// Multicast Transport Protocol
    Mtp = 0x5C,
    /// AX.25
    Ax25 = 0x5D,
    /// KA9Q NOS compatible IP over IP tunneling
    Ka9qNos = 0x5E,
    /// Mobile Internetworking Control Protocol
    Micp = 0x5F,
    /// Semaphore Communications Sec. Pro
    SccSp = 0x60,
    /// Ethernet-within-IP Encapsulation (see RFC 3378)
    EtherIp = 0x61,
    /// Encapsulation Header (see RFC 1241)
    Encap = 0x62,
    /// Any private encryption scheme
    AnyPrivateEncryption = 0x63,
    /// GMTP
    Gmtp = 0x64,
    /// Ipsilon Flow Management Protocol
    Ifmp = 0x65,
    /// PNNI over IP
    Pnni = 0x66,
    /// Protocol Independent Multicast
    Pim = 0x67,
    /// IBM's ARIS (Aggregate Route IP Switching) Protocol
    Aris = 0x68,
    /// SCPS (Space Communications Protocol Standards) (see SCPS-TP)
    Scps = 0x69,
    /// QNX
    Qnx = 0x6A,
    /// Active Networks
    ActiveNetworks = 0x6B,
    /// IP Payload Compression Protocol (see RFC 3173)
    IpComp = 0x6C,
    /// Sitara Networks Protocol
    Snp = 0x6D,
    /// Compaq Peer Protocol
    CompaqPeer = 0x6E,
    /// IPX in IP
    IpxInIp = 0x6F,
    /// Virtual Router Redundancy Protocol, Common Address Redundancy Protocol (not IANA assigned) (see RFC 5798)
    Vrrp = 0x70,
    /// PGM Reliable Transport Protocol (see RFC 3208)
    Pgm = 0x71,
    /// Any 0-hop protocol
    Any0Hop = 0x72,
    /// Layer Two Tunneling Protocol Version 3 (see RFC 3931)
    L2tp = 0x73,
    /// D-II Data Exchange (DDX)
    Ddx = 0x74,
    /// Interactive Agent Transfer Protocol
    Iatp = 0x75,
    /// Schedule Transfer Protocol
    Stp = 0x76,
    /// SpectraLink Radio Protocol
    Srp = 0x77,
    /// Universal Transport Interface Protocol
    Uti = 0x78,
    /// Simple Message Protocol
    Smp = 0x79,
    /// Simple Multicast Protocol
    Sm = 0x7A,
    /// Performance Transparency Protocol
    Ptp = 0x7B,
    /// Intermediate System to Intermediate System (IS-IS) Protocol over IPv4 (see RFC 1142, RFC 1195)
    IsIsOverIpv4 = 0x7C,
    /// Flexible Intra-AS Routing Environment
    Fire = 0x7D,
    /// Combat Radio Transport Protocol
    Crtp = 0x7E,
    /// Combat Radio User Datagram
    CrUdp = 0x7F,
    /// Service-Specific Connection-Oriented Protocol in a Multilink and Connectionless Environment (see ITU-T Q.2111 1999)
    Sscopmce = 0x80,
    /// IPLT
    Iplt = 0x81,
    /// Secure Packet Shield
    Sps = 0x82,
    /// Private IP Encapsulation within IP
    Pipe = 0x83,
    /// Stream Control Transmission Protocol (see RFC 4960)
    Sctp = 0x84,
    /// Fibre Channel
    Fc = 0x85,
    /// Reservation Protocol (RSVP) End-to-End Ignore (see RFC 3175)
    RsvpE2eIgnore = 0x86,
    /// Mobility Extension Header for IPv6 (see RFC 6275)
    MobilityHeader = 0x87,
    /// Lightweight User Datagram Protocol (see RFC 3828)
    UdpLite = 0x88,
    /// Multiprotocol Label Switching Encapsulated in IP (see RFC 4023, RFC 5332)
    MplsInIp = 0x89,
    /// MANET Protocols (see RFC 5498)
    Manet = 0x8A,
    /// Host Identity Protocol (see RFC 5201)
    Hip = 0x8B,
    /// Site Multihoming by IPv6 Intermediation (see RFC 5533)
    Shim6 = 0x8C,
    /// Wrapped Encapsulating Security Payload (see RFC 5840)
    Wesp = 0x8D,
    /// Robust Header Compression (see RFC 5856)
    Rohc = 0x8E,
    /// IPv6 Segment Routing (TEMPORARY - registered 2020-01-31, expired 2021-01-31)  
    Ethernet = 0x8F,
    // Unassigned ports (0x90-0xFC)
    // Unassigned(u8) = 0x90,
    _Unassigned0x90 = 0x90,
    _Unassigned0x91 = 0x91,
    _Unassigned0x92 = 0x92,
    _Unassigned0x93 = 0x93,
    _Unassigned0x94 = 0x94,
    _Unassigned0x95 = 0x95,
    _Unassigned0x96 = 0x96,
    _Unassigned0x97 = 0x97,
    _Unassigned0x98 = 0x98,
    _Unassigned0x99 = 0x99,
    _Unassigned0x9A = 0x9A,
    _Unassigned0x9B = 0x9B,
    _Unassigned0x9C = 0x9C,
    _Unassigned0x9D = 0x9D,
    _Unassigned0x9E = 0x9E,
    _Unassigned0x9F = 0x9F,
    _Unassigned0xA0 = 0xA0,
    _Unassigned0xA1 = 0xA1,
    _Unassigned0xA2 = 0xA2,
    _Unassigned0xA3 = 0xA3,
    _Unassigned0xA4 = 0xA4,
    _Unassigned0xA5 = 0xA5,
    _Unassigned0xA6 = 0xA6,
    _Unassigned0xA7 = 0xA7,
    _Unassigned0xA8 = 0xA8,
    _Unassigned0xA9 = 0xA9,
    _Unassigned0xAA = 0xAA,
    _Unassigned0xAB = 0xAB,
    _Unassigned0xAC = 0xAC,
    _Unassigned0xAD = 0xAD,
    _Unassigned0xAE = 0xAE,
    _Unassigned0xAF = 0xAF,
    _Unassigned0xB0 = 0xB0,
    _Unassigned0xB1 = 0xB1,
    _Unassigned0xB2 = 0xB2,
    _Unassigned0xB3 = 0xB3,
    _Unassigned0xB4 = 0xB4,
    _Unassigned0xB5 = 0xB5,
    _Unassigned0xB6 = 0xB6,
    _Unassigned0xB7 = 0xB7,
    _Unassigned0xB8 = 0xB8,
    _Unassigned0xB9 = 0xB9,
    _Unassigned0xBA = 0xBA,
    _Unassigned0xBB = 0xBB,
    _Unassigned0xBC = 0xBC,
    _Unassigned0xBD = 0xBD,
    _Unassigned0xBE = 0xBE,
    _Unassigned0xBF = 0xBF,
    _Unassigned0xC0 = 0xC0,
    _Unassigned0xC1 = 0xC1,
    _Unassigned0xC2 = 0xC2,
    _Unassigned0xC3 = 0xC3,
    _Unassigned0xC4 = 0xC4,
    _Unassigned0xC5 = 0xC5,
    _Unassigned0xC6 = 0xC6,
    _Unassigned0xC7 = 0xC7,
    _Unassigned0xC8 = 0xC8,
    _Unassigned0xC9 = 0xC9,
    _Unassigned0xCA = 0xCA,
    _Unassigned0xCB = 0xCB,
    _Unassigned0xCC = 0xCC,
    _Unassigned0xCD = 0xCD,
    _Unassigned0xCE = 0xCE,
    _Unassigned0xCF = 0xCF,
    _Unassigned0xD0 = 0xD0,
    _Unassigned0xD1 = 0xD1,
    _Unassigned0xD2 = 0xD2,
    _Unassigned0xD3 = 0xD3,
    _Unassigned0xD4 = 0xD4,
    _Unassigned0xD5 = 0xD5,
    _Unassigned0xD6 = 0xD6,
    _Unassigned0xD7 = 0xD7,
    _Unassigned0xD8 = 0xD8,
    _Unassigned0xD9 = 0xD9,
    _Unassigned0xDA = 0xDA,
    _Unassigned0xDB = 0xDB,
    _Unassigned0xDC = 0xDC,
    _Unassigned0xDD = 0xDD,
    _Unassigned0xDE = 0xDE,
    _Unassigned0xDF = 0xDF,
    _Unassigned0xE0 = 0xE0,
    _Unassigned0xE1 = 0xE1,
    _Unassigned0xE2 = 0xE2,
    _Unassigned0xE3 = 0xE3,
    _Unassigned0xE4 = 0xE4,
    _Unassigned0xE5 = 0xE5,
    _Unassigned0xE6 = 0xE6,
    _Unassigned0xE7 = 0xE7,
    _Unassigned0xE8 = 0xE8,
    _Unassigned0xE9 = 0xE9,
    _Unassigned0xEA = 0xEA,
    _Unassigned0xEB = 0xEB,
    _Unassigned0xEC = 0xEC,
    _Unassigned0xED = 0xED,
    _Unassigned0xEE = 0xEE,
    _Unassigned0xEF = 0xEF,
    _Unassigned0xF0 = 0xF0,
    _Unassigned0xF1 = 0xF1,
    _Unassigned0xF2 = 0xF2,
    _Unassigned0xF3 = 0xF3,
    _Unassigned0xF4 = 0xF4,
    _Unassigned0xF5 = 0xF5,
    _Unassigned0xF6 = 0xF6,
    _Unassigned0xF7 = 0xF7,
    _Unassigned0xF8 = 0xF8,
    _Unassigned0xF9 = 0xF9,
    _Unassigned0xFA = 0xFA,
    _Unassigned0xFB = 0xFB,
    _Unassigned0xFC = 0xFC,
    /// Use for experimentation and testing
    Exp1 = 0xFD,
    /// Use for experimentation and testing
    Exp2 = 0xFE,
    /// Reserved value
    Reserved = 0xFF,
}

impl From<u8> for Ipv4DataProtocol {
    #[inline]
    fn from(value: u8) -> Self {
        unsafe { mem::transmute(value) }
    }
}

#[derive(Clone, Debug)]
pub struct Ipv4Options {
    options: Option<Vec<Ipv4Option>>,
    padding: Option<Vec<u8>>,
}

impl Ipv4Options {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(Ipv4OptionsRef::from_bytes_unchecked(bytes))
    }

    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        Ipv4OptionsRef::validate(bytes)
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        return self.padding.as_ref().map(|p| p.len()).unwrap_or(0)
            + self
                .options
                .as_ref()
                .map(|o| o.iter().map(|o| o.byte_len()).sum())
                .unwrap_or(0);
    }

    #[inline]
    pub fn options(&self) -> &[Ipv4Option] {
        match &self.options {
            None => &[],
            Some(o) => o.as_slice(),
        }
    }

    #[inline]
    pub fn options_mut(&mut self) -> &mut Option<Vec<Ipv4Option>> {
        &mut self.options
    }

    #[inline]
    pub fn padding(&self) -> &[u8] {
        match &self.padding {
            None => &[],
            Some(p) => p.as_slice(),
        }
    }
}

impl ToBytes for Ipv4Options {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

impl From<&Ipv4OptionsRef<'_>> for Ipv4Options {
    fn from(value: &Ipv4OptionsRef<'_>) -> Self {
        let (options, padding) = if value.iter().next().is_none() {
            (None, None)
        } else {
            let mut opts = Vec::new();
            let mut iter = value.iter();
            while let Some(opt) = iter.next() {
                opts.push(Ipv4Option::from(opt));
            }
            match iter.bytes {
                &[] => (Some(opts), None),
                padding => (Some(opts), Some(Vec::from(padding))),
            }
        };

        Ipv4Options { options, padding }
    }
}

impl From<Ipv4OptionsRef<'_>> for Ipv4Options {
    fn from(value: Ipv4OptionsRef<'_>) -> Self {
        Self::from(&value)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Ipv4OptionsRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv4OptionsRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        Ipv4OptionsRef { bytes }
    }

    pub fn validate(mut bytes: &[u8]) -> Result<(), ValidationError> {
        if bytes.is_empty() {
            return Ok(());
        }

        if bytes.len() % 4 != 0 {
            return Err(ValidationError {
                layer: Ipv4::name(),
                err_type: ValidationErrorType::InvalidValue,
                reason: "Ipv4 Options data length must be a multiple of 4",
            });
        }

        while let Some(option_type) = bytes.first() {
            match option_type {
                0 => break,
                1 => bytes = &bytes[1..],
                _ => match bytes.get(1) {
                    Some(0..=1) => return Err(ValidationError {
                        layer: Ipv4::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "IPv4 option length field contained too small a value",
                    }),
                    Some(&len) => {
                        match bytes.get(len as usize..) {
                            Some(remaining) => bytes = remaining,
                            None => return Err(ValidationError {
                                layer: Ipv4::name(),
                                err_type: ValidationErrorType::InvalidValue,
                                reason: "truncated IPv4 option field in options--missing part of option data",
                            }),
                        }
                    }
                    None => return Err(ValidationError {
                        layer: Ipv4::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "truncated IPv4 option found in options--missing option length field",
                    }),
                },
            }
        }

        Ok(())
    }

    #[inline]
    pub fn iter(&self) -> Ipv4OptionsIterRef<'a> {
        Ipv4OptionsIterRef {
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

impl<'a> From<&'a Ipv4OptionsMut<'_>> for Ipv4OptionsRef<'a> {
    fn from(value: &'a Ipv4OptionsMut<'_>) -> Self {
        Self::from_bytes_unchecked(value.bytes)
    }
}

impl<'a> From<Ipv4OptionsMut<'a>> for Ipv4OptionsRef<'a> {
    fn from(value: Ipv4OptionsMut<'a>) -> Self {
        Self::from_bytes_unchecked(value.bytes)
    }
}

pub struct Ipv4OptionsIterRef<'a> {
    curr_idx: usize,
    bytes: &'a [u8],
    end_reached: bool,
}

impl<'a> Iterator for Ipv4OptionsIterRef<'a> {
    type Item = Ipv4OptionRef<'a>;

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
                Some(Ipv4OptionRef::from_bytes_unchecked(option))
            }
            Some(&op_len) => {
                let option = &self.bytes[self.curr_idx..self.curr_idx + op_len as usize];
                self.curr_idx += op_len as usize;
                Some(Ipv4OptionRef::from_bytes_unchecked(option))
            }
            None => None,
        }
    }
}

#[derive(Debug)]
pub struct Ipv4OptionsMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Ipv4OptionsMut<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self {
        Ipv4OptionsMut { bytes }
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        Ipv4OptionsRef::validate(bytes)
    }

    #[inline]
    pub fn iter(&'a self) -> Ipv4OptionsIterRef<'a> {
        Ipv4OptionsIterRef {
            curr_idx: 0,
            bytes: self.bytes,
            end_reached: false,
        }
    }

    /*
    #[inline]
    pub fn iter_mut(&'a mut self) -> Ipv4OptionsIterMut<'a> {
        Ipv4OptionsIterMut {
            curr_idx: 0,
            bytes: self.bytes,
            end_reached: false,
        }
    }
    */

    #[inline]
    pub fn padding(&'a self) -> &'a [u8] {
        let mut iter = self.iter();
        while iter.next().is_some() {}
        &iter.bytes[iter.curr_idx..]
    }

    /*
    #[inline]
    pub fn padding_mut(&'a mut self) -> &'a mut [u8] {
        let mut iter = self.iter_mut();
        while iter.next().is_some() {}
        &mut iter.bytes[iter.curr_idx..]
    }
    */
}

/*
pub struct Ipv4OptionsIterMut<'a> {
    curr_idx: usize,
    bytes: &'a mut [u8],
    end_reached: bool,
}

impl<'a> Iterator for Ipv4OptionsIterMut<'a> {
    type Item = Ipv4OptionMut<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.end_reached {
            return None;
        }

        match self.bytes[0] as usize {
            r @ (0 | 1) => {
                let option = &mut self.bytes[self.curr_idx..self.curr_idx + 1];
                self.curr_idx += 1;
                if r == 0 {
                    self.end_reached = true;
                }
                Some(Ipv4OptionMut::from_bytes_unchecked(option))
            }
            op_len => {
                let option = &mut self.bytes[self.curr_idx..self.curr_idx + op_len];
                self.curr_idx += op_len;
                Some(Ipv4OptionMut::from_bytes_unchecked(option))
            }
        }
    }
}
*/

// EOOL and NOP must have a size of 0
#[derive(Clone, Debug)]
pub struct Ipv4Option {
    option_type: u8,
    value: Option<Vec<u8>>,
}

impl ToBytes for Ipv4Option {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
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

impl Ipv4Option {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Self {
        Self::from(Ipv4OptionRef::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        Ipv4OptionRef::validate(bytes)
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
    pub fn copied(&self) -> bool {
        self.option_type & 0x80 > 0
    }

    #[inline]
    pub fn option_class(&self) -> Ipv4OptionClass {
        // SAFETY: this value can only ever be between 0 and 3 inclusive
        unsafe { mem::transmute((self.option_type & 0x60) >> 5) }
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
}

impl From<&Ipv4OptionRef<'_>> for Ipv4Option {
    #[inline]
    fn from(ipv4_option: &Ipv4OptionRef<'_>) -> Self {
        Ipv4Option {
            option_type: ipv4_option.option_type(),
            value: match ipv4_option.option_type() {
                0 | 1 => None,
                _ => Some(Vec::from(ipv4_option.option_data())),
            },
        }
    }
}

impl From<Ipv4OptionRef<'_>> for Ipv4Option {
    #[inline]
    fn from(ipv4_option: Ipv4OptionRef<'_>) -> Self {
        Self::from(&ipv4_option)
    }
}

pub struct Ipv4OptionRef<'a> {
    bytes: &'a [u8],
}

impl<'a> Ipv4OptionRef<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        Ipv4OptionRef { bytes }
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        match bytes.first() {
            Some(0 | 1) => if bytes.len() == 1 {
                Ok(())
            } else {
                Err(ValidationError {
                    layer: Ipv4::name(),
                    err_type: ValidationErrorType::ExcessBytes(bytes.len() - 1),
                    reason: "excess bytes at end of single-byte IPv4 option"
                })
            },
            Some(_) => match bytes.get(1) {
                Some(&len @ 2..) if bytes.len() >= len as usize => match bytes.len().checked_sub(len as usize) {
                    Some(0) => Ok(()),
                    Some(remaining) => Err(ValidationError {
                        layer: Ipv4::name(),
                        err_type: ValidationErrorType::ExcessBytes(remaining),
                        reason: "excess bytes at end of sized IPv4 option",
                    }),
                    None => Err(ValidationError {
                        layer: Ipv4::name(),
                        err_type: ValidationErrorType::InvalidValue,
                        reason: "length of IPv4 Option data exceeded available bytes"
                    }),
                },
                _ => Err(ValidationError {
                    layer: Ipv4::name(),
                    err_type: ValidationErrorType::InvalidValue,
                    reason: "insufficient bytes available to read IPv4 Option--missing length byte field"
                }),
            },
            None => Err(ValidationError {
                layer: Ipv4::name(),
                err_type: ValidationErrorType::InvalidValue,
                reason: "insufficient bytes available to read IPv4 Option--missing option_type byte field",
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
    pub fn copied(&self) -> bool {
        self.bytes[0] & 0b_1000_0000 > 0
    }

    #[inline]
    pub fn option_class(&self) -> Ipv4OptionClass {
        // SAFETY: this value can only ever be between 0 and 3 inclusive
        unsafe { mem::transmute((self.bytes[0] & 0b_0110_0000) >> 5) }
    }

    #[inline]
    pub fn option_data(&self) -> &[u8] {
        match &self.bytes[0] {
            0 | 1 => &[],
            _ => &self.bytes[2..self.bytes[1] as usize],
        }
    }
}

impl<'a> From<&'a Ipv4OptionMut<'_>> for Ipv4OptionRef<'a> {
    fn from(value: &'a Ipv4OptionMut<'_>) -> Self {
        Ipv4OptionRef { bytes: value.bytes }
    }
}

impl<'a> From<Ipv4OptionMut<'a>> for Ipv4OptionRef<'a> {
    fn from(value: Ipv4OptionMut<'a>) -> Self {
        Ipv4OptionRef { bytes: value.bytes }
    }
}

pub struct Ipv4OptionMut<'a> {
    bytes: &'a mut [u8],
}

impl<'a> Ipv4OptionMut<'a> {
    #[inline]
    pub fn from_bytes(bytes: &'a mut [u8]) -> Result<Self, ValidationError> {
        Self::validate(bytes)?;
        Ok(Self::from_bytes_unchecked(bytes))
    }

    #[inline]
    pub fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self {
        Ipv4OptionMut { bytes }
    }

    #[inline]
    pub fn validate(bytes: &[u8]) -> Result<(), ValidationError> {
        Ipv4OptionRef::validate(bytes)
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
    pub fn set_option_type(&mut self, option_type: u8) {
        self.bytes[0] = option_type;
    }

    #[inline]
    pub fn copied(&self) -> bool {
        self.bytes[0] & 0b_1000_0000 > 0
    }

    #[inline]
    pub fn option_class(&self) -> Ipv4OptionClass {
        // SAFETY: this value can only ever be between 0 and 3 inclusive
        unsafe { mem::transmute((self.bytes[0] & 0b_0110_0000) >> 5) }
    }

    #[inline]
    pub fn option_data(&self) -> &[u8] {
        match &self.bytes[0] {
            0 | 1 => &[],
            _ => &self.bytes[2..self.bytes[1] as usize],
        }
    }
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Ipv4OptionClass {
    Control = 0,
    Reserved1 = 1,
    DebuggingMeasurement = 2,
    Reserved3 = 3,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Ipv4OptionType {
    /// End of Option List
    Eool = 0x00,
    /// No Operation
    Nop = 0x01,
    /// Security (defunct option)
    Sec = 0x02,
    /// Record Route
    Rr = 0x07,
    /// Experimental Measurement
    Zsu = 0x0A,
    /// MTU Probe
    Mtup = 0x0B,
    /// MTU Reply
    Mtur = 0x0C,
    /// ENCODE
    Encode = 0x0F,
    /// Quick-Start
    Qs = 0x19,
    /// RFC 3692 Experiment
    Exp1 = 0x1E,
    // Time Stamp
    Ts = 0x44,
    /// Traceroute
    Tr = 0x52,
    /// RFC 3692 Experiment
    Exp2 = 0x5E,
    /// Security (RIPSO)
    Ripso = 0x82,
    /// Loose Source Route
    Lsr = 0x83,
    /// Extended Security (RIPSO)
    Esec = 0x85,
    /// Commercial IP Security
    Cipso = 0x86,
    /// Stream ID
    Sid = 0x88,
    /// Strict Source Route
    Ssr = 0x89,
    /// Experimental Access Control
    Visa = 0x8E,
    /// IMI Traffic Descriptor
    Imitd = 0x90,
    /// Extended Internet Protocol
    Eip = 0x91,
    /// Address Extension
    AddExt = 0x93,
    /// Router Alert
    RtrAlt = 0x94,
    /// Selective Directed Broadcast
    Sdb = 0x95,
    /// Dynamic Packet State
    Dps = 0x97,
    /// Upstream Multicast Packet
    Ump = 0x98,
    /// RFC 3692 Experiment
    Exp3 = 0x9E,
    /// Experimental Flow Control
    Finn = 0xCD,
    /// RFC 3692 Experiment
    Exp4 = 0xDE,
}
