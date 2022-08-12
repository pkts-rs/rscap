use core::fmt::Debug;
use core::{any, mem};

use rscap_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use crate::layers::traits::*;


// Included in this package:
// Ipv4, Ipv6

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(Ipv4AssociatedMetadata)]
#[ref_type(Ipv4Ref)]
pub struct Ipv4 {
    // version, ihl, length, protocol, and checksum all calculated dynamically
    dscp: DiffServ, // also known as tos
    ecn: Ecn,
    id: u16,
    flags: Ipv4Flags,
    frag_offset: u16,
    ttl: u8,
    pub saddr: u32,
    pub daddr: u32,
    options: Ipv4Options,
    #[payload_field]
    pub payload: Option<Box<dyn Layer>>,
}

impl ToBytes for Ipv4 {
    fn to_bytes_extend(&self, bytes: &mut Vec<u8>) {
        todo!()
    }
}

impl From<&Ipv4Ref<'_>> for Ipv4 {
    fn from(value: &Ipv4Ref<'_>) -> Self {
        todo!()
    }
}

impl FromBytesCurrent for Ipv4 {
    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        todo!()
    }
}

impl LayerImpl for Ipv4 {
    #[inline]
    fn can_set_payload_default(&self, payload: Option<&dyn Layer>) -> bool {
        match payload {
            None => true,
            Some(p) => p
                .layer_metadata()
                .as_any()
                .downcast_ref::<&dyn Ipv4Metadata>()
                .is_some(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        todo!()
    }
}

impl Ipv4 {

}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Ipv4)]
#[metadata_type(Ipv4AssociatedMetadata)]
pub struct Ipv4Ref<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> FromBytesRef<'a> for Ipv4Ref<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        Ipv4Ref { data: packet }
    }
}

impl LayerByteIndexDefault for Ipv4Ref<'_> {
    #[inline]
    fn get_layer_byte_index_default(bytes: &[u8], layer_type: any::TypeId) -> Option<usize> {
        todo!()
    }
}

impl Validate for Ipv4Ref<'_> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl<'a> Ipv4Ref<'a> {
    #[inline]
    pub fn version(&self) -> u8 {
        self.data[0] >> 4
    }

    #[inline]
    pub fn ihl(&self) -> u8 {
        self.data[0] & 0x0F
    }

    #[inline]
    pub fn dscp(&self) -> DiffServ {
        DiffServ::from(self.data[1])
    }

    #[inline]
    pub fn ecn(&self) -> Ecn {
        Ecn::from(self.data[1])
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
    pub fn protocol(&self) -> Result<Ipv4DataProtocol, ValidationError> {
        self.data[9]
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
    pub fn options(&self) -> Ipv4Options {
        let options_end = core::cmp::min(self.data[0] & 0x0F, 5) as usize * 4;
        Ipv4Options::try_from(&self.data[20..options_end]).unwrap()
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[owned_type(Ipv4)]
#[ref_type(Ipv4Ref)]
#[metadata_type(Ipv4AssociatedMetadata)]
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
            data: &value.data[..value.len]
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

// =========================================
//           INTERNAL FIELDS
// =========================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiffServ {
    dscp: u8,
}

impl From<u8> for DiffServ {
    fn from(value: u8) -> Self {
        DiffServ {
            dscp: value >> 2
        }
    }
}

impl DiffServ {
    pub fn dscp(&self) -> u8 {
        self.dscp
    }
}




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
    fn from(value: u8) -> Self {
        Ipv4Flags {
            flags: value & 0b11100000
        }
    }
}



#[derive(Clone, Copy, Debug)]
#[repr(u8)]
pub enum Ipv4DataProtocol {
    /// IPv6 Hop-by-Hop Option
    HopOpt = 0x00,
    /// Internet Control Message Protocol
    Icmp = 0x01,
    /// Internet Group Management Protocol
    Igmp = 0x02,
    /// Gateway-to-Gateway Protocol
    Ggp = 0x03,
    /// IP in IP (encapsulation)
    IpInIp = 0x04,
    /// Internet Stream Protocol
    ST = 0x05,
    /// Transmission Control Protocol
    Tcp = 0x06,
    /// User Datagram Protocol
    Udp = 0x11,
    // TODO: complete these
}

#[derive(Clone, Debug)]
pub struct Ipv4Options {
    options: Option<Vec<Ipv4Option>>,
    padding: Option<Vec<u8>>,
}

impl TryFrom<&[u8]> for Ipv4Options {
    type Error = ValidationError;

    fn try_from(mut value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() == 0 {
            return Ok(Ipv4Options {
                options: None,
                padding: None,
            })
        }

        if value.len() % 4 != 0 {
            return Err(ValidationError::InvalidValue)
        }

        let mut options = Vec::new();
        while value.len() > 0 {
            let option = Ipv4Option::try_from(value)?;
            value = &value[option.option_length()..];
            let is_eool = option.option_type() == Ipv4OptionType::Eool as u8;
            options.push(option);
            if is_eool {
                break
            }
        }

        Ok(Ipv4Options {
            options: Some(options),
            padding: if value.len() > 0 { Some(Vec::from(value)) } else { None }
        })
    }
}

impl Ipv4Options {
    #[inline]
    pub fn options(&self) -> &[Ipv4Option] {
        match &self.options {
            None => &[],
            Some(o) => o.as_slice(),
        }
    }

    #[inline]
    pub fn padding(&self) -> &[u8] {
        match &self.padding {
            None => &[],
            Some(p) => p.as_slice(),
        }
    }
}

// EOOL and NOP must have a size of 0
#[derive(Clone, Debug)]
pub struct Ipv4Option {
    option_type: u8,
    value: Option<Vec<u8>>,
}

impl Ipv4Option {
    #[inline]
    pub fn from_bytes_unchecked(bytes: &[u8]) -> Ipv4Option {
        Ipv4Option {
            option_type: bytes[0],
            value: if bytes[0] == Ipv4OptionType::Eool as u8 || bytes[0] == Ipv4OptionType::Nop as u8 {
                None
            } else {
                Some(Vec::from(&bytes[2..(bytes[1] as usize)]))
            }
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

    /*
    pub fn set_copied(&mut self, copied: bool) {
        if copied {
            self.option_type |= 0x80;
        } else {
            self.option_type &= !0x80;
        }
    }
    */

    #[inline]
    pub fn option_class(&self) -> Ipv4OptionClass {
        // SAFETY: this value can only ever be between 0 and 3 inclusive
        unsafe { mem::transmute((self.option_type & 0x60) >> 5) }
    }

    #[inline]
    pub fn option_length(&self) -> usize {
        match self.option_type {
            0 | 1 => 1,
            _ => self.value.as_ref().unwrap().len() + 2
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

impl TryFrom<&[u8]> for Ipv4Option {
    type Error = ValidationError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        match bytes.get(0) {
            Some(&option_type @ (0 | 1)) => Ok(Ipv4Option { option_type, value: None}),
            Some(&option_type) => match bytes.get(1) {
                Some(&len @ 2..) if bytes.len() >= len as usize => match bytes.get(2..len as usize) {
                    Some(value) => Ok(Ipv4Option { option_type, value: Some(Vec::from(value)) }),
                    None => Err(ValidationError::InvalidSize)
                }
                _ => Err(ValidationError::InvalidSize)
            }
            None => Err(ValidationError::InvalidValue)
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
    RR = 0x07,
    /// Experimental Measurement
    Zsu = 0x0A,
    /// MTU Probe
    MTUP = 0x0B,
    /// MTU Reply
    MTUR = 0x0C,
    /// ENCODE
    ENCODE = 0x0F,
    /// Quick-Start
    QS = 0x19,
    /// RFC 3692 Experiment
    EXP1 = 0x1E,
    // Time Stamp
    TS = 0x44,
    /// Traceroute
    TR = 0x52,
    /// RFC 3692 Experiment
    EXP2 = 0x5E,
    /// Security (RIPSO)
    RIPSO = 0x82,
    /// Loose Source Route
    LSR = 0x83,
    /// Extended Security (RIPSO)
    ESEC = 0x85,
    /// Commercial IP Security
    CIPSO = 0x86,
    /// Stream ID
    SID = 0x88,
    /// Strict Source Route
    SSR = 0x89,
    /// Experimental Access Control
    VISA = 0x8E,
    /// IMI Traffic Descriptor
    IMITD = 0x90,
    /// Extended Internet Protocol
    EIP = 0x91,
    /// Address Extension
    ADDEXT = 0x93,
    /// Router Alert
    RTRALT = 0x94,
    /// Selective Directed Broadcast
    SDB = 0x95,
    /// Dynamic Packet State
    DPS = 0x97,
    /// Upstream Multicast Packet
    UMP = 0x98,
    /// RFC 3692 Experiment
    EXP3 = 0x9E,
    /// Experimental Flow Control
    FINN = 0xCD,
    /// RFC 3692 Experiment
    EXP4 = 0xDE,
}
