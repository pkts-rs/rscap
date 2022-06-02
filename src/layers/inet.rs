use core::{cmp, mem};
use std::fmt::Debug;

use crate::layers;
use crate::layers::traits::*;

use rscap_macros::{MutLayerDerives, OwnedLayerDerives, RefLayerDerives};

// Included in this package:
// Icmp, Ipv4
//
// Notably absent:
// TCP and associated classes (moved to tcp.rs)
// UDP and associated classes (moved to udp.rs)

#[derive(Clone, OwnedLayerDerives)]
#[owned_name(Ipv4)]
#[metadata_type(Ipv4AssociatedMetadata)]
#[custom_layer_selection(Ipv4LayerSelection)]
pub struct Ipv4 {
    // version: u8,
    dscp: u8, // tos
    ecn: u8,
    id: u16,
    flags: u8,
    frag: u16,
    ttl: u8,
    // ihl, length, protocol, checksum all calculated dynamically
    pub src: u32,
    pub dst: u32,
    options: Ipv4Options,
    pub payload: Option<Box<dyn Layer>>,
}

impl Debug for Ipv4 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IPv4")
            .field("src", &self.src)
            .field("dst", &self.dst)
            .finish()
    }
}

impl Layer for Ipv4 {
    #[inline]
    fn get_payload_ref(&self) -> Option<&dyn Layer> {
        self.payload.as_ref().map(|p| p.as_ref())
    }

    #[inline]
    fn get_payload_mut(&mut self) -> Option<&mut dyn Layer> {
        self.payload.as_mut().map(|p| p.as_mut())
    }

    #[inline]
    fn can_set_payload(&self, payload: Option<&dyn Layer>) -> bool {
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
    fn set_payload_unchecked(&mut self, payload: Option<Box<dyn Layer>>) {
        self.payload = payload;
    }
}

impl ValidateBytes for Ipv4 {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl FromBytes<'_> for Ipv4 {
    #[inline]
    fn from_bytes_unchecked(bytes: &'_ [u8]) -> Self {
        todo!() // Make sure custom layering is used here
    }
}

#[derive(Clone, Debug, RefLayerDerives)]
#[owned_name(Ipv4)]
#[metadata_type(Ipv4AssociatedMetadata)]
#[custom_layer_selection(Ipv4LayerSelection)]
pub struct Ipv4Ref<'a> {
    data: &'a [u8],
}

impl ValidateBytes for Ipv4Ref<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl<'a> FromBytes<'a> for Ipv4Ref<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        Ipv4Ref { data: packet }
    }
}

impl<'a> LayerRef<'a> for Ipv4Ref<'a> {
    #[inline]
    fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    fn get_layer<T: LayerRef<'a>>(&self) -> Option<T> {
        if self.is_layer::<T>() {
            return Some(unsafe {
                Ipv4Ref::from_bytes_unchecked(self.data).cast_layer_unchecked::<T>()
            });
        }

        #[cfg(feature = "custom_layer_selection")]
        if let Some(&custom_selection) = self
            .custom_layer_selection_instance()
            .as_any()
            .downcast_ref::<&dyn CustomLayerSelection>()
        {
            return custom_selection
                .get_layer_from_next(self.data, &T::type_layer_id())
                .map(|offset| T::from_bytes_unchecked(&self.data[offset..]));
        }

        let offset = (cmp::max(self.data[0] & 0x0F, 5) * 4) as usize;
        if self.data.len() == offset {
            return None; // The current layer is the last one
        }

        match self.data[9] {
            p if p == Ipv4DataProtocol::IPInIP as u8 => {
                Ipv4Ref::from_bytes_unchecked(&self.data[offset..]).get_layer()
            }
            p if p == Ipv4DataProtocol::TCP as u8 => {
                layers::tcp::TcpRef::from_bytes_unchecked(&self.data[offset..]).get_layer()
            }
            // TODO: add more here as protocols are implemented
            _ => None,
        }
    }
}

#[derive(Debug, MutLayerDerives)]
#[owned_name(Ipv4)]
#[ref_name(Ipv4Ref)]
#[metadata_type(Ipv4AssociatedMetadata)]
#[custom_layer_selection(Ipv4LayerSelection)]
pub struct Ipv4Mut<'a> {
    data: &'a mut [u8],
}

impl<'a> LayerMut<'a> for Ipv4Mut<'a> {
    #[inline]
    fn as_bytes(&'a self) -> &'a [u8] {
        self.data
    }

    #[inline]
    fn as_bytes_mut(&'a mut self) -> &'a mut [u8] {
        self.data
    }

    #[inline]
    fn get_layer<T: LayerRef<'a>>(&'a self) -> Option<T> {
        if Self::is_mutable_variant_of::<T>() {
            return Some(unsafe {
                Ipv4Ref::from_bytes_unchecked(self.data).cast_layer_unchecked::<T>()
            });
        }

        #[cfg(feature = "custom_layer_selection")]
        if let Some(&custom_selection) = self
            .custom_layer_selection_instance()
            .as_any()
            .downcast_ref::<&dyn CustomLayerSelection>()
        {
            return custom_selection
                .get_layer_from_next(self.data, &T::type_layer_id())
                .map(|offset| T::from_bytes_unchecked(&self.data[offset..]));
        }

        Self::get_layer_from_raw(self.data)
    }

    fn get_layer_mut<T: LayerMut<'a>>(&'a mut self) -> Option<T> {
        if self.is_layer::<T>() {
            return Some(unsafe {
                Ipv4Mut::from_bytes_unchecked(self.data).cast_layer_unchecked::<T>()
            });
        }

        #[cfg(feature = "custom_layer_selection")]
        if let Some(&custom_selection) = self
            .custom_layer_selection_instance()
            .as_any()
            .downcast_ref::<&dyn CustomLayerSelection>()
        {
            return custom_selection
                .get_layer_from_next(self.data, &T::type_layer_id())
                .map(|offset| T::from_bytes_unchecked(&mut self.data[offset..]))
        }


       Self::get_layer_mut_from_raw(self.data)
    
    }

    fn get_layer_from_raw<'b, T: LayerRef<'b>>(bytes: &'b [u8]) -> Option<T> {
        let offset = (cmp::max(bytes[0] & 0x0F, 5) * 4) as usize;
        if bytes.len() == offset {
            // The current layer is the last one
            return None;
        }

        match bytes[9] {
            p if p == Ipv4DataProtocol::IPInIP as u8 => Ipv4Ref::from_bytes_unchecked(&bytes[offset..]).get_layer(),
            p if p == Ipv4DataProtocol::TCP as u8 => layers::tcp::TcpRef::from_bytes_unchecked(&bytes[offset..]).get_layer(),
            // TODO: add more here as protocols are implemented
            _ => None,
        }
    
    }

    fn get_layer_mut_from_raw<'b, T: LayerMut<'b>>(bytes: &'b mut [u8]) -> Option<T> {
        let offset = (cmp::max(bytes[0] & 0x0F, 5) * 4) as usize;
        if bytes.len() == offset {
            // The current layer is the last one
            return None;
        }

        
        match bytes[9] {
            p if p == Ipv4DataProtocol::IPInIP as u8 => {
                Ipv4Mut::get_layer_mut_from_raw(&mut bytes[offset..])
//                Ipv4Mut::from_bytes_unchecked(&mut self.data[offset..]).get_layer_mut()
            }
            p if p == Ipv4DataProtocol::TCP as u8 => {
                layers::tcp::TcpMut::get_layer_mut_from_raw(&mut bytes[offset..])
            }
            // TODO: add more here as protocols are implemented
            _ => None,
        }
        
    }
}

impl ValidateBytes for Ipv4Mut<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl<'a> FromBytesMut<'a> for Ipv4Mut<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self {
        Ipv4Mut { data: bytes }
    }
}

// =========================================
//           INTERNAL FIELDS
// =========================================

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum Ipv4DataProtocol {
    /// IPv6 Hop-by-Hop Option
    HOPOPT = 0x00,
    /// Internet Control Message Protocol
    ICMP = 0x01,
    /// Internet Group Management Protocol
    IGMP = 0x02,
    /// Gateway-to-Gateway Protocol
    GGP = 0x03,
    /// IP in IP (encapsulation)
    IPInIP = 0x04,
    /// Internet Stream Protocol
    ST = 0x05,
    /// Transmission Control Protocol
    TCP = 0x06,
    /// User Datagram Protocol
    UDP = 0x11,
    // TODO: complete these
}

#[derive(Clone)]
pub struct Ipv4Options {
    pub options: Vec<Ipv4Option>,
    pub padding: Vec<u8>,
}

// EOOL and NOP must have a size of 0
#[derive(Clone)]
pub struct Ipv4Option {
    pub option_type: u8,
    pub value: Vec<u8>,
}

impl Ipv4Option {
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

    pub fn option_class(&self) -> Ipv4OptionClass {
        // SAFETY: this value can only ever be between 0 and 3 inclusive
        unsafe { mem::transmute((self.option_type & 0x60) >> 5) }
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
    EOOL = 0x00,
    /// No Operation
    NOP = 0x01,
    /// Security (defunct option)
    SEC = 0x02,
    /// Record Route
    RR = 0x07,
    /// Experimental Measurement
    ZSU = 0x0A,
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
