use pkts_macros::{Layer, LayerRef, LayerMut, StatelessLayer};

use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::{error::*, utils};

use super::{Raw, RawRef};
use super::ip::{Ipv4, Ipv4Ref};

const ETH_PROTOCOL_IP: u16 = 0x0800;
const ETH_PROTOCOL_EXPERIMENTAL: u16 = 0x88B5;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(EtherMetadata)]
#[ref_type(EtherRef)]
pub struct Ether {
    src: [u8; 6],
    dst: [u8; 6],
    payload: Option<Box<dyn LayerObject>>,
}

impl Ether {
    #[inline]
    pub fn src_mac(&self) -> [u8; 6] {
        self.src
    }

    #[inline]
    pub fn dst_mac(&self) -> [u8; 6] {
        self.dst
    }

    #[inline]
    pub fn eth_type(&self) -> u16 {
        match self.payload.as_ref() {
            None => ETH_PROTOCOL_EXPERIMENTAL, // default to experimental protocol indicator
            Some(p) => {
                let payload_metadata = p
                    .layer_metadata()
                    .as_any()
                    .downcast_ref::<&dyn EtherPayloadMetadata>()
                    .expect("unknown payload protocol found in Ether packet");
                payload_metadata.eth_type()
            }
        }
    }
}

impl CanSetPayload for Ether {
    #[inline]
    fn can_set_payload_default(&self, payload: &dyn LayerObject) -> bool {
        payload
            .layer_metadata()
            .as_any()
            .downcast_ref::<&dyn EtherPayloadMetadata>()
            .is_some()
    }
}

impl FromBytesCurrent for Ether {
    #[inline]
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        let ether = EtherRef::from_bytes_unchecked(bytes);
        if ether.payload_raw().is_empty() {
            self.payload = None;
        } else {
            self.payload = match ether.eth_type() {
                ETH_PROTOCOL_IP if bytes[14] >> 4 == 4 => {
                    Some(Box::new(Ipv4::from_bytes_unchecked(ether.payload_raw())))                       
                }
                /* Add additional Networ layer protocols here */
                _ => Some(Box::new(Raw::from_bytes_unchecked(ether.payload_raw()))),
            };
        }
    }

    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        let ether = EtherRef::from_bytes_unchecked(bytes);
        Ether {
            src: ether.src_mac(),
            dst: ether.dst_mac(),
            payload: None,
        }
    }
}

impl LayerLength for Ether {
    #[inline]
    fn len(&self) -> usize {
        14 + self.payload.as_ref().map_or(0, |p| p.len())
    }
}

impl LayerObject for Ether {
    #[inline]
    fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
        self.payload.as_deref()
    }

    #[inline]
    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        self.payload.as_deref_mut()
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
        ret.expect("remove_payload() called on Ether layer when layer had no payload")
    }

    #[inline]
    fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        self.payload = Some(payload);
    }
}

impl ToBytes for Ether {
    #[inline]
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(self.src);
        bytes.extend(self.dst);
        match self.payload.as_ref() {
            None => bytes.extend(ETH_PROTOCOL_EXPERIMENTAL.to_be_bytes()),
            Some(p) => bytes.extend(match p.layer_metadata().as_any().downcast_ref::<&dyn EtherPayloadMetadata>() {
                Some(m) => m.eth_type(),
                None => ETH_PROTOCOL_EXPERIMENTAL,
            }.to_be_bytes()),
        }
    }
}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Ether)]
#[metadata_type(EtherMetadata)]
pub struct EtherRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> EtherRef<'a> {
    #[inline]
    pub fn src_mac(&self) -> [u8; 6] {
        *utils::get_array(self.data, 0).expect("insufficient bytes in Ether layer to extract Source MAC Address field")
    }

    #[inline]
    pub fn dst_mac(&self) -> [u8; 6] {
        *utils::get_array(self.data, 6).expect("insufficient bytes in Ether layer to extract Destination MAC Address field")
    }

    #[inline]
    pub fn eth_type(&self) -> u16 {
        u16::from_be_bytes(*utils::get_array(self.data, 12).expect("insufficient bytes in Ether layer to extract EtherType field"))
    }

    #[inline]
    pub fn payload_raw(&self) -> &[u8] {
        self.data.get(14..).expect("insufficient bytes in Ether layer to extract payload")
    }
}

impl<'a> FromBytesRef<'a> for EtherRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        EtherRef {
            data: bytes
        }
    }
}

impl<'a> LayerOffset for EtherRef<'a> {
    #[inline]
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        if bytes.len() <= 14 {
            return None
        }

        let eth_type = u16::from_be_bytes(*utils::get_array(bytes, 12).unwrap());
        match eth_type {
            ETH_PROTOCOL_IP => match bytes[14] >> 4 {
                0x04 => if layer_type == Ipv4Ref::layer_id_static() {
                    Some(14)
                } else {
                    Ipv4Ref::payload_byte_index_default(&bytes[14..], layer_type)
                }
                /* Add new Internet Protocol (IP) protocols here */
                _ => {
                    None
                }
            }
            /* Add new Network layer protocols here */
            _ => {
                None 
            }
        }
    }
}

impl<'a> Validate for EtherRef<'a> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        if curr_layer.len() < 14 {
            Err(ValidationError {
                layer: Ether::name(),
                err_type: ValidationErrorType::InsufficientBytes,
                reason: "insufficient bytes in Ether layer for header fields", 
            })
        } else {
            Ok(())
        }
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        if curr_layer.len() == 14 {
            return Ok(())
        }

        let eth_type = u16::from_be_bytes(*utils::get_array(curr_layer, 10).unwrap());
        match eth_type {
            ETH_PROTOCOL_IP => match curr_layer[14] {
                0x04 => Ipv4Ref::validate(&curr_layer[14..]),
                _ => RawRef::validate(&curr_layer[14..]), // Add new IP protocols here
            }
            _ => RawRef::validate(&curr_layer[14..]) // Add new L3 protocols here
        }
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[owned_type(Ether)]
#[ref_type(EtherRef)]
#[metadata_type(EtherMetadata)]
pub struct EtherMut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    length: usize,
}

impl<'a> EtherMut<'a> {
    #[inline]
    pub fn src_mac(&self) -> [u8; 6] {
        *utils::get_array(self.data, 0).expect("insufficient bytes in Ether layer to extract Source MAC Address field")
    }

    #[inline]
    pub fn set_src_mac(&mut self, src_mac: [u8; 6]) {
        self.data.get_mut(0..6).expect("insufficient bytes in Ether layer to replace Source MAC Address field").copy_from_slice(src_mac.as_slice());
    }

    #[inline]
    pub fn dst_mac(&self) -> [u8; 6] {
        *utils::get_array(self.data, 6).expect("insufficient bytes in Ether layer to extract Destination MAC Address field")
    }

    #[inline]
    pub fn set_dst_mac(&mut self, dst_mac: [u8; 6]) {
        self.data.get_mut(6..12).expect("insufficient bytes in Ether layer to replace Destination MAC Address field").copy_from_slice(dst_mac.as_slice());
    }

    #[inline]
    pub fn eth_type(&self) -> u16 {
        u16::from_be_bytes(*utils::get_array(self.data, 12).expect("insufficient bytes in Ether layer to extract EtherType field"))
    }

    #[inline]
    pub fn set_eth_type(&mut self, eth_type: u16) {
        self.data.get_mut(12..14).expect("insufficient bytes in Ether layer to replace Ether Type field").copy_from_slice(eth_type.to_be_bytes().as_slice());
    }

    #[inline]
    pub fn payload_raw(&self) -> &[u8] {
        self.data.get(14..self.length).expect("insufficient bytes in Ether layer to extract payload")
    }

    #[inline]
    pub fn payload_mut_raw(&mut self) -> &mut [u8] {
        self.data.get_mut(14..self.length).expect("insufficient bytes in Ether layer to extract payload")
    }
}

impl<'a> From<&'a EtherMut<'a>> for EtherRef<'a> {
    #[inline]
    fn from(value: &'a EtherMut<'a>) -> Self {
        EtherRef {
            data: &value.data[..value.length],
        }
    }
}
