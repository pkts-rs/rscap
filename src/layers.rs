pub mod diameter;
pub mod icmp;
pub mod ip;
pub mod l2;
pub mod mysql;
pub mod sctp;
pub mod tcp;
pub mod traits;
pub mod udp;

use crate::error::*;
use crate::layers::traits::extras::*;
use crate::layers::traits::*;

use rscap_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use core::fmt::Debug;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(RawMetadata)]
#[ref_type(RawRef)]
pub struct Raw {
    data: Vec<u8>,
    /// Kept for the sake of compatibility, but not normally used (unless a custom_layer_selection overrides it)
    payload: Option<Box<dyn LayerObject>>,
}

impl LayerLength for Raw {
    #[inline]
    fn len(&self) -> usize {
        self.data.len()
            + match &self.payload {
                Some(i) => i.len(),
                None => 0,
            }
    }
}

impl LayerObject for Raw {
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
        ret.expect(
            format!(
                "remove_payload() called on {} layer when layer had no payload",
                self.layer_name()
            )
            .as_str(),
        )
    }
}

impl ToBytes for Raw {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        bytes.extend(&self.data);
        match &self.payload {
            None => (),
            Some(p) => p.to_bytes_extended(bytes),
        }
    }
}

impl FromBytesCurrent for Raw {
    #[inline]
    fn from_bytes_payload_unchecked_default(&mut self, _bytes: &[u8]) {
        self.payload = None;
    }

    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        Raw {
            data: Vec::from(bytes),
            payload: None,
        }
    }
}

impl CanSetPayload for Raw {
    #[inline]
    fn can_set_payload_default(&self, _payload: &dyn LayerObject) -> bool {
        false
    }
}

impl Raw {
    #[inline]
    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut Vec<u8> {
        &mut self.data
    }
}

#[derive(Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Raw)]
#[metadata_type(RawMetadata)]
pub struct RawRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> FromBytesRef<'a> for RawRef<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        RawRef { data: packet }
    }
}

impl LayerOffset for RawRef<'_> {
    #[inline]
    fn payload_byte_index_default(_bytes: &[u8], _layer_type: LayerId) -> Option<usize> {
        None
    }
}

impl Validate for RawRef<'_> {
    #[inline]
    fn validate_current_layer(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(())
    }

    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(())
    }
}

impl RawRef<'_> {
    #[inline]
    pub fn data(&self) -> &[u8] {
        self.data
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[owned_type(Raw)]
#[ref_type(RawRef)]
#[metadata_type(RawMetadata)]
pub struct RawMut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    len: usize,
}

impl<'a> FromBytesMut<'a> for RawMut<'a> {
    #[inline]
    fn from_bytes_trailing_unchecked(bytes: &'a mut [u8], length: usize) -> Self {
        RawMut {
            len: length,
            data: bytes,
        }
    }
}

impl<'a> From<&'a RawMut<'a>> for RawRef<'a> {
    #[inline]
    fn from(value: &'a RawMut<'a>) -> Self {
        RawRef {
            data: &value.data[..value.len],
        }
    }
}

impl RawMut<'_> {
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len]
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}
