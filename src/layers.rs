pub mod ip;
pub mod l2;
pub mod mysql;
pub mod tcp;
pub mod traits;
pub mod udp;

use crate::layers::traits::*;

use rscap_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use core::any;
use core::fmt::Debug;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(RawMetadata)]
#[ref_type(RawRef)]
pub struct Raw {
    data: Vec<u8>,
    /// Kept for the sake of compatibility, but not normally used (unless a custom_layer_selection overrides it)
    #[payload_field]
    payload: Option<Box<dyn Layer>>,
}

impl ToByteVec for Raw {
    fn to_byte_vec_extend(&self, bytes: &mut Vec<u8>) {
        bytes.extend(&self.data);
        match &self.payload {
            None => (),
            Some(p) => p.to_byte_vec_extend(bytes),
        }
    }
}

impl From<&RawRef<'_>> for Raw {
    #[inline]
    fn from(value: &RawRef<'_>) -> Raw {
        Raw {
            data: Vec::from(<&[u8]>::from(value)),
            payload: None,
        }
    }
}

impl LayerImpl for Raw {
    #[inline]
    fn can_set_payload_default(&self, payload: Option<&dyn Layer>) -> bool {
        payload.is_none()
    }

    #[inline]
    fn len(&self) -> usize {
        self.data.len()
            + match &self.payload {
                Some(i) => i.len(),
                None => 0,
            }
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
    fn get_layer_offset_default(_bytes: &[u8], _layer_type: any::TypeId) -> Option<usize> {
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
            data: &value.data[..value.len]
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
