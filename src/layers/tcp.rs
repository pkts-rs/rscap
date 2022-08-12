use crate::layers::traits::*;
use core::any;
use rscap_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(TcpAssociatedMetadata)]
#[ref_type(TcpRef)]
pub struct Tcp {
    pub sport: u32,
    pub dport: u32,
    #[payload_field]
    pub payload: Option<Box<dyn Layer>>,
}

impl ToBytes for Tcp {
    fn to_bytes_extend(&self, bytes: &mut Vec<u8>) {
        todo!()
    }
}

impl From<&TcpRef<'_>> for Tcp {
    fn from(value: &TcpRef<'_>) -> Self {
        todo!()
    }
}

impl FromBytesCurrent for Tcp {
    #[inline]
    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        todo!()
    }
}

impl LayerImpl for Tcp {
    #[inline]
    fn can_set_payload_default(&self, _payload: Option<&dyn Layer>) -> bool {
        true // any protocol may be served over TCP
    }

    #[inline]
    fn len(&self) -> usize {
        todo!()
    }
}

#[derive(Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Tcp)]
#[metadata_type(TcpAssociatedMetadata)]
pub struct TcpRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> FromBytesRef<'a> for TcpRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        TcpRef { data: bytes }
    }
}

impl LayerByteIndexDefault for TcpRef<'_> {
    fn get_layer_byte_index_default(bytes: &[u8], layer_type: any::TypeId) -> Option<usize> {
        todo!()
    }
}

impl Validate for TcpRef<'_> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(()) // By default, we assume the next layer after Tcp is Raw, which has no validation constraints
    }
}

#[derive(Debug, LayerMut, StatelessLayer)]
#[ref_type(TcpRef)]
#[owned_type(Tcp)]
#[metadata_type(TcpAssociatedMetadata)]
pub struct TcpMut<'a> {
    #[data_field]
    data: &'a mut [u8],
    #[data_length_field]
    len: usize,
}

impl<'a> From<&'a TcpMut<'a>> for TcpRef<'a> {
    #[inline]
    fn from(value: &'a TcpMut<'a>) -> Self {
        TcpRef {
            data: &value.data[..value.len],
        }
    }
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
