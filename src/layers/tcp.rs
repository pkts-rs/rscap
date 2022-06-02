use crate::layers::traits::{
    AnyLayerMut, AnyLayerRef, BaseLayer, BaseLayerAppend, ConstSingleton, FromBytes, FromBytesMut,
    IntoLayer, Layer, LayerAppend, LayerIndex, LayerMetadata, LayerMut, LayerRef, LayerStruct,
    TcpAssociatedMetadata, ToOwnedLayer, ValidateBytes, ValidationError,
};

#[cfg(feature = "custom_layer_selection")]
use crate::layers::traits::{BaseLayerSelection, CustomLayerSelection, TcpLayerSelection};

use core::fmt::Debug;
use rscap_macros::{MutLayerDerives, OwnedLayerDerives, RefLayerDerives};

#[derive(Clone, OwnedLayerDerives)]
#[owned_name(Tcp)]
#[metadata_type(TcpAssociatedMetadata)]
#[custom_layer_selection(TcpLayerSelection)]
pub struct Tcp {
    pub sport: u32,
    pub dport: u32,
    pub payload: Option<Box<dyn Layer>>,
}

impl Debug for Tcp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TCP")
            .field("sport", &self.sport)
            .field("dport", &self.dport)
            .finish()
    }
}

impl Layer for Tcp {
    #[inline]
    fn get_payload_ref(&self) -> Option<&dyn Layer> {
        match &self.payload {
            Some(p) => Some(p.as_ref()),
            None => None,
        }
    }

    #[inline]
    fn get_payload_mut(&mut self) -> Option<&mut dyn Layer> {
        match &mut self.payload {
            Some(p) => Some(p.as_mut()),
            None => None,
        }
    }

    #[inline]
    fn can_set_payload(&self, _payload: Option<&dyn Layer>) -> bool {
        true
    }

    #[inline]
    fn set_payload(&mut self, payload: Option<Box<dyn Layer>>) -> Result<(), &'static str> {
        self.payload = payload;
        Ok(())
    }

    #[inline]
    fn set_payload_unchecked(&mut self, payload: Option<Box<dyn Layer>>) {
        self.payload = payload;
    }
}

impl ValidateBytes for Tcp {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl FromBytes<'_> for Tcp {
    fn from_bytes_unchecked(bytes: &'_ [u8]) -> Self {
        todo!()
    }
}

#[derive(Clone, Debug, RefLayerDerives)]
#[owned_name(Tcp)]
#[metadata_type(TcpAssociatedMetadata)]
#[custom_layer_selection(TcpLayerSelection)]
pub struct TcpRef<'a> {
    data: &'a [u8],
}

impl<'a> LayerRef<'a> for TcpRef<'a> {
    fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    fn get_layer<T: LayerRef<'a>>(&self) -> Option<T> {
        if self.is_layer::<T>() {
            return Some(unsafe {
                TcpRef::from_bytes_unchecked(self.data).cast_layer_unchecked::<T>()
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
        todo!()
    }
    /*
    fn new(data: &'a [u8]) -> Option<Self> {
        // TODO: check data for soundness here
        Some(LayerRef::new_unchecked(data))
    }

    fn new_unchecked(data: &'a [u8]) -> Self {
        TcpRef { data }
    }
    */
}

impl ValidateBytes for TcpRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl<'a> FromBytes<'a> for TcpRef<'a> {
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        TcpRef { data: bytes }
    }
}

#[derive(Debug, MutLayerDerives)]
#[ref_name(TcpRef)]
#[owned_name(Tcp)]
#[metadata_type(TcpAssociatedMetadata)]
#[custom_layer_selection(TcpLayerSelection)]
pub struct TcpMut<'a> {
    data: &'a mut [u8],
    len: usize,
}

impl<'a> LayerMut<'a> for TcpMut<'a> {
    /*
    fn new(data: &'a mut [u8]) -> Option<Self> {
        // TODO: check data for soundness here
        Some(LayerMut::new_unchecked(data))
    }

    fn new_unchecked(data: &'a mut [u8]) -> Self {
        TcpMut { data }
    }
    */

    fn as_bytes(&'a self) -> &'a [u8] {
        &self.data[0..self.len]
    }

    fn as_bytes_mut(&'a mut self) -> &'a mut [u8] {
        &mut self.data[0..self.len]
    }

    fn get_layer<T: LayerRef<'a>>(&'a self) -> Option<T> {
        TcpMut::get_layer_from_raw(self.data)
    }

    fn get_layer_mut<T: LayerMut<'a>>(&'a mut self) -> Option<T> {
        TcpMut::get_layer_mut_from_raw(self.data)
    }

    fn get_layer_from_raw<'b, T: LayerRef<'b>>(bytes: &'b [u8]) -> Option<T> {
        todo!()
    }

    fn get_layer_mut_from_raw<'b, T: LayerMut<'b>>(bytes: &'b mut [u8]) -> Option<T> {
        todo!()
    }
}

impl ValidateBytes for TcpMut<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl<'a> FromBytesMut<'a> for TcpMut<'a> {
    fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self {
        TcpMut {
            len: bytes.len(),
            data: bytes,
        }
    }
}
