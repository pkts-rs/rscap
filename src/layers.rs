pub mod inet;
pub mod l2;
pub mod tcp;
pub mod traits;
pub mod udp;

use rscap_macros::{OwnedLayerDerives, RefLayerDerives, MutLayerDerives};

use crate::layers::traits::*;

use core::fmt::Debug;

/*
impl<'a, T: From<&'a [u8]> + ValidateBytes> TryFrom<&'a [u8]> for T {
    type Error = ValidationError;

    fn try_from(value: &'a [u8]) -> Result<T, Self::Error> {
        Self::validate(value)?;
        Ok(Self::from(value))
    }
}
*/


#[derive(Clone, OwnedLayerDerives)]
#[owned_name(Raw)]
#[metadata_type(RawAssociatedMetadata)]
#[custom_layer_selection(RawLayerSelection)]
pub struct Raw {
    data: Vec<u8>,
    /// Kept for the sake of compatibility of methods, but not normally used (unless a custom_layer_selection overrides it)
    payload: Option<Box<dyn Layer>>,
}

impl Debug for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Raw")
            .field("data", &self.data)
            .finish()
    }
}

impl Layer for Raw {
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
        payload.is_none()
    }

    #[inline]
    fn set_payload_unchecked(&mut self, payload: Option<Box<dyn Layer>>) {
        self.payload = payload
    }
}

impl ValidateBytes for Raw {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl FromBytes<'_> for Raw {
    #[inline]
    fn from_bytes_unchecked(bytes: &'_ [u8]) -> Self {
        Raw { data: Vec::from(bytes), payload: None }
    }
}

#[derive(Clone, Debug, RefLayerDerives)]
#[owned_name(Raw)]
#[metadata_type(Ipv4AssociatedMetadata)]
#[custom_layer_selection(Ipv4LayerSelection)]
pub struct RawRef<'a> {
    data: &'a [u8],
}

impl ValidateBytes for RawRef<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl<'a> FromBytes<'a> for RawRef<'a> {
    #[inline]
    fn from_bytes_unchecked(packet: &'a [u8]) -> Self {
        RawRef { data: packet }
    }
}

impl<'a> LayerRef<'a> for RawRef<'a> {
    #[inline]
    fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    fn get_layer<T: LayerRef<'a>>(&self) -> Option<T> {
        if self.is_layer::<T>() {
            return Some(unsafe {
                RawRef::from_bytes_unchecked(self.data).cast_layer_unchecked::<T>()
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

        None
    }
}

#[derive(Debug, MutLayerDerives)]
#[owned_name(Raw)]
#[ref_name(RawRef)]
#[metadata_type(Ipv4AssociatedMetadata)]
#[custom_layer_selection(Ipv4LayerSelection)]
pub struct RawMut<'a> {
    data: &'a mut [u8],
}

impl<'a> LayerMut<'a> for RawMut<'a> {
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
        #[cfg(feature = "custom_layer_selection")]
        if let Some(&custom_selection) = self
            .custom_layer_selection_instance()
            .as_any()
            .downcast_ref::<&dyn CustomLayerSelection>()
        {
            return custom_selection
                .get_layer_from_next(self.data, &T::type_layer_id())
                .map(|offset| T::from_bytes_unchecked(&mut self.data[offset..]));
        }

        Self::get_layer_mut_from_raw(self.data)
    }

    /// The non-custom variant of get_layer (if custom layer selection is used)
    fn get_layer_from_raw<'b, T: LayerRef<'b>>(_bytes: &'b [u8]) -> Option<T> {
        None
    }

    fn get_layer_mut_from_raw<'b, T: LayerMut<'b>>(_bytes: &'b mut [u8]) -> Option<T> {
        None
    }
}

impl ValidateBytes for RawMut<'_> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}

impl<'a> FromBytesMut<'a> for RawMut<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a mut [u8]) -> Self {
        RawMut { data: bytes }
    }
}