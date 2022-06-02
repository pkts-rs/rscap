use crate::layers::traits::*;

use core::fmt::Debug;
use rscap_macros::{MutLayerDerives, OwnedLayerDerives, RefLayerDerives};

#[derive(Clone, OwnedLayerDerives)]
#[owned_name(Udp)]
#[metadata_type(UdpAssociatedMetadata)]
#[custom_layer_selection(UdpLayerSelection)]
pub struct Udp {
    pub sport: u32,
    pub dport: u32,
    pub payload: Option<Box<dyn Layer>>,
}

impl Debug for Udp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UDP")
            .field("sport", &self.sport)
            .field("dport", &self.dport)
            .finish()
    }
}

impl Layer for Udp {
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
