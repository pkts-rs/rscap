// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me@nathanielbennett.com>

use pkts_macros::{Layer, LayerMut, LayerRef, StatelessLayer};

use crate::layers::traits::extras::*;
use crate::layers::traits::*;
use crate::{error::*, LendingIterator};

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(ExampleMetadata)]
#[ref_type(ExampleRef)]
pub struct Example {

}

impl Example {

}

impl CanSetPayload for Example {
    fn can_set_payload_default(&self, payload: &dyn LayerObject) -> bool {
        todo!()
    }
}

impl FromBytesCurrent for Example {
    fn payload_from_bytes_unchecked_default(&mut self, bytes: &[u8]) {
        todo!()
    }

    fn from_bytes_current_layer_unchecked(bytes: &[u8]) -> Self {
        todo!()
    }
}

impl LayerLength for Example {
    fn len(&self) -> usize {
        todo!()
    }
}

impl LayerObject for Example {
    fn get_payload_ref(&self) -> Option<&dyn LayerObject> {
        todo!()
    }

    fn get_payload_mut(&mut self) -> Option<&mut dyn LayerObject> {
        todo!()
    }

    fn has_payload(&self) -> bool {
        todo!()
    }

    fn remove_payload(&mut self) -> Box<dyn LayerObject> {
        todo!()
    }

    fn set_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        todo!()
    }
}

impl ToBytes for Example {
    fn to_bytes_extended(&self, bytes: &mut Vec<u8>) {
        todo!()
    }
}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(Example)]
#[metadata_type(ExampleMetadata)]
pub struct ExampleRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> ExampleRef<'a> {

}

impl<'a> FromBytesRef<'a> for ExampleRef<'a> {
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        todo!()
    }
}

impl<'a> LayerOffset for ExampleRef<'a> {
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        todo!()
    }
}

impl<'a> Validate for ExampleRef<'a> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}