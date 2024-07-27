// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use pkts_macros::{Layer, LayerRef, StatelessLayer};

use crate::error::*;
use crate::layers::dev_traits::*;
use crate::layers::traits::*;

#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::boxed::Box;
#[cfg(all(not(feature = "std"), feature = "alloc"))]
use alloc::vec::Vec;

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(ExampleMetadata)]
#[ref_type(ExampleRef)]
pub struct Example {}

impl Example {}

#[doc(hidden)]
#[allow(unused_variables)]
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

#[allow(unused_variables)]
impl LayerObject for Example {
    fn can_add_payload_default(&self, payload: &dyn LayerObject) -> bool {
        todo!()
    }

    #[inline]
    fn add_payload_unchecked(&mut self, payload: Box<dyn LayerObject>) {
        todo!()
    }

    #[inline]
    fn payloads(&self) -> &[Box<dyn LayerObject>] {
        todo!()
    }

    fn payloads_mut(&mut self) -> &mut [Box<dyn LayerObject>] {
        todo!()
    }

    fn remove_payload_at(&mut self, index: usize) -> Option<Box<dyn LayerObject>> {
        todo!()
    }
}

#[allow(unused_variables)]
impl ToBytes for Example {
    fn to_bytes_checksummed(
        &self,
        bytes: &mut Vec<u8>,
        prev: Option<(LayerId, usize)>,
    ) -> Result<(), SerializationError> {
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

impl<'a> ExampleRef<'a> {}

#[allow(unused_variables)]
impl<'a> FromBytesRef<'a> for ExampleRef<'a> {
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        todo!()
    }
}

#[allow(unused_variables)]
impl<'a> LayerOffset for ExampleRef<'a> {
    fn payload_byte_index_default(bytes: &[u8], layer_type: LayerId) -> Option<usize> {
        todo!()
    }
}

#[allow(unused_variables)]
impl<'a> Validate for ExampleRef<'a> {
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }

    #[doc(hidden)]
    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}
