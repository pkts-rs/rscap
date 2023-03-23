// Copyright 2022 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[derive(Copy, Clone, Debug)]
pub struct ValidationError {
    pub layer: &'static str,
    pub err_type: ValidationErrorType,
    pub reason: &'static str,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ValidationErrorType {
    InvalidPayloadLayer,
    InsufficientBytes, // Packet needs more bytes to be well-formed
    InvalidSize, // A size field in a packet conflicts with the actual composition of its contents; or two size fields conflict
    InvalidValue,
    ExcessBytes(usize), // Packet had excess bytes at the end of it
}
