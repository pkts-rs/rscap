// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) Nathaniel Bennett <me[at]nathanielbennnett[dotcom]>

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
