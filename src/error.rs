#[derive(Copy, Clone, Debug)]
pub struct ValidationError {
    pub layer: &'static str,
    pub err_type: ValidationErrorType,
    pub reason: &'static str,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ValidationErrorType {
    InvalidPayloadLayer,
    InvalidSize,
    InvalidValue,
    TrailingBytes(usize),
}
