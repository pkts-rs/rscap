use super::{traits::*, Raw, RawRef};
use rscap_macros::{Layer, LayerRef, StatelessLayer};

// SIDE NOTE: postgres will be able to be a stateless protocol
// This is because all other packets besides StartupMessage and
// its related packets(SSLRequest, etc.) start with a 4-byte length
// field. This length field can safely be assumed to be less than
// 1 gigabyte (there just aren't enough options to warrant that),
// so we can assume that the first byte will be less than the ascii
// '1'. This in turn allows us to infer protocol state from the
// first byte of a given packet!
//
// Mysql, unfortunately, is not so simple. It's gonna require some state.

#[derive(Clone, Debug, Layer, StatelessLayer)]
#[metadata_type(MysqlPacketMetadata)]
#[ref_type(MysqlPacketRef)]
pub struct MysqlPacket {
    sequence_id: u8,
    #[payload_field]
    payload: Option<Box<dyn Layer>>,
}

impl ToByteVec for MysqlPacket {
    fn to_byte_vec_extend(&self, bytes: &mut Vec<u8>) {
        todo!()
    }
}

impl LayerImpl for MysqlPacket {
    #[inline]
    fn can_set_payload_default(&self, payload: Option<&dyn Layer>) -> bool {
        match payload {
            None => true,
            Some(p) => p.as_any().downcast_ref::<&MysqlClient>().is_some(),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        4 + match &self.payload {
            Some(p) => p.len(),
            None => 0,
        }
    }
}

impl<'a> From<&MysqlPacketRef<'a>> for MysqlPacket {
    #[inline]
    fn from(value: &MysqlPacketRef<'a>) -> Self {
        let sequence_id = value.data[0];
        if value.data[1] == 0 && value.data[1] == 0 && value.data[2] == 0 {
            MysqlPacket {
                sequence_id,
                payload: None,
            }
        } else {
            MysqlPacket {
                sequence_id,
                payload: Some(Box::new(Raw::from_bytes_unchecked(&value.data[4..]))),
            }
        }
    }
}

impl MysqlPacket {
    pub fn sequence_id(&self) -> u8 {
        self.sequence_id
    }

    pub fn set_sequence_id(&mut self, seq_id: u8) {
        self.sequence_id = seq_id
    }
}

#[derive(Copy, Clone, Debug, LayerRef, StatelessLayer)]
#[owned_type(MysqlPacket)]
#[metadata_type(MysqlPacketMetadata)]
pub struct MysqlPacketRef<'a> {
    #[data_field]
    data: &'a [u8],
}

impl<'a> FromBytesRef<'a> for MysqlPacketRef<'a> {
    #[inline]
    fn from_bytes_unchecked(bytes: &'a [u8]) -> Self {
        MysqlPacketRef { data: bytes }
    }
}

impl<'a> LayerOffset for MysqlPacketRef<'a> {
    #[inline]
    fn get_layer_offset_default(bytes: &[u8], layer_type: std::any::TypeId) -> Option<usize> {
        if (bytes[0] != 0 || bytes[1] != 0 || bytes[2] != 0)
            && RawRef::layer_id_static() == layer_type
        {
            Some(4)
        } else {
            None
        }
    }
}

impl<'a> Validate for MysqlPacketRef<'a> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        if curr_layer.len() < 4 {
            return Err(ValidationError::InvalidSize);
        }

        let payload_len = ((curr_layer[0] as usize) << 16)
            + ((curr_layer[1] as usize) << 8)
            + curr_layer[2] as usize;

        if curr_layer[4..].len() < payload_len {
            Err(ValidationError::InvalidSize)
        } else if curr_layer[4..].len() > payload_len {
            Err(ValidationError::TrailingBytes(
                curr_layer[4..].len() - payload_len,
            ))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn validate_payload_default(_curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(()) // Payload always defaults to `Raw`
    }
}

impl<'a> MysqlPacketRef<'a> {
    #[inline]
    pub fn payload_length(&self) -> usize {
        ((self.data[0] as usize) << 16) + ((self.data[1] as usize) << 8) + self.data[2] as usize
    }

    #[inline]
    pub fn sequence_id(&self) -> u8 {
        self.data[3]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        &self.data[4..]
    }
}

#[derive(Clone, Debug, Layer)]
#[metadata_type(MysqlClientMetadata)]
#[ref_type(MysqlClientRef)]
pub struct MysqlClient {
    pub sequence_id: u8,
    #[payload_field]
    pub payload: Option<Box<dyn Layer>>,
}

impl ToByteVec for MysqlClient {
    fn to_byte_vec_extend(&self, bytes: &mut Vec<u8>) {
        todo!()
    }
}

impl LayerImpl for MysqlClient {
    #[inline]
    fn can_set_payload_default(&self, payload: Option<&dyn Layer>) -> bool {
        payload.is_none()
    }

    fn len(&self) -> usize {
        todo!()
    }
}

impl<'a> From<&MysqlClientRef<'a>> for MysqlClient {
    fn from(value: &MysqlClientRef<'a>) -> Self {
        todo!()
    }
}

#[derive(Copy, Clone, Debug, LayerRef)]
#[owned_type(MysqlClient)]
#[metadata_type(MysqlClientMetadata)]
pub struct MysqlClientRef<'a> {
    #[data_field]
    data: &'a [u8],
    message_type: MessageType,
}

impl<'a> LayerOffset for MysqlClientRef<'a> {
    #[inline]
    fn get_layer_offset_default(_bytes: &[u8], _layer_type: std::any::TypeId) -> Option<usize> {
        None // Mysql does not encapsulate any inner layer
    }
}

impl<'a> MysqlClientRef<'a> {
    pub fn from_bytes_unchecked(bytes: &'a [u8], packet_type: MessageType) -> MysqlClientRef<'a> {
        MysqlClientRef {
            data: bytes,
            message_type: packet_type,
        }
    }

    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    pub fn message(&self) -> MessageTypeRef {
        todo!()
    }

    pub fn message_mut(&mut self) -> MessageTypeRef {
        todo!()
    }
}

/*
impl<'a> Validate for MysqlClientRef<'a> {
    #[inline]
    fn validate_current_layer(curr_layer: &[u8]) -> Result<(), ValidationError> {
        panic!("TODO: add `stateful protocol from unchecked bytes` error here as well")
    }

    #[inline]
    fn validate_payload_default(curr_layer: &[u8]) -> Result<(), ValidationError> {
        Ok(())
    }
}
*/

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageTypeOwned {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageTypeRef {
    // <'a>
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageTypeMut {
    // <'a>
}
