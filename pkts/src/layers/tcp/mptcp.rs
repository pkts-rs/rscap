use core::{array, mem, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

use bitflags::bitflags;

use pkts_common::Buffer;

use crate::{utils, IndexedWritable, PacketWriter};

use super::{SerializationError, Tcp, TCP_OPT_KIND_MPTCP};

pub const MP_CAPABLE: u8 = 0x0;
pub const MP_JOIN: u8 = 0x1;
pub const MP_DSS: u8 = 0x2;
pub const MP_ADD_ADDR: u8 = 0x3;
pub const MP_REMOVE_ADDR: u8 = 0x4;
pub const MP_PRIO: u8 = 0x5;
pub const MP_FAIL: u8 = 0x6;
pub const MP_FASTCLOSE: u8 = 0x7;
pub const MP_TCPRST: u8 = 0x8;
pub const MP_EXPERIMENTAL: u8 = 0xf;

#[derive(Clone, Debug)]
pub enum Mptcp {
    Capable(CapableOpt),
    Join(JoinOpt),
    Dss(DssOpt),
    AddAddr(AddAddrOpt),
    RemoveAddr(RemoveAddrOpt),
    Prio(PrioOpt),
    Fail(FallbackOpt),
    FastClose(FastCloseOpt),
    TcpRst(ResetOpt),
    Unknown(GenericOpt),
    Experimetal(GenericOpt), // Same as unknown but for subtype 0xf
}

impl Mptcp {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        match self {
            Mptcp::Capable(o) => o.to_bytes_extended(writable),
            Mptcp::Join(o) => o.to_bytes_extended(writable),
            Mptcp::Dss(o) => o.to_bytes_extended(writable),
            Mptcp::AddAddr(o) => o.to_bytes_extended(writable),
            Mptcp::RemoveAddr(o) => o.to_bytes_extended(writable),
            Mptcp::Prio(o) => o.to_bytes_extended(writable),
            Mptcp::Fail(o) => o.to_bytes_extended(writable),
            Mptcp::FastClose(o) => o.to_bytes_extended(writable),
            Mptcp::TcpRst(o) => o.to_bytes_extended(writable),
            Mptcp::Unknown(o) => o.to_bytes_extended(writable),
            Mptcp::Experimetal(o) => o.to_bytes_extended(writable),
        }
    }


    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let subtype = data[3] >> 4;
        match subtype {
            MP_CAPABLE => Self::Capable(CapableOpt::from_bytes_unchecked(data)),
            MP_JOIN => Self::Join(JoinOpt::from_bytes_unchecked(data)),
            MP_DSS => Self::Dss(DssOpt::from_bytes_unchecked(data)),
            MP_ADD_ADDR => Self::AddAddr(AddAddrOpt::from_bytes_unchecked(data)),
            MP_REMOVE_ADDR => Self::RemoveAddr(RemoveAddrOpt::from_bytes_unchecked(data)),
            MP_PRIO => Self::Prio(PrioOpt::from_bytes_unchecked(data)),
            MP_FAIL => Self::Fail(FallbackOpt::from_bytes_unchecked(data)),
            MP_FASTCLOSE => Self::FastClose(FastCloseOpt::from_bytes_unchecked(data)),
            MP_TCPRST => Self::TcpRst(ResetOpt::from_bytes_unchecked(data)),
            MP_EXPERIMENTAL => Self::Experimetal(GenericOpt::from_bytes_unchecked(data)),
            _ => Self::Unknown(GenericOpt::from_bytes_unchecked(data)),
        }
    }

    pub fn byte_len(&self) -> usize {
        match self {
            Mptcp::Capable(c) => c.byte_len(),
            Mptcp::Join(j) => j.byte_len(),
            Mptcp::Dss(d) => d.byte_len(),
            Mptcp::AddAddr(a) => a.byte_len(),
            Mptcp::RemoveAddr(r) => r.byte_len(),
            Mptcp::Prio(p) => p.byte_len(),
            Mptcp::Fail(f) => f.byte_len(),
            Mptcp::FastClose(f) => f.byte_len(),
            Mptcp::TcpRst(t) => t.byte_len(),
            Mptcp::Unknown(u) => u.byte_len(),
            Mptcp::Experimetal(e) => e.byte_len(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct GenericOpt {
    subtype: u8,
    reserved: u8,
    data: Buffer<u8, 37>, // 1 byte each for type, length and subtype.
}

impl GenericOpt {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&[(self.subtype << 4) | self.reserved])?;
        writer.write(self.data.as_slice())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let subtype = data[2] >> 4;
        let reserved = data[2] & 0x0f;
        let mut buf = Buffer::new();
        buf.append(&data[3..]);

        Self {
            subtype,
            reserved,
            data: buf,
        }
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        3 + self.data.len()
    }

    #[inline]
    pub fn subtype(&self) -> u8 {
        self.subtype
    }

    #[inline]
    pub fn set_subtype(&mut self, subtype: u8) {
        self.subtype = subtype & 0x0f;
    }

    #[inline]
    pub fn reserved(&self) -> u8 {
        self.reserved
    }

    #[inline]
    pub fn set_reserved(&mut self, reserved: u8) {
        self.reserved = reserved & 0x0f;
    }

    #[inline]
    pub fn data(&self) -> &Buffer<u8, 37> {
        &self.data
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut Buffer<u8, 37> {
        &mut self.data
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct CapableFlags: u8 {
        /// Checksum Required flag.
        const A = 0b_1000_0000;
        /// Extensibility flag.
        const B = 0b_0100_0000;
        /// Indicates no new subflows should be established to the source address.
        const C = 0b_0010_0000;
        /// Unassigned.
        const D = 0b_0001_0000;
        /// Unassigned.
        const E = 0b_0000_1000;
        /// Unassigned.
        const F = 0b_0000_0100;
        /// Unassigned.
        const G = 0b_0000_0010;
        /// HMAC-SHA256 flag.
        const H = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct CapableOpt {
    flags: CapableFlags,
    sender_key: Option<u64>,
    receiver_key: Option<u64>,
    data_len: Option<u16>,
    chksum: Option<u16>,
}

impl CapableOpt {
    const SENDER_KEY_OFFSET: usize = 4;
    const RECEIVER_KEY_OFFSET: usize = 12;
    const DATA_LEN_OFFSET: usize = 20;
    const CHKSUM_OFFSET: usize = 22;

    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&[(self.subtype() << 4) | self.version(), self.flags().bits()])?;

        if let Some(sender_key) = self.sender_key {
            writer.write(&sender_key.to_be_bytes())?;
        }

        if let Some(receiver_key) = self.receiver_key {
            writer.write(&receiver_key.to_be_bytes())?;
        }

        if let Some(data_len) = self.data_len {
            writer.write(&data_len.to_be_bytes())?;
        }

        if let Some(chksum) = self.chksum {
            writer.write(&chksum.to_be_bytes())?;
        }

        Ok(())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        debug_assert_eq!(data[2] & 0x0f, 1);
        let optlen = data[1] as usize;
        let flags = CapableFlags::from_bits_truncate(data[3]);

        let sender_key = if optlen > Self::SENDER_KEY_OFFSET {
            Some(u64::from_be_bytes(utils::to_array(data, Self::SENDER_KEY_OFFSET).unwrap()))
        } else {
            None
        };

        let receiver_key = if optlen > Self::RECEIVER_KEY_OFFSET {
            Some(u64::from_be_bytes(utils::to_array(data, Self::RECEIVER_KEY_OFFSET).unwrap()))
        } else {
            None
        };

        let data_len = if optlen > Self::DATA_LEN_OFFSET {
            Some(u16::from_be_bytes(utils::to_array(data, Self::DATA_LEN_OFFSET).unwrap()))
        } else {
            None
        };

        let chksum = if optlen > Self::CHKSUM_OFFSET {
            Some(u16::from_be_bytes(utils::to_array(data, Self::CHKSUM_OFFSET).unwrap()))
        } else {
            None
        };
        
        Self {
            flags,
            sender_key,
            receiver_key,
            data_len,
            chksum,
        }
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        if self.sender_key.is_none() {
            4
        } else if self.receiver_key.is_none() {
            12
        } else if self.data_len.is_none() {
            20
        } else if self.chksum.is_none() {
            22
        } else {
            24
        }
    }

    #[inline]
    pub fn subtype(&self) -> u8 {
        MP_CAPABLE
    }

    #[inline]
    pub fn version(&self) -> u8 {
        1
    }

    #[inline]
    pub fn flags(&self) -> CapableFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: CapableFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn sender_key(&self) -> Option<u64> {
        self.sender_key
    }

    #[inline]
    pub fn set_sender_key(&mut self, sender_key: Option<u64>) {
        self.sender_key = sender_key;
    }

    #[inline]
    pub fn receiver_key(&self) -> Option<u64> {
        self.receiver_key
    }

    #[inline]
    pub fn set_receiver_key(&mut self, receiver_key: Option<u64>) {
        self.receiver_key = receiver_key;
    }

    #[inline]
    pub fn data_len(&self) -> Option<u16> {
        self.data_len
    }

    #[inline]
    pub fn set_data_len(&mut self, data_len: Option<u16>) {
        self.data_len = data_len;
    }

    #[inline]
    pub fn chksum(&self) -> Option<u16> {
        self.chksum
    }

    #[inline]
    pub fn set_chksum(&mut self, chksum: Option<u16>) {
        self.chksum = chksum;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct JoinFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const B = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct JoinOpt {
    flags: JoinFlags,
    addr_id: u8,
    payload: JoinPayload,
}

impl JoinOpt {
    const OPTLEN_OFFSET: usize = 1;
    const FLAGS_OFFSET: usize = 2;
    const ADDR_ID_OFFSET: usize = 3;
    const RECEIVER_TOKEN_OFFSET: usize = 4;
    const HMAC_OFFSET: usize = 4;

    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&[(self.subtype() << 4) | self.flags().bits(), self.addr_id])?;
        match &self.payload {
            JoinPayload::Syn(syn) => {
                writer.write(&syn.receiver_token.to_be_bytes())?;
                writer.write(&syn.sender_rand.to_be_bytes())
            }
            JoinPayload::SynAck(synack) => {
                writer.write(&synack.sender_hmac)?;
                writer.write(&synack.sender_rand.to_be_bytes())
            }
            JoinPayload::Ack(ack) => {
                writer.write(&ack.sender_hmac)
            }
        }
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let flags = JoinFlags::from_bits_truncate(data[Self::FLAGS_OFFSET]);
        let addr_id = data[Self::ADDR_ID_OFFSET];
        let payload = match data[Self::OPTLEN_OFFSET] {
            12 => {
                let receiver_token = u32::from_be_bytes(utils::to_array(data, Self::RECEIVER_TOKEN_OFFSET).unwrap());
                let sender_rand = u32::from_be_bytes(utils::to_array(data, Self::RECEIVER_TOKEN_OFFSET + 4).unwrap());
                JoinPayload::Syn(JoinSyn {
                    receiver_token,
                    sender_rand,
                })
            }
            16 => {
                let sender_hmac = utils::to_array(data, Self::HMAC_OFFSET).unwrap();
                let sender_rand = u32::from_be_bytes(utils::to_array(data, Self::HMAC_OFFSET + 8).unwrap());
                JoinPayload::SynAck(JoinSynAck {
                    sender_hmac,
                    sender_rand,
                })
            }
            24 => {
                let sender_hmac = utils::to_array(data, Self::HMAC_OFFSET).unwrap();
                JoinPayload::Ack(JoinAck {
                    sender_hmac,
                })
            }
            _ => panic!(),
        };

        Self {
            flags,
            addr_id,
            payload,
        }
    }

    pub fn byte_len(&self) -> usize {
        match &self.payload {
            JoinPayload::Syn(_) => 12,
            JoinPayload::SynAck(_) => 16,
            JoinPayload::Ack(_) => 24,
        }
    }

    pub fn subtype(&self) -> u8 {
        MP_JOIN
    }

    pub fn flags(&self) -> JoinFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: JoinFlags) {
        self.flags = flags;
    }

    pub fn addr_id(&self) -> u8 {
        self.addr_id
    }

    pub fn set_addr_id(&mut self, addr_id: u8) {
        self.addr_id = addr_id;
    }

    pub fn payload(&self) -> &JoinPayload {
        &self.payload
    }

    pub fn payload_mut(&mut self) -> &mut JoinPayload {
        &mut self.payload
    }
}

#[derive(Clone, Debug)]
pub enum JoinPayload {
    Syn(JoinSyn),
    SynAck(JoinSynAck),
    Ack(JoinAck),
}

#[derive(Clone, Debug)]
pub struct JoinSyn {
    receiver_token: u32,
    sender_rand: u32,
}

impl JoinSyn {
    pub fn receiver_token(&self) -> u32 {
        self.receiver_token
    }

    pub fn set_receiver_token(&mut self, token: u32) {
        self.receiver_token = token;
    }

    pub fn sender_rand(&self) -> u32 {
        self.sender_rand
    }

    pub fn set_sender_rand(&mut self, rand: u32) {
        self.sender_rand = rand;
    }
}

#[derive(Clone, Debug)]
pub struct JoinSynAck {
    sender_hmac: [u8; 8],
    sender_rand: u32,
}

impl JoinSynAck {
    pub fn sender_hmac(&self) -> [u8; 8] {
        self.sender_hmac
    }

    pub fn set_sender_hmac(&mut self, trunc_hmac: [u8; 8]) {
        self.sender_hmac = trunc_hmac;
    }

    pub fn sender_rand(&self) -> u32 {
        self.sender_rand
    }

    pub fn set_sender_rand(&mut self, rand: u32) {
        self.sender_rand = rand;
    }
}

#[derive(Clone, Debug)]
pub struct JoinAck {
    sender_hmac: [u8; 20],
}

impl JoinAck {
    pub fn sender_hmac(&self) -> [u8; 20] {
        self.sender_hmac
    }

    pub fn set_sender_hmac(&mut self, trunc_hmac: [u8; 20]) {
        self.sender_hmac = trunc_hmac;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct DssFlags: u16 {
        const R1      = 0b_1000_0000_0000;
        const R2      = 0b_0100_0000_0000;
        const R3      = 0b_0010_0000_0000;
        const R4      = 0b_0001_0000_0000;
        const R5      = 0b_0000_1000_0000;
        const R6      = 0b_0000_0100_0000;
        const R7      = 0b_0000_0010_0000;
        const DATA_FIN     = 0b_0001_0000;
        const DSN_8_OCTETS = 0b_0000_1000;
        const DSN_PRESENT  = 0b_0000_0100;
        const ACK_8_OCTETS = 0b_0000_0010;
        const ACK_PRESENT  = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct DssOpt {
    flags: DssFlags,
    ack: Option<u64>,
    dsn_info: Option<DsnInfo>,
}

impl DssOpt {
    const FLAGS_OFFSET: usize = 2;
    const ACK_OFFSET: usize = 4;

    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&((self.subtype() << 4) as u16 | self.flags().bits()).to_be_bytes())?;

        if let Some(ack) = self.ack {
            if self.flags.contains(DssFlags::ACK_8_OCTETS) {
                writer.write(&ack.to_be_bytes())?;
            } else {
                writer.write(&(ack as u32).to_be_bytes())?;
            }
        }

        if let Some(dsn_info) = &self.dsn_info {
            if self.flags.contains(DssFlags::DSN_8_OCTETS) {
                writer.write(&dsn_info.dsn.to_be_bytes())?;
            } else {
                writer.write(&(dsn_info.dsn as u32).to_be_bytes())?;
            }

            writer.write(&dsn_info.ssn.to_be_bytes())?;
            writer.write(&dsn_info.dll.to_be_bytes())?;
            
            if let Some(chksum) = dsn_info.chksum {
                writer.write(&chksum.to_be_bytes())?;
            }
        }

        Ok(())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let optlen = data[1] as usize;
        let flags = DssFlags::from_bits_truncate(u16::from_be_bytes(utils::to_array(data, Self::FLAGS_OFFSET).unwrap()));
        let mut idx = Self::ACK_OFFSET;
        
        let ack = if !flags.contains(DssFlags::ACK_PRESENT) {
            None
        } else if flags.contains(DssFlags::ACK_8_OCTETS) {
            let ack = u64::from_be_bytes(utils::to_array(data, idx).unwrap());
            idx += 8;
            Some(ack)
        } else {
            let ack = u32::from_be_bytes(utils::to_array(data, idx).unwrap()) as u64;
            idx += 4;
            Some(ack)
        };

        let dsn_info = if flags.contains(DssFlags::DSN_PRESENT) {
            let dsn = if flags.contains(DssFlags::DSN_8_OCTETS) {
                let dsn = u64::from_be_bytes(utils::to_array(data, idx).unwrap());
                idx += 8;
                dsn
            } else {
                let dsn = u32::from_be_bytes(utils::to_array(data, idx).unwrap()) as u64;
                idx += 4;
                dsn
            };

            let ssn = u32::from_be_bytes(utils::to_array(data, idx).unwrap());
            idx += mem::size_of_val(&ssn);

            let dll = u16::from_be_bytes(utils::to_array(data, idx).unwrap());
            idx += mem::size_of_val(&dll);

            let chksum = if idx < optlen {
                let chksum = u16::from_be_bytes(utils::to_array(data, idx).unwrap());
                idx += mem::size_of_val(&chksum);
                Some(chksum)
            } else {
                None
            };

            debug_assert_eq!(optlen, idx);

            Some(DsnInfo {
                dsn,
                ssn,
                dll,
                chksum,
            })
        } else {
            None
        };

        return Self {
            flags,
            ack,
            dsn_info,
        }
    }

    pub fn byte_len(&self) -> usize {
        let mut len = 4;
        if self.ack.is_some() {
            len += if self.flags.contains(DssFlags::ACK_8_OCTETS) {
                8
            } else {
                4
            };
        }

        if let Some(info) = self.dsn_info {
            len += 6 + if self.flags.contains(DssFlags::DSN_8_OCTETS) {
                8
            } else {
                4
            };
            if info.chksum.is_some() {
                len += 2;
            }
        }

        len
    }

    pub fn subtype(&self) -> u8 {
        MP_DSS
    }

    pub fn flags(&self) -> DssFlags {
        self.flags
    }

    pub fn ack(&self) -> Option<u64> {
        self.ack
    }

    pub fn set_ack(&mut self, ack: Option<u64>) {
        self.ack = ack;
        self.flags.set(DssFlags::ACK_PRESENT, ack.is_some());
    }

    pub fn set_data_fin(&mut self, data_fin: bool) {
        self.flags.set(DssFlags::DATA_FIN, data_fin);
    }

    pub fn set_ack_8_octets(&mut self, is_8_octets: bool) {
        self.flags.set(DssFlags::ACK_8_OCTETS, is_8_octets);
    }

    pub fn set_dsn_8_octets(&mut self, is_8_octets: bool) {
        self.flags.set(DssFlags::DSN_8_OCTETS, is_8_octets);
    }

    pub fn dsn(&self) -> Option<DsnInfo> {
        self.dsn_info
    }

    pub fn set_dsn(&mut self, dsn: Option<DsnInfo>) {
        self.dsn_info = dsn;
        self.flags.set(DssFlags::DSN_PRESENT, dsn.is_some());
    }
}

#[derive(Copy, Clone, Debug)]
pub struct DsnInfo {
    dsn: u64,
    ssn: u32,
    dll: u16,
    chksum: Option<u16>,
}

impl DsnInfo {
    pub fn dsn(&self) -> u64 {
        self.dsn
    }

    pub fn set_dsn(&mut self, dsn: u64) {
        self.dsn = dsn;
    }

    pub fn ssn(&self) -> u32 {
        self.ssn
    }

    pub fn set_ssn(&mut self, ssn: u32) {
        self.ssn = ssn;
    }

    pub fn dll(&self) -> u16 {
        self.dll
    }

    pub fn set_dll(&mut self, dll: u16) {
        self.dll = dll;
    }

    pub fn chksum(&self) -> Option<u16> {
        self.chksum
    }

    pub fn set_chksum(&mut self, chksum: Option<u16>) {
        self.chksum = chksum;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct AddAddrFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const E = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct AddAddrOpt {
    flags: AddAddrFlags,
    addr_id: u8,
    addr: IpAddr,
    port: Option<u16>,
    hmac: Option<[u8; 8]>,
}

impl AddAddrOpt {
    const FLAGS_OFFSET: usize = 2;
    const ADDR_ID_OFFSET: usize = 3;
    const ADDR_OFFSET: usize = 4;

    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&[(self.subtype() << 4) | self.flags().bits(), self.addr_id])?;

        match &self.addr {
            IpAddr::V4(v4) => {
                writer.write(&v4.octets())?;
            }
            IpAddr::V6(v6) => {
                writer.write(&v6.octets())?;
            }
        }

        if let Some(port) = self.port {
            writer.write(&port.to_be_bytes())?;
        }

        if let Some(hmac) =self.hmac {
            writer.write(&hmac)?;
        }

        Ok(())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let optlen = data[1] as usize;

        let flags = AddAddrFlags::from_bits_truncate(data[Self::FLAGS_OFFSET]);
        let addr_id = data[Self::ADDR_ID_OFFSET];
        let mut addrlen = optlen - 4;
        if flags.contains(AddAddrFlags::E) {
            addrlen -= 8; // Remove truncated HMAC
        }
        addrlen -= addrlen % 4; // Remove optional port


        let addr = match addrlen {
            4 => IpAddr::V4(Ipv4Addr::new(data[Self::FLAGS_OFFSET], data[Self::FLAGS_OFFSET + 1], data[Self::FLAGS_OFFSET + 2], data[Self::FLAGS_OFFSET + 3])),
            16 => {
                let segments: [u16; 8] = array::from_fn(|i| u16::from_be_bytes(utils::to_array(data, Self::ADDR_OFFSET + 2 * i).unwrap()));
                IpAddr::V6(Ipv6Addr::new(segments[0], segments[1], segments[2], segments[3], segments[4], segments[5], segments[6], segments[7]))
            }
            _ => panic!(),
        };

        let mut idx = Self::ADDR_OFFSET + addrlen;
        let port = if optlen % 4 == 0 {
            None
        } else {
            let port = u16::from_be_bytes(utils::to_array(data, idx).unwrap());
            idx += 2;
            Some(port)
        };

        let hmac = if flags.contains(AddAddrFlags::E) {
            Some(utils::to_array(data, idx).unwrap())
        } else {
            None
        };

        Self {
            flags,
            addr_id,
            addr,
            port,
            hmac,
        }
    }

    pub fn byte_len(&self) -> usize {
        let mut len = 4;
        len += match self.addr {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 16,
        };

        if self.port.is_some() {
            len += 2;
        }

        if self.hmac.is_some() {
            len += 2;
        }

        len
    }

    #[inline]
    pub fn subtype(&self) -> u8 {
        MP_ADD_ADDR
    }

    #[inline]
    pub fn flags(&self) -> AddAddrFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: AddAddrFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn addr_id(&self) -> u8 {
        self.addr_id
    }

    #[inline]
    pub fn set_addr_id(&mut self, addr_id: u8) {
        self.addr_id = addr_id;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct RemoveAddrFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const R4 = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct RemoveAddrOpt {
    flags: RemoveAddrFlags,
    addr_ids: Buffer<u8, 37>,
}

impl RemoveAddrOpt {
    const FLAGS_OFFSET: usize = 2;
    const ADDR_IDS_OFFSET: usize = 3;

    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&[(self.subtype() << 4) | self.flags().bits()])?;
        writer.write(self.addr_ids.as_slice())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let flags = RemoveAddrFlags::from_bits_truncate(data[Self::FLAGS_OFFSET]);
        let mut addr_ids = Buffer::new();
        addr_ids.append(&data[Self::ADDR_IDS_OFFSET..]);

        Self {
            flags,
            addr_ids,
        }
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        3 + self.addr_ids.len()
    }

    pub fn subtype(&self) -> u8 {
        MP_REMOVE_ADDR
    }

    #[inline]
    pub fn flags(&self) -> RemoveAddrFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: RemoveAddrFlags) {
        self.flags = flags;
    }
}

#[derive(Clone, Debug)]
pub struct FallbackOpt {
    reserved: u16,
    dsn: u64,
}

impl FallbackOpt {
    const RESERVED_OFFSET: usize = 2;
    const DSN_OFFSET: usize = 4;

    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&(self.subtype() as u16 | self.reserved).to_be_bytes())?;
        writer.write(&self.dsn.to_be_bytes())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let reserved = u16::from_be_bytes(utils::to_array(data, Self::RESERVED_OFFSET).unwrap());
        let dsn = u64::from_be_bytes(utils::to_array(data, Self::DSN_OFFSET).unwrap());

        Self {
            reserved,
            dsn,
        }
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        12
    }

    #[inline]
    pub fn subtype(&self) -> u8 {
        MP_FAIL
    }

    #[inline]
    pub fn reserved(&self) -> u16 {
        self.reserved
    }

    #[inline]
    pub fn set_reserved(&mut self, reserved: u16) {
        self.reserved = reserved;
    }

    #[inline]
    pub fn dsn(&self) -> u64 {
        self.dsn
    }

    #[inline]
    pub fn set_dsn(&mut self, dsn: u64) {
        self.dsn = dsn;
    }
}

#[derive(Clone, Debug)]
pub struct FastCloseOpt {
    reserved: u16, // last 12 bits are reserved
    receiver_key: u64,
}

impl FastCloseOpt {
    const RESERVED_OFFSET: usize = 2;
    const RECEIVER_KEY_OFFSET: usize = 4;

    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&(self.subtype() as u16 | self.reserved).to_be_bytes())?;
        writer.write(&self.receiver_key.to_be_bytes())
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let reserved = u16::from_be_bytes(utils::to_array(data, Self::RESERVED_OFFSET).unwrap());
        let receiver_key = u64::from_be_bytes(utils::to_array(data, Self::RECEIVER_KEY_OFFSET).unwrap());

        Self {
            reserved,
            receiver_key,
        }
    }

    #[inline]
    pub fn byte_len(&self) -> usize {
        12
    }

    pub fn subtype(&self) -> u8 {
        MP_FASTCLOSE
    }

    #[inline]
    pub fn reserved(&self) -> u16 {
        self.reserved
    }

    #[inline]
    pub fn receiver_key(&self) -> u64 {
        self.receiver_key
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct ResetFlags: u8 {
        const U = 0b_0000_1000;
        const V = 0b_0000_0100;
        const W = 0b_0000_0010;
        const T = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct ResetOpt {
    flags: ResetFlags,
    reason: u8,
}

impl ResetOpt {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&[self.subtype() | self.flags.bits()])?;
        writer.write(&[self.flags.bits()])
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        let flags = ResetFlags::from_bits_truncate(data[2]);
        let reason = data[3];

        Self {
            flags,
            reason,
        }
    }

    pub fn byte_len(&self) -> usize {
        4
    }

    pub fn subtype(&self) -> u8 {
        MP_TCPRST
    }

    #[inline]
    pub fn flags(&self) -> ResetFlags {
        self.flags
    }

    #[inline]
    pub fn set_flags(&mut self, flags: ResetFlags) {
        self.flags = flags;
    }

    #[inline]
    pub fn reason(&self) -> u8 {
        self.reason
    }

    #[inline]
    pub fn set_reason(&mut self, reason: u8) {
        self.reason = reason;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct PrioFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const B = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct PrioOpt {
    flags: PrioFlags,
}

impl PrioOpt {
    pub fn to_bytes_extended(&self, writable: &mut impl IndexedWritable) -> Result<(), SerializationError> {
        let mut writer = PacketWriter::new::<Tcp>(writable);
        writer.write(&[TCP_OPT_KIND_MPTCP, self.byte_len() as u8])?;
        writer.write(&[self.subtype() | self.flags.bits()])
    }

    pub fn from_bytes_unchecked(data: &[u8]) -> Self {
        Self {
            flags: PrioFlags::from_bits_truncate(data[2]),
        }       
    }

    pub fn byte_len(&self) -> usize {
        3
    }

    pub fn subtype(&self) -> u8 {
        MP_PRIO
    }

    pub fn flags(&self) -> PrioFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: PrioFlags) {
        self.flags = flags;
    }
}
