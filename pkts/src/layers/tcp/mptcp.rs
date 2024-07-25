use core::net::IpAddr;

use bitflags::bitflags;

use pkts_common::Buffer;

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
    data: Buffer<37>, // 1 byte each for type, length and subtype.
}

impl GenericOpt {
    pub fn byte_len(&self) -> usize {
        3 + self.data.len()
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MptcpFlags: u8 {
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
    flags: MptcpFlags,
    sender_key: Option<u64>,
    receiver_key: Option<u64>,
    data_len: Option<u16>,
    checksum: Option<u16>,
}

impl CapableOpt {
    pub fn subtype(&self) -> u8 {
        MP_CAPABLE
    }

    pub fn version(&self) -> u8 {
        1
    }

    pub fn byte_len(&self) -> usize {
        if self.sender_key.is_none() {
            4
        } else if self.receiver_key.is_none() {
            12
        } else if self.data_len.is_none() {
            20
        } else if self.checksum.is_none() {
            22
        } else {
            24
        }
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MptcpJoinFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const B = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct JoinOpt {
    flags: MptcpJoinFlags,
    addr_id: u8,
    payload: MptcpJoinPayload,
}

impl JoinOpt {
    pub fn byte_len(&self) -> usize {
        match &self.payload {
            MptcpJoinPayload::Syn(_) => 12,
            MptcpJoinPayload::SynAck(_) => 16,
            MptcpJoinPayload::Ack(_) => 24,
        }
    }

    pub fn subtype(&self) -> u8 {
        MP_JOIN
    }

    pub fn flags(&self) -> MptcpJoinFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: MptcpJoinFlags) {
        self.flags = flags;
    }

    pub fn addr_id(&self) -> u8 {
        self.addr_id
    }

    pub fn set_addr_id(&mut self, addr_id: u8) {
        self.addr_id = addr_id;
    }

    pub fn payload(&self) -> &MptcpJoinPayload {
        &self.payload
    }

    pub fn payload_mut(&mut self) -> &mut MptcpJoinPayload {
        &mut self.payload
    }
}

#[derive(Clone, Debug)]
pub enum MptcpJoinPayload {
    Syn(MptcpJoinSyn),
    SynAck(MptcpJoinSynAck),
    Ack(MptcpJoinAck),
}

#[derive(Clone, Debug)]
pub struct MptcpJoinSyn {
    receiver_token: u32,
    sender_rand: u32,
}

impl MptcpJoinSyn {
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
pub struct MptcpJoinSynAck {
    sender_hmac: [u8; 8],
    sender_rand: u32,
}

impl MptcpJoinSynAck {
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
pub struct MptcpJoinAck {
    sender_hmac: [u8; 20],
}

impl MptcpJoinAck {
    pub fn sender_hmac(&self) -> [u8; 20] {
        self.sender_hmac
    }

    pub fn set_sender_hmac(&mut self, trunc_hmac: [u8; 20]) {
        self.sender_hmac = trunc_hmac;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MptcpDssFlags: u16 {
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
    flags: MptcpDssFlags,
    ack: Option<u64>,
    dsn_info: Option<DsnInfo>,
}

impl DssOpt {
    pub fn byte_len(&self) -> usize {
        let mut len = 4;
        if self.ack.is_some() {
            len += if self.flags.contains(MptcpDssFlags::ACK_8_OCTETS) {
                8
            } else {
                4
            };
        }

        if let Some(info) = self.dsn_info {
            len += 6 + if self.flags.contains(MptcpDssFlags::DSN_8_OCTETS) {
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

    pub fn flags(&self) -> MptcpDssFlags {
        self.flags
    }

    pub fn ack(&self) -> Option<u64> {
        self.ack
    }

    pub fn set_ack(&mut self, ack: Option<u64>) {
        self.ack = ack;
        self.flags.set(MptcpDssFlags::ACK_PRESENT, ack.is_some());
    }

    pub fn set_data_fin(&mut self, data_fin: bool) {
        self.flags.set(MptcpDssFlags::DATA_FIN, data_fin);
    }

    pub fn set_ack_8_octets(&mut self, is_8_octets: bool) {
        self.flags.set(MptcpDssFlags::ACK_8_OCTETS, is_8_octets);
    }

    pub fn set_dsn_8_octets(&mut self, is_8_octets: bool) {
        self.flags.set(MptcpDssFlags::DSN_8_OCTETS, is_8_octets);
    }

    pub fn dsn(&self) -> Option<DsnInfo> {
        self.dsn_info
    }

    pub fn set_dsn(&mut self, dsn: Option<DsnInfo>) {
        self.dsn_info = dsn;
        self.flags.set(MptcpDssFlags::DSN_PRESENT, dsn.is_some());
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
    pub struct MptcpAddAddrFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const E = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct AddAddrOpt {
    flags: MptcpAddAddrFlags,
    addr_id: u8,
    addr: IpAddr,
    port: Option<u16>,
    hmac: Option<[u8; 8]>,
}

impl AddAddrOpt {
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
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MptcpRemoveAddrFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const R4 = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct RemoveAddrOpt {
    flags: MptcpRemoveAddrFlags,
    addr_ids: Buffer<37>,
}

impl RemoveAddrOpt {
    pub fn byte_len(&self) -> usize {
        3 + self.addr_ids.len()
    }
}

#[derive(Clone, Debug)]
pub struct FallbackOpt {
    reserved: u16,
    dsn: u64,
}

impl FallbackOpt {
    pub fn byte_len(&self) -> usize {
        12
    }
}

#[derive(Clone, Debug)]
pub struct FastCloseOpt {
    reserved: u16, // last 12 bits are reserved
    receiver_key: u64,
}

impl FastCloseOpt {
    pub fn byte_len(&self) -> usize {
        12
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MptcpResetFlags: u8 {
        const U = 0b_0000_1000;
        const V = 0b_0000_0100;
        const W = 0b_0000_0010;
        const T = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct ResetOpt {
    flags: MptcpResetFlags,
    reason: u8,
}

impl ResetOpt {
    pub fn byte_len(&self) -> usize {
        4
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug, Default)]
    pub struct MptcpPrioFlags: u8 {
        const R1 = 0b_0000_1000;
        const R2 = 0b_0000_0100;
        const R3 = 0b_0000_0010;
        const B = 0b_0000_0001;
    }
}

#[derive(Clone, Debug)]
pub struct PrioOpt {
    flags: MptcpPrioFlags,
}

impl PrioOpt {
    pub fn byte_len(&self) -> usize {
        3
    }

    pub fn subtype(&self) -> u8 {
        MP_PRIO
    }

    pub fn flags(&self) -> MptcpPrioFlags {
        self.flags
    }

    pub fn set_flags(&mut self, flags: MptcpPrioFlags) {
        self.flags = flags;
    }
}
