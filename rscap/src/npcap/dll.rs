// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#[cfg(feature = "npcap-runtime")]
mod dlopen;
#[cfg(not(feature = "npcap-runtime"))]
mod link;

#[cfg(feature = "npcap-runtime")]
pub use dlopen::Npcap;
#[cfg(not(feature = "npcap-runtime"))]
pub use link::Npcap;

use windows_sys::Win32::Foundation::{BOOLEAN, HANDLE};
use windows_sys::Win32::Networking::WinSock::SOCKADDR_STORAGE;
use windows_sys::Win32::System::Threading::CRITICAL_SECTION;
use windows_sys::Win32::System::IO::OVERLAPPED;

use std::mem;

use crate::filter::BpfInstruction;

pub const PACKET_MODE_CAPT: libc::c_int = 0x00;
pub const PACKET_MODE_STAT: libc::c_int = 0x01;
pub const PACKET_MODE_MON: libc::c_int = 0x02;
pub const PACKET_MODE_DUMP: libc::c_int = 0x10;
pub const PACKET_MODE_STAT_DUMP: libc::c_int = PACKET_MODE_DUMP | PACKET_MODE_STAT;

pub const PACKET_ALIGNMENT: usize = mem::size_of::<libc::c_int>();
pub const fn packet_wordalign(x: usize) -> usize {
    (x + (PACKET_ALIGNMENT - 1)) & !(PACKET_ALIGNMENT - 1)
}

pub const NDIS_MEDIUM_NULL: i32 = -1;
pub const NDIS_MEDIUM_CHDLC: i32 = -2;
pub const NDIS_MEDIUM_PPP_SERIAL: i32 = -3;
pub const NDIS_MEDIUM_BARE_802_11: i32 = -4;
pub const NDIS_MEDIUM_RADIO_802_11: i32 = -5;
pub const NDIS_MEDIUM_PPI: i32 = -6;

pub const NPF_DISABLE_LOOPBACK: i32 = 1;
pub const NPF_ENABLE_LOOPBACK: i32 = 2;

pub const TIMESTAMPMODE_SINGLE_SYNCHRONIZATION: i32 = 0;
pub const TIMESTAMPMODE_QUERYSYSTEMTIME: i32 = 2;
pub const TIMESTAMPMODE_QUERYSYSTEMTIME_PRECISE: i32 = 4;

// pub const DOSNAMEPREFIX: TEXT = TEXT("Packet_");
pub const MAX_LINK_NAME_LENGTH: usize = 64;
pub const NMAX_PACKET: usize = 65535;

pub const ADAPTER_NAME_LENGTH: usize = 256 + 12;
pub const ADAPTER_DESC_LENGTH: usize = 128;
pub const MAX_MAC_ADDR_LENGTH: usize = 8;
pub const MAX_NETWORK_ADDRESSES: usize = 16;

pub const INFO_FLAG_NDIS_ADAPTER: libc::c_int = 0;
pub const INFO_FLAG_NDISWAN_ADAPTER: libc::c_int = 1;
pub const INFO_FLAG_DAG_CARD: libc::c_int = 2;
pub const INFO_FLAG_DAG_FILE: libc::c_int = 6;
pub const INFO_FLAG_DONT_EXPORT: libc::c_int = 8;
pub const INFO_FLAG_AIRPCAP_CARD: libc::c_int = 1;
pub const INFO_FLAG_NPFIM_DEVICE: libc::c_int = 3;
pub const INFO_FLAG_MASK_NOT_NPF: libc::c_int = 0;
pub const INFO_FLAG_NPCAP_LOOPBACK: libc::c_int = 0;
pub const INFO_FLAG_NPCAP_DOT11: libc::c_int = 0;

#[repr(C)]
pub struct NetType {
    pub link_type: libc::c_uint,
    pub link_speed: libc::c_ulonglong,
}

#[repr(C)]
pub struct BpfStat {
    pub bs_recv: libc::c_uint,
    pub bs_drop: libc::c_uint,
    pub ps_ifdrop: libc::c_uint,
    pub bs_capt: libc::c_uint,
}

#[repr(C)]
pub struct BpfHdr {
    pub bh_tstamp: libc::timeval,
    pub bh_caplen: libc::c_uint,
    pub bh_datalen: libc::c_uint,
    pub bh_hdrlen: libc::c_ushort,
}

#[repr(C)]
pub struct DumpBpfHdr {
    pub ts: libc::timeval,
    pub caplen: libc::c_uint,
    pub len: libc::c_uint,
}

#[repr(C)]
pub struct NpfIfAddr {
    pub ip_address: SOCKADDR_STORAGE,
    pub subnet_mask: SOCKADDR_STORAGE,
    pub broadcast: SOCKADDR_STORAGE,
}

#[repr(C)]
pub struct Adapter {
    pub h_file: HANDLE,
    pub symbolic_link: [libc::c_char; MAX_LINK_NAME_LENGTH],
    pub num_writes: libc::c_int,
    pub read_event: HANDLE,
    pub read_timeout: libc::c_uint,
    pub name: [libc::c_char; ADAPTER_NAME_LENGTH],
    pub wan_adapter: *mut WanAdapter, // PWAN_ADAPTER
    pub flags: libc::c_uint,
}

#[repr(C)]
pub struct Packet {
    pub h_event: HANDLE,
    pub overlapped: OVERLAPPED,
    pub buffer: *mut libc::c_void,
    pub length: libc::c_uint,
    pub ul_bytes_received: libc::c_ulong, // DWORD
    pub bio_complete: BOOLEAN,
}

#[repr(C)]
pub struct PacketOidData {
    pub oid: libc::c_ulong,
    pub length: libc::c_ulong,
    pub data: [libc::c_uchar; 1], // TODO: is this correct?
}

// Taken from WanPacket.cpp
#[repr(C)]
pub struct WanAdapter {
    pub h_capture_blob: *const libc::c_void, // HBLOB
    pub critical_section: CRITICAL_SECTION,
    pub buffer: *mut libc::c_uchar,  // PUCHAR
    pub c: libc::c_ulong,            // DWORD
    pub p: libc::c_ulong,            // DWORD
    pub free: libc::c_ulong,         // DWORD
    pub size: libc::c_ulong,         // DWORD
    pub dropped: libc::c_ulong,      // DWORD
    pub accepted: libc::c_ulong,     // DWORD
    pub received: libc::c_ulong,     // DWORD
    pub min_to_copy: libc::c_ulong,  // DWORD
    pub read_timeout: libc::c_ulong, // DWORD
    pub h_read_event: libc::c_ulong, // DWORD
    pub filter_code: *mut BpfInstruction,
    pub mode: libc::c_ulong, // DWORD
    pub nbytes: i64,         // LARGE_INTEGER,
    pub npackets: i64,       // LARGE_INTEGER,
    // ifdef have buggy tme support
    // mem_ex: MEM_TYPE,
    // tme: TME_CORE,
    // endif
    pub p_irtc: *mut libc::c_void, // C++ derived class/struct IRTC; we use a void* instead
}
