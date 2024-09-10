#![allow(non_snake_case)]

use std::ffi::CStr;
use std::ptr::NonNull;
use std::ptr;

use dlopen2::wrapper::{Container, WrapperApi};
use windows_sys::Win32::Foundation::{BOOL, BOOLEAN, HANDLE};

use super::{Adapter, BpfProgram, BpfStat, NetType, NpfIfAddr, Packet, PacketOidData};
use crate::npcap::{NpcapError, NpcapErrorKind};

// TODO: change this to `windows`

pub struct Npcap {
    container: Container<NpcapApi>,
}

// Note: PCCH is type `const char *`

#[derive(WrapperApi)]
struct NpcapApi {
    PacketGetDriverVersion: unsafe extern "C" fn() -> windows_sys::core::PCSTR,
    PacketGetDriverName: unsafe extern "C" fn() -> windows_sys::core::PCSTR,
    PacketSetMinToCopy: unsafe extern "C" fn(adapter: *mut Adapter, nbytes: libc::c_int) -> BOOLEAN,
    PacketSetNumWrites: unsafe extern "C" fn(adapter: *mut Adapter, nwrites: libc::c_int) -> BOOLEAN,
    PacketSetMode: unsafe extern "C" fn(adapter: *mut Adapter, mode: libc::c_int) -> BOOLEAN,
    PacketSetReadTimeout: unsafe extern "C" fn(adapter: *mut Adapter, timeout: libc::c_int) -> BOOLEAN,
    PacketSetBpf: unsafe extern "C" fn(adapter: *mut Adapter, fp: *const BpfProgram) -> BOOLEAN,
    PacketSetLoopbackBehavior: unsafe extern "C" fn(adapter: *mut Adapter, behavior: libc::c_uint) -> BOOLEAN,
    PacketSetTimestampMode: unsafe extern "C" fn(adapter: *mut Adapter, mode: libc::c_ulong) -> BOOLEAN,
    PacketGetTimestampModes: unsafe extern "C" fn(adapter: *mut Adapter, p_modes: *mut libc::c_ulong) -> BOOLEAN,
    PacketSetSnaplen: unsafe extern "C" fn(adapter: *mut Adapter, snaplen: libc::c_int) -> libc::c_int,
    PacketGetStats: unsafe extern "C" fn(adapter: *mut Adapter, stats: *mut BpfStat) -> BOOLEAN,
    PacketGetStatsEx: unsafe extern "C" fn(adapter: *mut Adapter, stats: *mut BpfStat) -> BOOLEAN,
    PacketSetBuff: unsafe extern "C" fn(adapter: *mut Adapter, dim: libc::c_int) -> BOOLEAN,
    PacketGetNetType: unsafe extern "C" fn(adapter: *mut Adapter, ty: *mut NetType) -> BOOLEAN,
    PacketIsLoopbackAdapter: unsafe extern "C" fn(adapter_name: *const libc::c_char) -> BOOLEAN,
    PacketIsMonitorModeSupported: unsafe extern "C" fn(adapter_name: *const libc::c_char) -> libc::c_int,
    PacketSetMonitorMode: unsafe extern "C" fn(adapter_name: *const libc::c_char, mode: libc::c_int) -> libc::c_int,
    PacketGetMonitorMode: unsafe extern "C" fn(adapter_name: *const libc::c_char) -> libc::c_int,
    PacketOpenAdapter: unsafe extern "C" fn(adapter_name: *const libc::c_char) -> *mut Adapter,
    PacketSendPacket: unsafe extern "C" fn(adapter: *mut Adapter, packet: *mut Packet, sync: BOOLEAN) -> BOOLEAN,
    PacketSendPackets: unsafe extern "C" fn(adapter: *mut Adapter, packet_buf: *mut libc::c_void, size: libc::c_ulong, sync: BOOLEAN) -> libc::c_int,
    PacketAllocatePacket: unsafe extern "C" fn() -> *mut Packet,
    PacketInitPacket: unsafe extern "C" fn(packet: *mut Packet, buffer: *mut libc::c_void, length: libc::c_uint),
    PacketFreePacket: unsafe extern "C" fn(packet: *mut Packet),
    PacketReceivePacket: unsafe extern "C" fn(adapter: *mut Adapter, packet: *mut Packet, sync: BOOLEAN) -> BOOLEAN,
    PacketSetHwFilter: unsafe extern "C" fn(adapter: *mut Adapter, filter: libc::c_ulong) -> BOOLEAN,
    PacketGetAdapterNames: unsafe extern "C" fn(buf: *mut libc::c_char, buf_size: *mut libc::c_ulong),
    PacketGetNetInfoEx: unsafe extern "C" fn(adapter: *mut Adapter, buffer: *mut NpfIfAddr, n_entries: *mut libc::c_long) -> BOOLEAN,
    PacketRequest: unsafe extern "C" fn(adapter: *mut Adapter, set: BOOLEAN, oid_data: *mut PacketOidData) -> BOOLEAN,
    PacketGetReadEvent: unsafe extern "C" fn(adapter: *mut Adapter) -> HANDLE,
    // PacketSetDumpName, PacketSetDumpLimits and PacketIsDumpEnded are deprecated
    PacketStopDriver: unsafe extern "C" fn() -> BOOL,
    PacketStopDriver60: unsafe extern "C" fn() -> BOOL,
    PacketCloseAdapter: unsafe extern "C" fn(adapter: *mut Adapter),
    // PacketStartOem and PacketStartOemEx are deprecated WinPcap Pro functions
    // We don't define PAirpcapHandle
    // PacketGetAirPcapHandle: fn(adapter: *mut Adapter) -> PAirpcapHandle,
}

impl Npcap {
    pub fn new() -> Result<Self, NpcapError> {
        unsafe {
            Ok(Self {
                container: Container::load("Packet.dll").map_err(|e| match e {
                    dlopen2::Error::NullCharacter(_) => unreachable!(),
                    dlopen2::Error::OpeningLibraryError(e) => NpcapError::new(NpcapErrorKind::DllNotFound, e),
                    dlopen2::Error::SymbolGettingError(e) => NpcapError::new(NpcapErrorKind::MissingDllSymbol, e),
                    dlopen2::Error::NullSymbol => NpcapError::new(NpcapErrorKind::MissingDllSymbol, "the value of a resolved dll symbol was null"),
                    dlopen2::Error::AddrNotMatchingDll(e) => NpcapError::new(NpcapErrorKind::DllNotFound, e),
                })?,
            })
        }
    }

    pub fn driver_version(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.container.PacketGetDriverVersion() as *const i8) }
    }

    pub fn driver_name(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.container.PacketGetDriverName() as *const i8) }
    }

    pub fn set_min_to_copy(&self, adapter: &mut Adapter, nbytes: libc::c_int) -> bool {
        match unsafe { self.container.PacketSetMinToCopy(adapter, nbytes) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_num_writes(&self, adapter: &mut Adapter, nwrites: libc::c_int) -> bool {
        match unsafe { self.container.PacketSetNumWrites(adapter, nwrites) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_mode(&self, adapter: &mut Adapter, mode: libc::c_int) -> bool {
        match unsafe { self.container.PacketSetMode(adapter, mode) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_read_timeout(&self, adapter: &mut Adapter, timeout: libc::c_int) -> bool {
        match unsafe { self.container.PacketSetReadTimeout(adapter, timeout) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_bpf(&self, adapter: &mut Adapter, program: &BpfProgram) -> bool {
        match unsafe { self.container.PacketSetBpf(adapter, ptr::from_ref(program)) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_loopback_behavior(&self, adapter: &mut Adapter, behavior: libc::c_uint) -> bool {
        match unsafe { self.container.PacketSetLoopbackBehavior(adapter, behavior) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_timestamp_mode(&self, adapter: &mut Adapter, mode: libc::c_ulong) -> bool {
        match unsafe { self.container.PacketSetTimestampMode(adapter, mode) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_timestamp_modes(&self, adapter: &mut Adapter, modes: *mut libc::c_ulong) -> bool {
        match unsafe { self.container.PacketGetTimestampModes(adapter, modes) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_snaplen(&self, adapter: &mut Adapter, snaplen: libc::c_int) -> bool {
        match unsafe { self.container.PacketSetSnaplen(adapter, snaplen) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_stats(&self, adapter: &mut Adapter, stats: &mut BpfStat) -> bool {
        match unsafe { self.container.PacketGetStats(adapter, ptr::from_mut(stats)) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_stats_ex(&self, adapter: &mut Adapter, stats: &mut BpfStat) -> bool {
        match unsafe { self.container.PacketGetStatsEx(adapter, ptr::from_mut(stats)) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_buff(&self, adapter: &mut Adapter, dim: libc::c_int) -> bool {
        match unsafe { self.container.PacketSetBuff(adapter, dim) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_net_type(&self, adapter: &mut Adapter, ty: &mut NetType) -> bool {
        match unsafe { self.container.PacketGetNetType(adapter, ptr::from_mut(ty)) } {
            0 => false,
            _ => true,
        }
    }

    pub fn is_loopback_adapter(&self, adapter_name: &CStr) -> bool {
        match unsafe { self.container.PacketIsLoopbackAdapter(adapter_name.as_ptr()) } {
            0 => false,
            _ => true,
        }
    }

    pub fn is_monitor_mode_supported(&self, adapter_name: &CStr) -> libc::c_int {
        unsafe {
            self.container.PacketIsMonitorModeSupported(adapter_name.as_ptr())
        }
    }

    pub fn set_monitor_mode(&self, adapter_name: &CStr, mode: libc::c_int) -> libc::c_int {
        unsafe {
            self.container.PacketSetMonitorMode(adapter_name.as_ptr(), mode)
        }
    }

    pub fn get_monitor_mode(&self, adapter_name: &CStr) -> libc::c_int {
        unsafe {
            self.container.PacketGetMonitorMode(adapter_name.as_ptr())
        }
    }

    pub fn open_adapter(&self, adapter_name: &CStr) -> *mut Adapter {
        unsafe {
            self.container.PacketOpenAdapter(adapter_name.as_ptr())
        }
    }

    pub fn send_packet(&self, adapter: &mut Adapter, packet: &mut Packet) -> bool {
        match unsafe { self.container.PacketSendPacket(adapter, ptr::from_mut(packet), 1) } {
            0 => false,
            _ => true,
        }
    }

    pub fn send_packets(&self, adapter: &mut Adapter, packets: &mut [Packet]) -> libc::c_int {
        let packets_ptr = packets.as_mut_ptr() as *mut libc::c_void;
        let packets_len = packets.len() as u64;

        // TODO: does this set the correct length?
        unsafe {
            self.container.PacketSendPackets(adapter, packets_ptr, packets_len, 1)
        }
    }

    pub fn allocate_packet(&self) -> *mut Packet {
        unsafe {
            self.container.PacketAllocatePacket()
        }
    }

    pub fn init_packet(&self, packet: &mut Packet, buffer: NonNull<u8>, buflen: usize) {
        let buffer_ptr = buffer.as_ptr() as *mut libc::c_void;
        let buffer_len = buflen as libc::c_uint;

        unsafe {
            self.container.PacketInitPacket(packet, buffer_ptr, buffer_len)
        }
    }

    pub fn free_packet(&self, packet: &mut Packet) {
        unsafe {
            self.container.PacketFreePacket(packet)
        }
    }

    pub fn receive_packet(&self, adapter: &mut Adapter, packet: &mut Packet) -> bool {
        match unsafe { self.container.PacketReceivePacket(adapter, ptr::from_mut(packet), 1) } {
            0 => false,
            _ => true,
        }
    }

    pub fn set_hw_filter(&self, adapter: &mut Adapter, filter: libc::c_ulong) -> bool {
        match unsafe { self.container.PacketSetHwFilter(adapter, filter) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_adapter_names(&self, buf: &mut [u8], len: &mut libc::c_ulong) {
        let buf_ptr = buf.as_mut_ptr() as *mut libc::c_char;
        let buflen_ptr = ptr::from_mut(len);

        unsafe {
            self.container.PacketGetAdapterNames(buf_ptr, buflen_ptr)
        }
    }

    pub fn get_net_info_ex(&self, adapter: &mut Adapter, addrs: &mut [NpfIfAddr], entries: &mut libc::c_long) -> bool {
        let addrs_ptr = addrs.as_mut_ptr();
        let entries_ptr = ptr::from_mut(entries);

        match unsafe { self.container.PacketGetNetInfoEx(adapter, addrs_ptr, entries_ptr) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_request(&self, adapter: &mut Adapter, set: bool, oid_data: &mut PacketOidData) -> bool {
        let set = match set {
            true => 1,
            false => 0,
        };

        match unsafe { self.container.PacketRequest(adapter, set, oid_data) } {
            0 => false,
            _ => true,
        }
    }

    pub fn get_read_event(&self, adapter: &mut Adapter) -> HANDLE {
        unsafe {
            self.container.PacketGetReadEvent(adapter)
        }
    }

    pub fn stop_driver(&self) -> bool {
        match unsafe { self.container.PacketStopDriver() } {
            0 => false,
            _ => true,
        }
    }

    pub fn stop_driver_60(&self) -> bool {
        match unsafe { self.container.PacketStopDriver60() } {
            0 => false,
            _ => true,
        }
    }

    pub unsafe fn close_adapter(&self, adapter: *mut Adapter) {
        self.container.PacketCloseAdapter(adapter)
    }
}


