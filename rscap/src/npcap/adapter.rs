// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::ptr::{self, NonNull};

use once_cell::sync::OnceCell;

use windows_sys::Win32::Foundation::{ERROR_BAD_UNIT, ERROR_INVALID_NAME, HANDLE};
use windows_sys::Win32::Networking::WinSock::{WSACleanup, WSAStartup, WSADATA};
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

use crate::filter::{PacketFilter, PacketStatistics};
use crate::Interface;

use super::dll::{Adapter, BpfStat, Npcap, Packet};
use super::NpcapTimeout;

const WSA_VERSION: u16 = 0x0202;

static NPCAP_API: OnceCell<Npcap> = OnceCell::new();

/// A network adapter capable of sniffing and injecting packets over an interface.
pub struct NpcapAdapter {
    adapter: NonNull<Adapter>,
    iface: Interface,
    nonblocking: bool,
    npcap: &'static Npcap,
    packet: NonNull<Packet>,
}

impl NpcapAdapter {
    pub const DEFAULT_DRIVER_BUFFER: usize = 1024 * 1024 * 1024; // Default buffer of 1MB (similar to libpcap)

    /// Retrieves the name of the npcap driver.
    ///
    /// As Winpcap uses a very similar API to npcap, this function is useful in disambiguating
    /// the one from the other.
    #[inline]
    pub fn driver_name(&self) -> &CStr {
        self.npcap.driver_name()
    }

    /// Retrieves the version of the npcap driver.
    #[inline]
    pub fn driver_version(&self) -> &CStr {
        self.npcap.driver_version()
    }

    /// Retrieves the interface the npcap driver is listening on.
    #[inline]
    pub fn interface(&self) -> Interface {
        self.iface
    }

    /// Indicates whether monitor mode is enabled for the associated network interface.
    pub fn monitor_mode(iface: Interface) -> io::Result<bool> {
        let npcap = NPCAP_API.get_or_try_init(Npcap::new)?;

        match npcap.get_monitor_mode(iface.name_cstr()) {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Enables or disables monitor mode for the adapter.
    ///
    /// # Errors
    ///
    /// On failure, the following error kinds may be returned:
    /// - [`io::ErrorKind::Unsupported`] - monitor mode is unsupported for the device currrently
    ///   being captured from.
    pub fn set_monitor_mode(iface: Interface, enabled: bool) -> io::Result<()> {
        let npcap = NPCAP_API.get_or_try_init(Npcap::new)?;

        let enabled = match enabled {
            true => 1,
            false => 0,
        };

        match npcap.set_monitor_mode(iface.name_cstr(), enabled) {
            1 => Ok(()),
            0 => Err(io::ErrorKind::Unsupported.into()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Returns a new Npcap adapter listening on the specified interface.
    ///
    /// The interface name must begin with "\Device\" or "NPF_" to be considered valid.
    ///
    /// # Errors
    ///
    /// On failure, the following error kinds may be returned:
    /// - [`io::ErrorKind::NotFound`] - the specified interface could not be found on the system
    /// - [io::ErrorKind::InvalidInput`] - the specified interface had an invalid format
    /// - [`io::ErrorKind::OutOfMemory`] - the driver could not allocate the necessary buffers to
    ///   create a new Npcap adapter.
    ///
    /// The above are common errors a developer may want to specifically handle, but they are in
    /// no way a comprehensive list. In addition to the above, this method may return errors
    /// originating from any of the following Windows library functions:
    /// - `WSAStartup`
    /// - `GetProcAddress` (if compiled with the `npcap-runtime` feature set)
    /// - `CreateFileA`
    /// - `SetNamedPipeHandleState`
    /// - `WriteFile`
    /// - `ReadFile`
    /// - `CreateEvent`
    /// - `DeviceIoControl`
    ///
    pub fn new(iface: Interface) -> io::Result<Self> {
        let npcap = NPCAP_API.get_or_try_init(Npcap::new)?;

        let packet_ptr = npcap.allocate_packet();
        let packet = match NonNull::new(packet_ptr) {
            None => return Err(io::ErrorKind::OutOfMemory.into()),
            Some(p) => p,
        };

        let mut wsa_data: MaybeUninit<WSADATA> = MaybeUninit::uninit();

        unsafe {
            match WSAStartup(WSA_VERSION, ptr::addr_of_mut!(wsa_data) as *mut WSADATA) {
                0 => (),
                e => return Err(io::Error::from_raw_os_error(e)),
            }
        }

        // TODO: should we append "\Device\" or "NPF_" to the interface name?
        // TODO: when should we append "WIFI_"? (for AirNpcap)

        let adapter = match NonNull::new(npcap.open_adapter(iface.name_cstr())) {
            None => {
                let error = io::Error::last_os_error();
                return Err(match error.raw_os_error().map(|e| e as u32) {
                    Some(ERROR_BAD_UNIT) => io::ErrorKind::NotFound.into(),
                    Some(ERROR_INVALID_NAME) => io::ErrorKind::InvalidInput.into(),
                    _ => error,
                });
            }
            Some(p) => p,
        };

        let mut socket = Self {
            adapter,
            iface,
            npcap,
            nonblocking: false,
            packet,
        };

        socket.set_driver_buffer(Self::DEFAULT_DRIVER_BUFFER)?;

        Ok(socket)
    }

    /// Sets `filter` as the packet filter for the adapter.
    ///
    /// # Errors
    ///
    /// On failure, one of the following error kinds may be returned:
    ///
    /// - [io::ErrorKind::InvalidInput] - `filter` was too short (e.g. 0 instructions), too long
    /// (> 4096 instructions) or invalid in some other way. The absence of this error _does not_
    /// guarantee that the filter has valid instructions, but it _may_ be present if the filter
    /// has invalid instructions.
    /// - [io::ErrorKind::OutOfMemory] - the operating system had insufficent memory to allocate
    /// the packet filter.
    /// - [io::ErrorKind::Other] - some other unexpected error occurred.
    pub fn set_filter(&mut self, filter: &mut PacketFilter) -> io::Result<()> {
        match unsafe {
            self.npcap
                .set_bpf(self.adapter.as_mut(), &filter.as_bpf_program())
        } {
            false => Err(io::Error::last_os_error()),
            true => Ok(()),
        }
    }

    /// Sets the filter to reject all packets and fushes any packets currently pending in the
    /// socket's buffer.
    ///
    /// This method should not need to be called during general active capture; Raw/Packet sockets
    /// internally use a ring buffer, so if more packets are received than the application can
    /// handle within a given time frame then oldsockets will be automatically flushed by the ring
    /// buffer. **However**, this method is very important when it comes to applying a new filter
    /// to an active socket or changing the `Interface`/protocol an active socket is bound to
    /// (see [`set_filter()`](Self::set_filter) for more details on this).
    ///
    /// # Errors
    ///
    /// This method only returns error originating from [`set_filter()`](Self::set_filter); refer
    /// to its documentation for the list of possible error kinds that can be returned.
    pub fn flush(&mut self) -> io::Result<()> {
        if let Err(e) = self.set_filter(&mut PacketFilter::reject_all()) {
            return Err(io::Error::new(io::ErrorKind::Other, e));
        }

        let mut tmp_buf = [0u8; 0];

        // Loop through messages until none left to be received
        loop {
            unsafe {
                let buf = NonNull::new_unchecked(tmp_buf.as_mut_ptr());
                self.npcap.init_packet(self.packet.as_mut(), buf, 0);

                // This is nonblocking by default
                match self
                    .npcap
                    .receive_packet(self.adapter.as_mut(), self.packet.as_mut())
                {
                    false => break, // TODO: check return value here
                    true => (),
                }
            }
        }

        Ok(())
    }

    /// Configures whether the adapter will perform [`send()`](Self::send)/[`recv()`](Self::recv)
    /// methods in a nonblocking manner.
    #[inline]
    pub fn set_nonblocking(&mut self, nonblocking: bool) {
        self.nonblocking = nonblocking;
    }

    /// Indicates whether the adapter will perform [`send()`](Self::send)/[`recv()`](Self::recv)
    /// methods in a nonblocking manner.
    #[inline]
    pub fn nonblocking(&self) -> bool {
        self.nonblocking
    }

    /// Retrieves statistical information on the number of packets the adapter has captured/dropped.
    pub fn packet_stats(&mut self) -> io::Result<PacketStatistics> {
        let mut stat = BpfStat {
            bs_recv: 0,
            bs_drop: 0,
            ps_ifdrop: 0,
            bs_capt: 0,
        };

        match self
            .npcap
            .get_stats_ex(unsafe { self.adapter.as_mut() }, &mut stat)
        {
            true => Ok(PacketStatistics {
                received: stat.bs_recv,
                dropped: stat.bs_drop,
            }),
            false => Err(io::Error::last_os_error()),
        }
    }

    /// Sets the size of the buffer used by the npcap driver to queue packets for the socket.
    pub fn set_driver_buffer(&mut self, buffer_size: usize) -> io::Result<()> {
        let buffer_size =
            libc::c_int::try_from(buffer_size).map_err(|_| io::ErrorKind::InvalidInput)?;
        match self
            .npcap
            .set_buff(unsafe { self.adapter.as_mut() }, buffer_size)
        {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }

    /// Defines the minimum amount of data npcap driver that will cause a `recv()` to return.
    pub fn set_min_to_copy(&mut self, copy_bytes: usize) -> io::Result<()> {
        let copy_bytes =
            libc::c_int::try_from(copy_bytes).map_err(|_| io::ErrorKind::InvalidInput)?;
        match self
            .npcap
            .set_min_to_copy(unsafe { self.adapter.as_mut() }, copy_bytes)
        {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }

    pub fn read_event_handle(&mut self) -> HANDLE {
        self.npcap.get_read_event(unsafe { self.adapter.as_mut() })
    }

    /// Receive a datagram from the socket.
    pub fn recv(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let buf = NonNull::new_unchecked(packet.as_mut_ptr());
            self.npcap
                .init_packet(self.packet.as_mut(), buf, packet.len());

            loop {
                match self
                    .npcap
                    .receive_packet(self.adapter.as_mut(), self.packet.as_mut())
                {
                    false if self.nonblocking => return Err(io::Error::last_os_error()),
                    false => (), // TODO: check error
                    true => return Ok(packet.len()),
                }

                let handle = self.read_event_handle();
                WaitForSingleObject(handle, INFINITE);
                // ^ TODO: handle errors from this
            }
        }
    }

    /// Configures the number of times a packet written to the interface via `send()` will b
    /// repeated.
    pub fn set_repeat_send(&mut self, num_repeats: u32) -> io::Result<()> {
        let num_repeats =
            libc::c_int::try_from(num_repeats).map_err(|_| io::ErrorKind::InvalidInput)?;

        match self
            .npcap
            .set_num_writes(unsafe { self.adapter.as_mut() }, num_repeats)
        {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }

    /// Sends a datagram over the socket. On success, returns the number of bytes written.
    pub fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        unsafe {
            // BUG: this casts a `*const u8` into a `*mut u8`.
            // Depending on how the resulting mut pointer is used, this could be unsound/UB.
            let buf = NonNull::new_unchecked(packet.as_ptr() as *mut u8);
            self.npcap
                .init_packet(self.packet.as_mut(), buf, packet.len());

            // BUG: this technically blocks regardless of blocking/nonblocking mode.
            // This is an issue in npcap that will require an API addition to resolve.
            match self
                .npcap
                .send_packet(self.adapter.as_mut(), self.packet.as_mut())
            {
                false => return Err(io::Error::last_os_error()),
                true => Ok(packet.len()),
            }
        }
    }

    /*
    /// Sets the capture mode of the interface.
    ///
    /// By default, the capture mode is set to `NpcapMode::Capture`.
    pub fn set_mode(&self, mode: NpcapMode) -> Result<(), NpcapError> {
        let mode_int = match mode {
            NpcapMode::Capture => PACKET_MODE_CAPT,
            NpcapMode::Statistic => PACKET_MODE_STAT,
        };

        match self.npcap.set_mode(self.adapter.as_ptr(), mode_int) {
            true => Ok(()),
            false => Err(NpcapError::new(NpcapErrorKind::UnsupportedMode, format!("failed to set npcap mode to {}", mode_int))),
        }
    }
    */

    /// Sets the value of the read timeout associated with the socket.
    ///
    /// `timeout` indicates how long the socket will wait to receive a packet before returning.
    pub fn set_timeout(&mut self, timeout: NpcapTimeout) -> io::Result<()> {
        let timeout = match timeout {
            NpcapTimeout::None => -1,
            NpcapTimeout::Immediate => 0,
            NpcapTimeout::Milliseconds(ms) => {
                libc::c_int::try_from(ms).map_err(|_| io::ErrorKind::InvalidInput)?
            }
        };

        match self
            .npcap
            .set_read_timeout(unsafe { self.adapter.as_mut() }, timeout)
        {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for NpcapAdapter {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}
