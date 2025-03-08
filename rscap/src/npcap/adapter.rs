// SPDX-License-Identifier: MIT OR Apache-2.0
//
// Copyright (c) 2024 Nathaniel Bennett <me[at]nathanielbennett[dotcom]>
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use once_cell::sync::OnceCell;

use windows_sys::Win32::Foundation::{ERROR_BAD_UNIT, ERROR_INVALID_NAME, HANDLE};
use windows_sys::Win32::Networking::WinSock::{WSACleanup, WSAStartup, WSADATA};
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

use std::cell::UnsafeCell;
use std::ffi::CStr;
use std::mem::MaybeUninit;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::{cmp, io, mem, ptr};

use crate::filter::{PacketFilter, PacketStatistics};
use crate::Interface;

use super::dll::{packet_wordalign, Adapter, BpfHdr, BpfStat, Npcap, Packet};
use super::NpcapTimeout;

const WSA_VERSION: u16 = 0x0202;

static NPCAP_API: OnceCell<Npcap> = OnceCell::new();

pub struct PacketContext {
    packet: NonNull<Packet>,
    pktbuf: UnsafeCell<Vec<u8>>,
    pkt_indices: UnsafeCell<Vec<usize>>,
    ticket_info: AtomicU64, // <next_ticket> (32 bits) | <ticket_range> (32 bits)
    outstanding: AtomicUsize, // "E"
}

/// A network adapter capable of sniffing and injecting packets over an interface.
pub struct NpcapAdapter {
    npcap: &'static Npcap,
    adapter: NonNull<Adapter>,
    iface: Interface,
    nonblocking: AtomicBool,
    pkt_ctx: PacketContext,
}

impl NpcapAdapter {
    pub const DEFAULT_DRIVER_BUFFER: usize = 1024 * 1024; // Default buffer of 1MB (similar to libpcap)
    const DEFAULT_PACKET_CAPACITY: usize = 262144;

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

        let packet = match unsafe { npcap.allocate_packet() } {
            None => return Err(io::ErrorKind::OutOfMemory.into()),
            Some(p) => p,
        };

        let mut pktbuf: Vec<u8> = Vec::with_capacity(Self::DEFAULT_PACKET_CAPACITY);
        let pktbuf_ptr = NonNull::new(pktbuf.as_mut_ptr()).unwrap();

        // Safety: `init_packet()` is called within a context where exclusive access is guaranteed.
        unsafe {
            npcap.init_packet(packet, pktbuf_ptr, Self::DEFAULT_PACKET_CAPACITY);
        }

        let mut wsa_data: MaybeUninit<WSADATA> = MaybeUninit::uninit();

        unsafe {
            match WSAStartup(WSA_VERSION, ptr::addr_of_mut!(wsa_data) as *mut WSADATA) {
                0 => (),
                e => return Err(io::Error::from_raw_os_error(e)),
            }
        }

        // TODO: should we append "\Device\" or "NPF_" to the interface name?
        // TODO: when should we append "WIFI_"? (for AirNpcap)

        let adapter = match unsafe { npcap.open_adapter(iface.name_cstr()) } {
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

        let socket = Self {
            adapter,
            iface,
            npcap,
            nonblocking: AtomicBool::new(false),
            pkt_ctx: PacketContext {
                packet,
                pktbuf: UnsafeCell::new(pktbuf),
                pkt_indices: UnsafeCell::new(Vec::new()),
                ticket_info: AtomicU64::new(0),
                outstanding: AtomicUsize::new(0),
            },
        };

        socket.set_driver_buffer(Self::DEFAULT_DRIVER_BUFFER)?;

        Ok(socket)
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

        match unsafe { npcap.set_monitor_mode(iface.name_cstr(), enabled) } {
            1 => Ok(()),
            0 => Err(io::ErrorKind::Unsupported.into()),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Retrieves the name of the npcap driver.
    ///
    /// As Winpcap uses a very similar API to npcap, this function is useful in disambiguating
    /// the one from the other.
    #[inline]
    pub fn driver_name(&self) -> &CStr {
        unsafe { self.npcap.driver_name() }
    }

    /// Retrieves the version of the npcap driver.
    #[inline]
    pub fn driver_version(&self) -> &CStr {
        unsafe { self.npcap.driver_version() }
    }

    /// Retrieves the interface the npcap driver is listening on.
    #[inline]
    pub fn interface(&self) -> Interface {
        self.iface
    }

    /// Indicates whether monitor mode is enabled for the associated network interface.
    pub fn monitor_mode(iface: Interface) -> io::Result<bool> {
        let npcap = NPCAP_API.get_or_try_init(Npcap::new)?;

        match unsafe { npcap.get_monitor_mode(iface.name_cstr()) } {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
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
    pub fn set_filter(&self, filter: &mut PacketFilter) -> io::Result<()> {
        match unsafe { self.npcap.set_bpf(self.adapter, &filter.as_bpf_program()) } {
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

        // Invalidate all packets currently in the ringbuffer
        self.pkt_ctx.ticket_info.store(0, Ordering::Release);
        self.pkt_ctx.outstanding.store(0, Ordering::Release);

        // Loop through messages until none left to be received
        loop {
            // This is nonblocking by default
            match unsafe { self.npcap.receive_packet(self.adapter, self.pkt_ctx.packet) } {
                false => break, // TODO: check return value here
                true => (),
            }
        }

        Ok(())
    }

    /// Configures whether the adapter will perform [`send()`](Self::send)/[`recv()`](Self::recv)
    /// methods in a nonblocking manner.
    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblocking.store(nonblocking, Ordering::Relaxed);
    }

    /// Indicates whether the adapter will perform [`send()`](Self::send)/[`recv()`](Self::recv)
    /// methods in a nonblocking manner.
    #[inline]
    pub fn nonblocking(&self) -> bool {
        self.nonblocking.load(Ordering::Relaxed)
    }

    /// Retrieves statistical information on the number of packets the adapter has captured/dropped.
    pub fn packet_stats(&self) -> io::Result<PacketStatistics> {
        let mut stat = BpfStat {
            bs_recv: 0,
            bs_drop: 0,
            ps_ifdrop: 0,
            bs_capt: 0,
        };

        match unsafe { self.npcap.get_stats_ex(self.adapter, &mut stat) } {
            true => Ok(PacketStatistics {
                received: stat.bs_recv,
                dropped: stat.bs_drop,
            }),
            false => Err(io::Error::last_os_error()),
        }
    }

    /// Sets the size of the buffer used by the npcap driver to queue packets for the socket.
    pub fn set_driver_buffer(&self, buffer_size: usize) -> io::Result<()> {
        let buffer_size =
            libc::c_int::try_from(buffer_size).map_err(|_| io::ErrorKind::InvalidInput)?;
        match unsafe { self.npcap.set_buff(self.adapter, buffer_size) } {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }

    /// Defines the minimum amount of data npcap driver that will cause a `recv()` to return.
    pub fn set_min_to_copy(&self, copy_bytes: usize) -> io::Result<()> {
        let copy_bytes =
            libc::c_int::try_from(copy_bytes).map_err(|_| io::ErrorKind::InvalidInput)?;
        match unsafe { self.npcap.set_min_to_copy(self.adapter, copy_bytes) } {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }

    pub fn read_event_handle(&self) -> HANDLE {
        unsafe { self.npcap.get_read_event(self.adapter) }
    }

    /// Receive a datagram from the socket.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        // This method is implemented via a non-trivial number of concurrency operations.
        // It is advisable not to introduce or shuffle ANY code in this method unless you've
        // done thorough analysis of the potential concurrency issues that may arise.

        // This implementation is the way it is for three reasons:
        // 1. We want the `recv()` method to use `&self` so that it can be used in async contexts,
        //    but `npcap` fundamentally uses memory-mapped buffers as its underlying method of
        //    transport. Thus, we need a way of handling accesses/updates to the buffer in a
        //    thread-safe way.
        // 2. We can't use any synchronization primitives that block. Async runimes offer their
        //    own version of primitives that are safe to use, but using those would bind this
        //    function to a specific `async` backend.
        // 3. We'd ideally like multiple tasks to be able to read packets concurrently when more
        //    than one is in the receive buffer so that asynchronous `recv()` calls actually lead
        //    to performance improvement.
        //
        // Any proposed changes should adhere to these 3 features.

        // The ticket issuer and range of valid tickets are tightly bound to each other by being
        // saved in the same AtomicU64. This guarantees no ABA problem in checking if the ticket
        // is out of range.
        // `Acquire` Synchronizes all prior writes for `pkt_indices` and `pktbuf`
        let ticket_info = self
            .pkt_ctx
            .ticket_info
            .fetch_add(1 << 32, Ordering::Acquire);
        let mut ticket = (ticket_info >> 32) as usize; // first 32 bits
        let range = (ticket_info & 0xff_ff_ff_ff) as usize; // last 32 bits
        if ticket >= range {
            // No more packets are available in the mapped packet buffer--it must be refilled

            // Check to see if all outstanding tickets have completed for the current mapped buffer
            // TODO: is compare_exchange_weak allowed here?
            match self.pkt_ctx.outstanding.compare_exchange(
                0,
                usize::MAX,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => loop {
                    // This is to mitigate any kind of "what if the computer counts to 4 billion"
                    // issue. By immediately clearing the `range` field of ticket_info, we guarantee
                    // that no future bogus tickets are issued that appear valid due to overflow of
                    // the `ticket` field. Note that because `ticket` counts in increments of 1 << 32,
                    // an overflow after this has been called will look like the following:
                    // 0xffffffff00000000 + 0x0000000100000000 = 0x0000000000000000
                    // The length field is not affected by the wraparound, so the overflow ticket
                    // will still be correctly identified as out of range.
                    //
                    // With this mitigation in place, the only way an invalid ticket could be
                    // issued is if 2^32 (~4 billion) tickets are issued between the time the
                    // last valid ticket was issued and the time that task finished copying its
                    // packet into `buf` (and subsequently decrementing `outstanding`). The task
                    // holding the last ticket would have to be *incredibly*, persistently starved
                    // of execution cycles despite being ready to run for this to ever be remotely
                    // possible. Given that the tasks consuming tickets would be looping through
                    // polling for readiness on the socket each time they consumed a ticket, I find
                    // this case to be impossible enough to not be a worry. Someone may prove me
                    // wrong in this with a concrete counterexample; if so, I'll happily revise this
                    // code.
                    self.pkt_ctx.ticket_info.store(0, Ordering::Relaxed);

                    // SAFETY: `self.packet` internally points to `self.pkt_ctx.pktbuf`, and both
                    // are mutably accessed by `self.npcap.receive_packet`. Thus, `pktbuf` needs to
                    // be wrapped by an `UnsafeCell` so that immutability guarantees are opted out
                    // of (see the documentation to `UnsafeCell`). It is guaranteed that no other
                    // tasks will have `pktbuf` referenced at this point, as borrows only happen
                    // while `pkt_ctx.outstanding` > 0 or in this exclusive critical zone.
                    let res =
                        unsafe { self.npcap.receive_packet(self.adapter, self.pkt_ctx.packet) };
                    let err = io::Error::last_os_error();

                    match res {
                        false
                            if self.nonblocking.load(Ordering::Relaxed)
                                || err.kind() != io::ErrorKind::WouldBlock =>
                        {
                            self.pkt_ctx.outstanding.store(0, Ordering::Relaxed);
                            return Err(io::Error::last_os_error());
                        }
                        false => {
                            let handle = self.read_event_handle();
                            unsafe {
                                WaitForSingleObject(handle, INFINITE);
                            }
                            // ^ TODO: handle errors from WaitForSingleObject?
                        }
                        true => {
                            // This scope is necessary to clear `indices`, `pktbuf` references
                            let range = {
                                // SAFETY: this section can only be entered by one task at a time, and
                                // its data mutations are propogated by the subsequent `ticket_start`
                                // store operation that uses `Ordering::Release`. Other tasks are
                                // guaranteed not to be accessing `pkt_indices` or `pktbuf` while in this
                                // section.
                                let indices = unsafe { &mut *self.pkt_ctx.pkt_indices.get() };
                                let pktbuf = unsafe { &mut *self.pkt_ctx.pktbuf.get() };
                                indices.clear();

                                unsafe {
                                    // Adjust `pktbuf` so that it reflects the last received amount
                                    let buflen = (*self.pkt_ctx.packet.as_ptr()).ul_bytes_received;
                                    pktbuf.set_len(buflen as usize);
                                };

                                let mut rem_buf = pktbuf.as_slice();
                                let mut pktbuf_idx = 0;

                                while !rem_buf.is_empty() {
                                    // Parse packet indices one at a time

                                    let Some(hdr_data) = rem_buf.get(..mem::size_of::<BpfHdr>())
                                    else {
                                        // TODO: this is really an error
                                        break;
                                    };

                                    let (s1, bpf_hdr_slice, s2) =
                                        unsafe { hdr_data.align_to::<BpfHdr>() };
                                    debug_assert!(
                                        s1.is_empty() && bpf_hdr_slice.len() == 1 && s2.is_empty()
                                    );
                                    let bpf_hdr = &bpf_hdr_slice[0];

                                    debug_assert!(
                                        bpf_hdr.bh_hdrlen as usize == mem::size_of::<BpfHdr>()
                                    );
                                    if rem_buf.len()
                                        < bpf_hdr.bh_hdrlen as usize + bpf_hdr.bh_caplen as usize
                                    {
                                        // TODO: this is really an error
                                        break;
                                    }

                                    indices.push(pktbuf_idx);
                                    let next_pkt_start = packet_wordalign(
                                        bpf_hdr.bh_hdrlen as usize + bpf_hdr.bh_caplen as usize,
                                    );

                                    if rem_buf.len() < next_pkt_start {
                                        break; // Padding missing--last packet likely reached
                                    }

                                    rem_buf = &rem_buf[next_pkt_start..];
                                    pktbuf_idx += next_pkt_start;
                                }

                                // This task is assigned the first packet
                                ticket = 0;
                                indices.len()
                            };
                            assert!(range > 0);

                            // storing some value > 0 to outstanding => other tasks still won't be
                            // able to get into this critical section
                            self.pkt_ctx.outstanding.store(range, Ordering::Relaxed);

                            // Synchronize following reads/writes to `pkt_indices` and `pktbuf`
                            // Now other tasks can begin to read packets from the updated buffer
                            self.pkt_ctx
                                .ticket_info
                                .store((1u64 << 32) | (range as u64), Ordering::Release);

                            break;
                        }
                    }
                },
                Err(_) => return Err(io::ErrorKind::WouldBlock.into()),
            }
        }

        // This scope is necessary to clear `indices`, `pktbuf` references
        let written = {
            let indices = unsafe { &*self.pkt_ctx.pkt_indices.get() };
            let pktbuf = unsafe { &*self.pkt_ctx.pktbuf.get() };

            let pkt_index = indices[ticket];
            let pkt_data = &pktbuf[pkt_index..];

            // Invariant: pkt_data.len() > mem::size_of::<BpfHdr>()
            let (hdr_data, payload) = pkt_data.split_at(mem::size_of::<BpfHdr>());
            let (s1, bpf_hdr_slice, s2) = unsafe { hdr_data.align_to::<BpfHdr>() };
            debug_assert!(s1.is_empty() && bpf_hdr_slice.len() == 1 && s2.is_empty());
            let bpf_hdr = &bpf_hdr_slice[0];

            debug_assert!(bpf_hdr.bh_hdrlen as usize == mem::size_of::<BpfHdr>());
            let payload = &payload[..bpf_hdr.bh_caplen as usize];

            let written = cmp::min(buf.len(), payload.len());
            buf.copy_from_slice(&payload[..written]);
            written
        };

        self.pkt_ctx.outstanding.fetch_sub(1, Ordering::Relaxed);

        Ok(written)
    }

    /// Configures the number of times a packet written to the interface via `send()` will b
    /// repeated.
    pub fn set_repeat_send(&self, num_repeats: u32) -> io::Result<()> {
        let num_repeats =
            libc::c_int::try_from(num_repeats).map_err(|_| io::ErrorKind::InvalidInput)?;

        match unsafe { self.npcap.set_num_writes(self.adapter, num_repeats) } {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }

    /// Sends a datagram over the socket. On success, returns the number of bytes written.
    pub fn send(&self, buf: &[u8]) -> io::Result<usize> {
        let packet = match unsafe { self.npcap.allocate_packet() } {
            None => return Err(io::ErrorKind::OutOfMemory.into()),
            Some(p) => p,
        };

        // Safety: this casts a `*const u8` into a `*mut u8`. `npcap.init_packet()` uses this
        // buffer without modifying its contents, so this is sound; the C API simply neglects
        // to specify that the buffer pointer is const, so it requires a `*mut u8` as input.
        let data = unsafe { NonNull::new_unchecked(buf.as_ptr().cast_mut()) };
        // Safety: `init_packet()` is called within a `&mut self` context, so `self.packet` is
        // exclusively accessed at this point.
        unsafe {
            self.npcap.init_packet(packet, data, buf.len());
        }

        // Safety: `send_packet()` is thread-safe so long as `Packet`s are not shared.
        // BUG: this technically blocks regardless of blocking/nonblocking mode.
        // This is an issue in npcap that will require an API addition to resolve.
        let res = unsafe { self.npcap.send_packet(self.adapter, packet) };

        unsafe {
            self.npcap.free_packet(packet);
        }

        match res {
            false => return Err(io::Error::last_os_error()),
            true => Ok(buf.len()), // TODO: can truncation occur? Is it silent?
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
    pub fn set_timeout(&self, timeout: NpcapTimeout) -> io::Result<()> {
        let timeout = match timeout {
            NpcapTimeout::None => -1,
            NpcapTimeout::Immediate => 0,
            NpcapTimeout::Milliseconds(ms) => {
                libc::c_int::try_from(ms).map_err(|_| io::ErrorKind::InvalidInput)?
            }
        };

        // Safety: `self` guaranteed to be borrowed only once due to &mut, so `self.adapter` is
        // exclusively accessed here.
        match unsafe { self.npcap.set_read_timeout(self.adapter, timeout) } {
            true => Ok(()),
            false => Err(io::Error::last_os_error()),
        }
    }
}

unsafe impl Send for NpcapAdapter {}

unsafe impl Sync for NpcapAdapter {}

impl Drop for NpcapAdapter {
    fn drop(&mut self) {
        unsafe {
            WSACleanup();
        }
    }
}
