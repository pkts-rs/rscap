pub mod linux;

pub use pkts::*;


use std::{mem, ptr, net::SocketAddr};



// 3 types: Sniffer, Spoofer and Socket
// Sniffer is read-only, Spoofer is write-only, Socket is RW


#[repr(C)]
struct tpacket_req {
    tp_block_size: libc::c_int,
    tp_block_nr: libc::c_int,
    tp_frame_size: libc::c_int,
    tp_frame_nr: libc::c_int,
}

struct SockError {
//    reason: &'static str,
}

struct PacketMmapSocket<const PKT_SIZE: usize, const RING_SIZE: usize> {
    fd: i32,
    receive_buf: [*mut [u8; PKT_SIZE]; RING_SIZE], // TODO: change to MaybeUninit
    transmit_buf: [*mut [u8; PKT_SIZE]; RING_SIZE],
}

impl<const PKT_SIZE: usize, const RING_SIZE: usize> PacketMmapSocket<PKT_SIZE, RING_SIZE> {
    pub fn create(iface: &[u8]) -> Result<Self, SockError> {

        // protocol set to 0 initially so that our RX buffer doesn't fill
        let fd = match unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) } {
            -1 => return Err(SockError { }),
            fd => fd,
        };

        debug_assert!(PKT_SIZE <= (libc::c_int::MAX ^ (libc::c_int::MAX >> 1)) as usize);
        let tp_block_size = if PKT_SIZE.count_ones() == 1 {
            PKT_SIZE as libc::c_int // PKT_SIZE is a power of 2
        } else {
            ((PKT_SIZE << 1) ^ PKT_SIZE) as libc::c_int // Get next power of 2 larger than PKT_SIZE
        };

        debug_assert!(RING_SIZE <= libc::c_int::MAX as usize);

        let t_req = tpacket_req {
            tp_block_size,
            tp_block_nr: RING_SIZE as libc::c_int,
            tp_frame_size: PKT_SIZE as libc::c_int,
            tp_frame_nr: RING_SIZE as libc::c_int,
        };

//        let res = unsafe { libc::setsockopt(fd, libc::SOL_PACKET) };

        // map 



        /*
        Ok(PacketMmapSocket {
            fd,
            receive_buf: [[0; PKT_SIZE].as_mut_ptr(); RING_SIZE],
            transmit_buf: [[0; PKT_SIZE]; RING_SIZE],
        })
        */
        todo!()
    }
}




fn get_interfaces() {

}



fn getifaddrs() {

    // SAFETY: `getifaddrs` expects no fields to be set in its corresponding `ifaddrs` struct.
    let mut ifaddrs_ptr: *mut libc::ifaddrs = unsafe { mem::zeroed() };
    // SAFETY: `getifaddrs` expects a pointer to a pointer which it allocates with memory.
    // We provide that pointer and later free it.
    let res = unsafe { libc::getifaddrs(ptr::addr_of_mut!(ifaddrs_ptr)) };
    if res == -1 {
        todo!("return error here")
    }

    // SAFETY: ifaddrs_ptr is guaranteed to be allocated so long as getifaddrs did not return -1.
    let ifaddrs_ref =  unsafe { &*ifaddrs_ptr };



}



fn interfaces() -> Vec<String> {
    let ifaces = Vec::new();

    unsafe {
        let sock = match libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) {
            -1 => panic!("couldn't create socket"),
            s => s,
        };

        // Initialize buffer to all 0 values
        let mut ifreq_buf: [libc::ifreq; 128] = [libc::ifreq {
            ifr_ifru: libc::__c_anonymous_ifr_ifru {
                ifru_addr: libc::sockaddr {
                    sa_family: 0u16,
                    sa_data: [0i8; 14],
                }
            },
            ifr_name: [0i8; 16],
        }; 128];

        let ifconf = libc::ifconf {
            ifc_len: 128 * mem::size_of::<libc::ifreq>() as i32,
            ifc_ifcu: libc::__c_anonymous_ifc_ifcu {
                ifcu_buf: ifreq_buf.as_mut_ptr() as *mut i8,
            }
        };

        match libc::ioctl(sock, libc::SIOCGIFCONF, &ifconf) {
            0 => (),
            _ => panic!("SIOCGIFCONF ioctl() failed"),
        }

        let ifc_num = ifconf.ifc_len / mem::size_of::<libc::ifreq>() as i32;
        for ifreq in ifreq_buf.iter().take(ifc_num as usize) {
            //ifreq.ifr_ifru.ifru_addr
        }



    }

    ifaces
}

// Various platform-specific ways to get IPv4 + IPv6 interfaces:
// https://stackoverflow.com/questions/20743709/get-ipv6-addresses-in-linux-using-ioctl

// Linux:
// use glibc if_nametoindex, it uses netlink properly:
// https://github.com/bminor/glibc/blob/ae612c45efb5e34713859a5facf92368307efb6e/sysdeps/unix/sysv/linux/if_index.c
// or use getifaddrs; it likewise does netlink right:
// https://github.com/bminor/glibc/blob/ae612c45efb5e34713859a5facf92368307efb6e/sysdeps/unix/sysv/linux/ifaddrs.c

// OpenBSD:
// Supports IPv6 directly in calls to SIOCGIFCONF by mangling sockaddr ABI:
// https://man.openbsd.org/netintro.4

// Apple:
// Use getifaddrs:
// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
// (evidence it returns IPv6 addrs)
// https://developer.apple.com/forums/thread/660434 

// FreeBSD:
// Likewise does some interesting ABI mangling behavior that should be watched out for:
// https://bugs.freebsd.org/bugzilla/show_bug.cgi?id=159099

// Note that libpcap only uses either getifaddrs (if available) or SIOCGIFCONF (if getifaddrs isn't available):
// https://github.com/the-tcpdump-group/libpcap/blob/fbcc461fbc2bd3b98de401cc04e6a4a10614e99f/fad-glifc.c
// https://github.com/the-tcpdump-group/libpcap/blob/fbcc461fbc2bd3b98de401cc04e6a4a10614e99f/fad-getad.c 

// Some interfaces may only support certain packet families (that don't include AF_PACKET):
// https://stackoverflow.com/questions/19227781/linux-getting-all-network-interface-names
