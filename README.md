# rscap

[![Latest Version]][crates.io] [![Documentation]][docs.rs] [![rscap: rustc 1.74+]][Rust 1.74]

[Latest Version]: https://img.shields.io/crates/v/rscap.svg
[crates.io]: https://crates.io/crates/rscap
[rscap: rustc 1.74+]: https://img.shields.io/badge/MSRV-rustc_1.74+-blue.svg
[Rust 1.74]: https://blog.rust-lang.org/2023/11/16/Rust-1.74.0.html
[Documentation]: https://docs.rs/rscap/badge.svg
[docs.rs]: https://docs.rs/rscap/

**rscap - Rust packet capture and transmission utilities**

---

`rscap` is a multi-purpose library for low-level network packet capture and transmission. Its aims are twofold:

1. To provide Rust-native platform APIs for packet capture and transmission (comparable to `libpcap`, but written from the ground up in Rust)
2. To expose a robust and ergonomic API for building packets and accessing/modifying packet data fields in various network protocols (like `scapy`, but with strong typing and significantly improved performance thanks to zero-allocation abstractions)

The `rscap` submodule focuses specifically on (1)--it provides safe, Rust-native APIs for capturing packets over network interfaces. 
The sibling [`pkts` crate](https://github.com/pkts-rs/pkts) handles building/dissecting specific protocols and packet types (2).

## Platform Support

`rscap` provides both platform-specific and unified cross-platform APIs for capturing and
transmitting arbitrary packets. It currently supports the following features for each platform:

| Platform         | Sniffing (RX) | Spoofing (TX) | Packet Filtering (BPF) | Memory-Mapped I/O |
| ---------------- | ------------- | ------------- | ---------------------- | ----------------- |
| Linux            | ✅            | ✅            | ✅                     | ✅                |
| MacOS            | ✅            | ✅            | ✅                     | N/A               |
| Windows (Npcap)  | ✅            | ✅            | ⬜                     | N/A               |
| Windows (native) | ⬜            | N/A           | ⬜                     | ?                 |
| FreeBSD          | ✅            | ✅            | ⬜                     | ✅*               |
| OpenBSD          | ⬜            | ⬜            | ⬜                     | N/A               |
| NetBSD           | ⬜            | ⬜            | ⬜                     | N/A               |
| DragonFly BSD    | ⬜            | ⬜            | ⬜                     | N/A               |
| Solaris          | ⬜            | ⬜            | ⬜                     | ?                 |
| IllumOS          | ⬜            | ⬜            | ⬜                     | ?                 |
| AIX              | ⬜            | ⬜            | ⬜                     | ?                 |

`*` - FreeBSD supports only memory-mapped sniffing (RX)

Note that `rscap` is under active development--*BSD system support (with CI testing) will be implemented in the near future, whereas native Windows APIs and Solaris/IllumOS/AIX support are respectively in mid- and long-term plans.

## Development Status

In Progress:
- Compiling/assembling methods for more advanced filter programs (BPF)
- *BSD Continuous Integration (CI) testing
- Additional platform-specific configuration options
- Native Windows 10/11 capture support via reverse-engineered ioctl calls from `pktmon` (RX only)
- Solaris/IllumOS support via DLPI/`PF_SOCKET`/`/dev/bpf` (RX + TX)
- AIX support

## Features

- **Platform-independent interface for packet capture/transmission:** `rscap` provides a single unified interface for capturing and transmitting packets across any supported platform. Additionally, the library exposes safe abstractions of platform-specific packet capture tools (such as `AF_PACKET`/`PACKET_MMAP` sockets in Linux) to support cases where fine-grained control or platform-specific features are desired.
- **`no-std` Compatible:** every packet type in the `pkts` crate can be used without the standard library, and a special `LayerRef` type can be used to access raw packet bytes without requiring `alloc`.
- **Robust APIs for building/modifying packets:** `pkts` provides simple operations to combine various layers into a single packet, and to index into a different layers of a packet to retrieve or modify fields. Users of [`scapy`](https://github.com/ecdev/scapy) may find the API surprisingly familiar, especially for layer composition and indexing operations:

```rust
use layers::{ip::Ipv4, tcp::Tcp};

let pkt = Ip::new() / Tcp::new();
pkt[Tcp].set_sport(80);
pkt[Tcp].set_dport(12345);
```

- **Packet defragmentation/reordering:** In some protocols, packets may be fragmented (such as IPv4) or arrive out-of-order (TCP, SCTP, etc.). `pkts` overcomes both of these issues through `Sequence` types that transparently handle defragmentation and reordering. `Sequence` types can even be stacked so that application-layer data can easily be reassembled from captured packets. They even work in `no-std` environments with or without `alloc`.
- **Stateful packet support:** Many network protocols are stateful, and interpreting packets from such protocols can be difficult (if not impossible) to accomplish unless information about the protocol session is stored. Rscap provides `Session` types that handle these kinds of packets--Sessions ensure that packets are validated based on the current expected state of the protocol. Just like `Sequence`, `Session` types are compatible with `no-std` environments and do not require `alloc`.

## `async` Runtime Support

All `Sniffer`/`Socket` types implement synchronous blocking/nonblocking `send()` and `recv()` APIs.
In addition to this, `rscap` plans on providing first-class support for the following `async`
runtimes:

| `async` Runtime | Supported? |
| --------------- | ---------- |
| `async-std`     | ⬜         |
| `smol`          | ⬜         |
| `mio`           | ⬜*        |
| `tokio`         | ⬜         |

`*` - on all platforms except for Windows

## Dependency Policy

Like other crates managed by pkts.org, `rscap` aims to rely on a minimal set of dependencies
that are vetted and well-used in the Rust ecosystem. As such, `rscap` has only the following
dependencies:

* `libc`, `windows-sys` - Exposes base types and functions needed for underlying system library calls.
* `bitflags` - Provides a simple, clean interface for accessing and modifying bitfields in packets.
Used extensively in the rust ecosystem (e.g. by `rustix`, `openssl`, `bindgen`, etc.); includes no transitive dependencies.
* `once_cell` - Used in Windows implementation of `Sniffer`. Will be replaced with the standard
library once certain `OnceCell` APIs are stabilized; includes no transitive dependencies.
* `pkts-common` - Shared data types/methods between `rscap` and `pkts`; includes no transitive dependencies.

The following optional dependencies will be included once various async runtime features are implemented:
* `async-std` - Included for async compatibility with the `async-std` runtime
* `mio` - Included for async compatibility with the `mio` runtime
* `smol` - Included for async compatibility with the `smol` runtime
* `tokio` - Included for async compatibility with the `tokio` runtime
* `async-io` - Additional dependency for the `async-std` and `smol` runtimes

We do not plan on adding in any additional dependencies to `rscap`. The one exception to this
rule is that some common structs (e.g. `MacAddr`, `Interface`) may be split out into a separate
crate in a future release.

## License

This project is licensed under either of

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
  ([LICENSE-APACHE](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-APACHE))

* [MIT License](https://opensource.org/licenses/MIT)
  ([LICENSE-MIT](https://github.com/rust-lang/libc/blob/HEAD/LICENSE-MIT))

at your option.

## Contributing

`rscap` is open to contribution--feel free to submit an issue or pull request if there's
something you'd like to add to this library.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
`rscap` by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
