# pkts-macros &emsp; [![Latest Version]][crates.io] [![pkts: rustc 1.65+]][Rust 1.65] [![License Information]][GPLv2] [![Documentation]][docs.rs]

[Latest Version]: https://img.shields.io/crates/v/pkts-macros.svg
[crates.io]: https://crates.io/crates/pkts-macros
[pkts: rustc 1.65+]: https://img.shields.io/badge/MSRV-rustc_1.65+-orange.svg
[Rust 1.65]: https://blog.rust-lang.org/2022/11/03/Rust-1.65.0.html
[License Information]: https://img.shields.io/crates/l/pkts-macros.svg
[GPLv2]: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
[Documentation]: https://docs.rs/pkts-macros/badge.svg
[docs.rs]: https://docs.rs/pkts-macros/


### **pkts-macros - an [rscap](https://crates.io/crates/rscap) submodule for generating common code for Layers**

---

Rscap is a multi-purpose library for network packet capture/transmission and packet building. Its aims are twofold:

1. To provide Rust-native platform tools for packet capture and transmission (comparable to `libpcap`, but written from the ground up in Rust)
2. To expose a robust and ergonomic API for building packets and accessing/modifying packet data fields in various network protocols (like `scapy`, but with strong typing and significantly improved performance)

The `pkts` submodule focuses solely on (2)--it provides a packet-building API for a wide variety of network protocol layers.
This library isn't meant to only cover Physical through Transport layers or stateless protocols--thanks to `Sequence` and `Session` types (which defragment/reorder packets and track packet state, respectively), any application-layer protocol can be easily captured and decoded.

The `pkts-macros` submodule provides derive macros that assist in creating new `Layer` types.

More information on the library can be found in the [`rscap`](https://crates.io/crates/rscap) or [`pkts`](https://crates.io/crates/pkts) crates.

## License

The source code of this project is made available under the [GNU General Public License, version 2][GPLv2].

Requests regarding other licensing options can be made to *email address here*.