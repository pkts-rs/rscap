# Release History:

* 0.3.1 (2025-02-14)
  - Resolve bug in `L4Socket` address binding
  - Add sponsors information

* 0.3.0 (2025-02-14)
  - Adjust `Interface` creation functions to work with wider range of inputs
  - Add `AsRawFd` APIs for various sniffers
  - Various quality-of-life improvements in CI
  - Bump MSRV to 1.74

* 0.2.2 (2024-11-02)
  - Add documentation
  - Make OS-specific APIs visible to all documentation
  - Update README

* 0.2.1 (2024-10-21)
  - Fix size of `tpacket_req` passed into setsockopt

* 0.2.0 (2024-09-09)
  - Split out `rscap` and `pkts` into separate crates
  - Introduce CI pipeline

* 0.1.1 (2023-03-23)
  - Cleanup of unstable/unused APIs

* 0.1.0 (2023-03-03)
  - Initial commit, interfaces very unstable/untested/nonexistent