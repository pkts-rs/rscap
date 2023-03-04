## Worklog:

- Builder pattern for each packet to simplify creating new packets with custom values that are then immediately joined with other layers
- Implement `Default` for Layer types
- Feature flags in `pkts` for different Layer types--one for telco, one for bluetooth, one for internet, one for SQL, etc.
- Addition of `prelude` file containing common traits (`Sequence`, `Session`, most of everything in `layers::traits`)
- Documentation of basic types
- Change `Sequence` types to actually use generic const expressions + VecDeque optionally (`no-std` compliant)
- add email to `rscap` README.md--get domain and email routing set up