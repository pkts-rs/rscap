

Important design decisions:

===get_layer() API===

1. How aggressive should we be on guessing next layers from current ones?
  - No guessing for layers past TCP
  - No guessing for UDP when Ipv4 fragmentation happens
  - Guessing enabled for specific ports on UDP? If so, it would be enabled universally... and ports aren't universally designated, so we'll want a seperate API to specify layers.

2. How to manually choose layers when constructing packet?
  - fn from_bytes

3. How to mutate a Raw layer into new layers afterwards?
  - fn try_into<T: Layer>() implemented generically for Raw (internals)
  - fn raw_to_layer<T: Layer>(&mut self) -> bool;