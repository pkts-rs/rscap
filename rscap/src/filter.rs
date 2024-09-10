

//! Cross-platform packet filtering utilities.
//! 
//! 


#[derive(Clone, Debug)]
pub struct PacketStatistics {
    pub(crate) received: u32,
    pub(crate) dropped: u32,
}

impl PacketStatistics {
    #[inline]
    pub fn received(&self) -> u32 {
        self.received
    }

    #[inline]
    pub fn dropped(&self) -> u32 {
        self.dropped
    }
}
