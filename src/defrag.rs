use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;

use crate::layers::traits::{Layer, ValidationError, LayerRef, FromBytes, Validate, Ipv4Metadata, BaseLayerImpl, StatelessLayer};
use crate::layers::ip::Ipv4Ref;

pub trait BaseDefragment {
    #[inline]
    fn put_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        match self.filter() {
            Some(should_discard_packet) if should_discard_packet(pkt.as_slice()) => return Ok(()),
            _ => self.put_unfiltered_pkt_unchecked(pkt)
        }
    }

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError>;

    fn get_pkt_raw(&mut self) -> Option<Vec<u8>>;

    fn filter(&self) -> Option<fn(&[u8]) -> bool>;

    fn set_filter(&mut self, filter: Option<fn(&[u8]) -> bool>);
}

pub trait Defragment<Out: Layer + Validate + FromBytes + StatelessLayer>: BaseDefragment {
    type In<'a>: LayerRef<'a> + Into<&'a [u8]> + ToOwned + Validate;

    #[inline]
    fn put_pkt(&mut self, pkt: Self::In<'_>) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.into();
        self.put_pkt_unchecked(Vec::from(pkt_ref))
    }

    #[inline]
    fn put_unfiltered_pkt(&mut self, pkt: Self::In<'_>) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.into();
        self.put_pkt_unchecked(Vec::from(pkt_ref))
    }

    #[inline]
    fn get_pkt(&mut self) -> Option<Out> {
        self.get_pkt_raw().and_then(|pkt| Some(Out::from_bytes_unchecked(pkt.as_ref())))
    }

//    fn set_filter<'a>(&mut self, filter: Option<impl Fn(&Self::In<'a>) -> bool>);
}

pub struct DefragmentLayers<FirstIn: ToOwned + Validate, LastOut: Layer + Validate + FromBytes + StatelessLayer> {
    sessions: Vec<Box<dyn BaseDefragment>>,
    _in: PhantomData<FirstIn>,
    _out: PhantomData<LastOut>,
}


impl<'a, In: for<'b> LayerRef<'b> + ToOwned + Validate, Out: Layer + Validate + FromBytes> DefragmentLayers<In, Out> {
    #[inline]
    pub fn new<S: Defragment<Out, In<'a> = In> + 'static>(sequence: S) -> Self {
        DefragmentLayers {
            sessions: vec!(Box::new(sequence)),
            _in: PhantomData::default(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn append<I: ToOwned<Owned = Out> + Validate, O: Layer + Validate + FromBytes, S: Defragment<Out, In<'a> = I> + 'static>(mut self, sequence: S) -> DefragmentLayers<In, O> {
        self.sessions.push(Box::new(sequence));
        DefragmentLayers {
            sessions: self.sessions,
            _in: PhantomData::default(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn put_pkt(&mut self, pkt: In) -> Result<(), ValidationError> {
        let pkt_ref: &[u8] = pkt.into();
        self.put_pkt_unchecked(Vec::from(pkt_ref))
    }

    #[inline]
    pub fn put_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        let mut pkts = vec!(pkt);
        let num_sessions = self.sessions.len();
        for (session_idx, session) in self.sessions.iter_mut().enumerate() {
            while let Some(pkt) = pkts.pop() {
                session.put_pkt_unchecked(pkt)?;
            }

            if session_idx + 1 == num_sessions {
                break // Once we've reached the last session, we don't want to pull its packets
            }

            while let Some(pkt) = session.get_pkt_raw() {
                pkts.push(pkt);
            }

            if pkts.is_empty() {
                break
            }
        }

        Ok(())
    }

    #[inline]
    pub fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        match self.sessions.last_mut() {
            None => None,
            Some(session) => session.get_pkt_raw()
        }
    }

    #[inline]
    pub fn get_pkt(&mut self) -> Option<Out> {
        self.get_pkt_raw().and_then(|pkt| Some(Out::from_bytes_unchecked(pkt.as_ref())))
    }
}

pub struct Ipv4Session<Out: Layer + Validate + FromBytes + BaseLayerImpl> {
    // filter: Option<fn(&[u8]) -> bool>,
    filter: Option<fn(&[u8]) -> bool>,
    fragments: HashMap<Ipv4BufferIdentifier, Ipv4Fragments>,
    _out: PhantomData<Out>,
}

impl<Out: Layer + Validate + FromBytes + BaseLayerImpl> Ipv4Session<Out> {
    #[inline]
    pub fn new() -> Self {
        if Out::layer_metadata_instance().as_any().downcast_ref::<&dyn Ipv4Metadata>().is_none() {
            // TODO: is this the best way to handle this? Should we just allow sessions to accept arbitrary `Out` types?
            panic!("Ipv4Session instances can only be created for Layer types that implement `Ipv4Metadata` for their associated metadata")
        }

        Ipv4Session {
            filter: None,
            fragments: HashMap::new(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn new_filtered(filter: fn(&[u8]) -> bool) -> Self {
        if Out::layer_metadata_instance().as_any().downcast_ref::<&dyn Ipv4Metadata>().is_none() {
            // TODO: is this the best way to handle this? Should we just allow sessions to accept arbitrary `Out` types?
            panic!("Ipv4Session instances can only be created for Layer types that implement `Ipv4Metadata` for their associated metadata")
        }

        Ipv4Session {
            filter: Some(filter),
            fragments: HashMap::new(),
            _out: PhantomData::default(),
        }
    }
}

impl<Out: Layer + Validate + FromBytes + BaseLayerImpl + StatelessLayer> BaseDefragment for Ipv4Session<Out> {
    /*
    #[inline]
    fn process_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<Option<Vec<u8>>, ValidationError> {
        let ipv4 = Ipv4Ref::from_bytes_unchecked(pkt.as_slice());
        let ihl = cmp::max(ipv4.ihl() as usize, 5) * 4;
        let tl = cmp::max(ipv4.total_length() as usize, ihl);
        let data = pkt.get(ihl..tl).unwrap();

        // The following algorithm is implemented near-verbatim from RFC 791
        let buf_id = Ipv4BufferIdentifier {
            saddr: ipv4.saddr(),
            daddr: ipv4.daddr(),
            id: ipv4.identifier()
        };

        let mf = ipv4.flags().more_fragments();
        let fo = ipv4.frag_offset() as usize;

        if fo == 0 && mf == false {
            self.fragments.remove(&buf_id);
            return Ok(Some(pkt)) // TODO: discard first n bytes that form Ipv4 header
        }

        let mut frag = match self.fragments.remove(&buf_id) {
            Some(f) => f,
            None => Ipv4Fragments::new(),
        };
        
        let data_start = fo * 8;
        let data_end = data_start + (tl - (ihl*4));

        if frag.data_buf.len() < data_end {
            frag.data_buf.extend(std::iter::repeat(0).take(data_end - frag.data_buf.len())); // Pad intermediate data with 0's
        }

        for i in 0..data.len() {
            frag.data_buf[data_start + i] = data[i];
        }

        let rcvbt_start = fo;
        let rcvbt_end = fo + ((tl - (ihl * 4) + 7) / 8);

        let u64_end = rcvbt_end / 64 + if rcvbt_end % 64 > 0 { 1 } else { 0 };
        if frag.rcvbt.len() < u64_end {
            frag.rcvbt.extend(std::iter::repeat(0).take(fo - frag.rcvbt.len()));
            frag.rcvbt_len = rcvbt_end % 64;
        } else if frag.rcvbt.len() == u64_end {
            frag.rcvbt_len = cmp::max(frag.rcvbt_len, u64_end % 64);
        }

        for i in fo..rcvbt_end {
            frag.rcvbt[i] = 1;
        }

        // TODO: finish

        Ok(Some(pkt))
    }
    */

    #[inline]
    fn set_filter(&mut self, filter: Option<fn(&[u8]) -> bool>) {
        self.filter = filter
    }

    #[inline]
    fn filter(&self) -> Option<fn(&[u8]) -> bool> {
        self.filter
    }

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        todo!()
    }

    fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        todo!()
    }
}


// Note that this effectively closes `Ipv4Session` to implementation of `Defragment`
// by other `Layer` types unless they implement StatelessLayer
impl<L: Layer + BaseLayerImpl + FromBytes + StatelessLayer> Defragment<L> for Ipv4Session<L> {
    type In<'a> = Ipv4Ref<'a>;
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct Ipv4BufferIdentifier {
    saddr: u32,
    daddr: u32,
    id: u16,
}

struct Ipv4Fragments {
    pub total_length: usize,
    pub data_buf: Vec<u8>, // length of this is total_data_len
    pub rcvbt: Vec<u64>,
    pub rcvbt_len: usize,
}

impl Ipv4Fragments {
    #[inline]
    fn new() -> Self {
        Ipv4Fragments {
            total_length: 0,
            data_buf: Vec::new(),
            rcvbt: Vec::new(),
            rcvbt_len: 0,
        }
    }
}