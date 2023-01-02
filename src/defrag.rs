use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::marker::PhantomData;

use std::cmp;

use crate::error::*;
use crate::layers::ip::Ipv4Ref;
use crate::layers::traits::extras::*;
use crate::layers::traits::*;

pub trait BaseDefragment {
    #[inline]
    fn put_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        match self.filter() {
            Some(should_discard_packet) if should_discard_packet(pkt.as_slice()) => return Ok(()),
            _ => self.put_unfiltered_pkt_unchecked(pkt),
        }
    }

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError>;

    fn get_pkt_raw(&mut self) -> Option<Vec<u8>>;

    fn filter(&self) -> Option<&Box<dyn Fn(&[u8]) -> bool>>;

    fn set_filter_raw(&mut self, filter: Option<fn(&[u8]) -> bool>);
}

pub trait Defragment<Out: LayerObject + Validate + FromBytes + StatelessLayer>:
    BaseDefragment
{
    type In<'a>: LayerRef<'a>;

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
        self.get_pkt_raw()
            .and_then(|pkt| Some(Out::from_bytes_unchecked(pkt.as_ref())))
    }

    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filter: Option<F>);

    //    fn set_filter<'a>(&mut self, filter: Option<impl Fn(&Self::In<'a>) -> bool>);
}

pub struct DefragmentLayers<
    FirstIn: ToOwnedLayer + Validate,
    LastOut: LayerObject + Validate + FromBytes + StatelessLayer,
> {
    sessions: Vec<Box<dyn BaseDefragment>>,
    _in: PhantomData<FirstIn>,
    _out: PhantomData<LastOut>,
}

impl<
        'a,
        In: for<'b> LayerRef<'b> + ToOwnedLayer + Validate,
        Out: LayerObject + Validate + FromBytes,
    > DefragmentLayers<In, Out>
{
    #[inline]
    pub fn new<S: Defragment<Out, In<'a> = In> + 'static>(sequence: S) -> Self {
        DefragmentLayers {
            sessions: vec![Box::new(sequence)],
            _in: PhantomData::default(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn append<
        I: ToOwned<Owned = Out> + Validate,
        O: LayerObject + Validate + FromBytes,
        S: Defragment<Out, In<'a> = I> + 'static,
    >(
        mut self,
        sequence: S,
    ) -> DefragmentLayers<In, O> {
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
        let mut pkts = vec![pkt];
        let num_sessions = self.sessions.len();
        for (session_idx, session) in self.sessions.iter_mut().enumerate() {
            while let Some(pkt) = pkts.pop() {
                session.put_pkt_unchecked(pkt)?;
            }

            if session_idx + 1 == num_sessions {
                break; // Once we've reached the last session, we don't want to pull its packets
            }

            while let Some(pkt) = session.get_pkt_raw() {
                pkts.push(pkt);
            }

            if pkts.is_empty() {
                break;
            }
        }

        Ok(())
    }

    #[inline]
    pub fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        match self.sessions.last_mut() {
            None => None,
            Some(session) => session.get_pkt_raw(),
        }
    }

    #[inline]
    pub fn get_pkt(&mut self) -> Option<Out> {
        self.get_pkt_raw()
            .and_then(|pkt| Some(Out::from_bytes_unchecked(pkt.as_ref())))
    }
}

pub struct Ipv4Session<Out: LayerObject + Validate + FromBytes + BaseLayerMetadata> {
    filter: Option<Box<dyn Fn(&[u8]) -> bool>>,
    fragments: HashMap<u16, Ipv4Fragments>,
    reassembled: VecDeque<Vec<u8>>,
    _out: PhantomData<Out>,
}

impl<Out: LayerObject + Validate + FromBytes + BaseLayerMetadata> Ipv4Session<Out> {
    #[inline]
    pub fn new() -> Self {
        if Out::metadata()
            .as_any()
            .downcast_ref::<&dyn Ipv4PayloadMetadata>()
            .is_none()
        {
            // TODO: is this the best way to handle this? Should we just allow sessions to accept arbitrary `Out` types?
            panic!("Ipv4Session instances can only be created for Layer types that implement `Ipv4Metadata` for their associated metadata")
        }

        Ipv4Session {
            filter: None,
            fragments: HashMap::new(),
            reassembled: VecDeque::new(),
            _out: PhantomData::default(),
        }
    }

    #[inline]
    pub fn new_filtered(filter: fn(&[u8]) -> bool) -> Self {
        if Out::metadata()
            .as_any()
            .downcast_ref::<&dyn Ipv4PayloadMetadata>()
            .is_none()
        {
            // TODO: is this the best way to handle this? Should we just allow sessions to accept arbitrary `Out` types?
            panic!("Ipv4Session instances can only be created for Layer types that implement `Ipv4Metadata` for their associated metadata")
        }

        Ipv4Session {
            filter: Some(Box::new(filter)),
            fragments: HashMap::new(),
            reassembled: VecDeque::new(),
            _out: PhantomData::default(),
        }
    }
}

impl<Out: LayerObject + Validate + FromBytes + BaseLayerMetadata + StatelessLayer> BaseDefragment
    for Ipv4Session<Out>
{
    #[inline]
    fn set_filter_raw(&mut self, filt: Option<fn(&[u8]) -> bool>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(f)),
            None => None,
        }
    }

    #[inline]
    fn filter(&self) -> Option<&Box<dyn Fn(&[u8]) -> bool>> {
        self.filter.as_ref()
    }

    fn put_unfiltered_pkt_unchecked(&mut self, pkt: Vec<u8>) -> Result<(), ValidationError> {
        let ipv4 = Ipv4Ref::from_bytes_unchecked(pkt.as_slice());
        let ihl = cmp::max(ipv4.ihl() as usize, 5) * 4;
        let tl = cmp::max(ipv4.total_length() as usize, ihl);
        let data = pkt.get(ihl..tl).unwrap();

        let mf = ipv4.flags().more_fragments();
        let fo = ipv4.frag_offset() as usize;

        if fo == 0 && mf == false {
            self.fragments.remove(&ipv4.identifier());

            Out::validate_current_layer(&pkt[ihl..])?;
            let payload = pkt[ihl..].to_vec();
            self.reassembled.push_back(payload);
            return Ok(());
        }

        let mut frag = match self.fragments.remove(&ipv4.identifier()) {
            Some(f) => f,
            None => Ipv4Fragments::new(),
        };

        todo!();
        /*
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
        */
    }

    fn get_pkt_raw(&mut self) -> Option<Vec<u8>> {
        self.reassembled.pop_front()
    }
}

// Note that this effectively closes `Ipv4Session` to implementation of `Defragment`
// by other `Layer` types unless they implement StatelessLayer
impl<L: LayerObject + BaseLayerMetadata + FromBytes + StatelessLayer> Defragment<L>
    for Ipv4Session<L>
{
    type In<'a> = Ipv4Ref<'a>;

    fn set_filter<F: 'static + Fn(Self::In<'_>) -> bool>(&mut self, filt: Option<F>) {
        self.filter = match filt {
            Some(f) => Some(Box::new(move |i| f(Ipv4Ref::from_bytes_unchecked(i)))),
            None => None,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct Ipv4StreamId {
    pub saddr: u32,
    pub daddr: u32,
    pub protocol: u8,
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct Ipv4FragmentId {
    pub stream_id: Ipv4StreamId,
    pub fragment_id: u16,
}

struct Ipv4Fragments {
    pub tdl: usize,
    pub data: Vec<u8>, // length of this is total_data_len
    pub rcvbt: Vec<u64>,
    pub rcvbt_len: usize,
}

impl Ipv4Fragments {
    #[inline]
    fn new() -> Self {
        Ipv4Fragments {
            tdl: 0,
            data: Vec::new(),
            rcvbt: Vec::new(),
            rcvbt_len: 0,
        }
    }
}
