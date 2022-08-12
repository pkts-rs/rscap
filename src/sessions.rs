use std::marker::PhantomData;

use crate::layers::traits::{Layer, LayerRef, Validate, FromBytes};
use crate::defrag::{Defragment, DefragmentLayers, BaseDefragment};

trait Session { // <In: ToOwned + Validate> {
    type Out: Layer;

    // fn prepend_session<I: ToOwned + Validate, S: Session<I, Out = Self::Out>>(self, session: S);

    // fn prepend_defragmentor<I: ToOwned + Validate, S: Session<I, Out = Self::Out>>(self, defrag: S);
}

pub struct LayeredSessions<In: ToOwned + Validate> { // <FirstIn: ToOwned + Validate, LastOut: Layer> {
    sessions: Vec<Box<dyn BaseDefragment>>,
    _in: PhantomData<In>,
}

struct _ExampleSession {
    sessions: Vec<Box<dyn BaseDefragment>>,
}

trait DualSession {
    type Out1: Layer;
    type Out2: Layer;
}

trait MultiSession {
    type Out: Layer;
}


//  

/*
trait TwoWaySession<Peer1In: Layer, Peer2In: Layer> {
    type Out: Layer;
    type NewSession<I1: Layer, I2: Layer>: TwoWaySession<I1, I2, Out = Self::Out>;
    fn prepend_sequence<In2: Layer>(self) -> Self::NewSession<In2>;
}

struct MysqlTwoSession {

}

impl<In> TwoWaySession<In> for MysqlTwoSession {
    type Out = Mysql;
    type NewSession<I: Layer> = MysqlTwoSession;

    fn prepend_sequence<In2: Layer>(self) -> Self::NewSession<In2> {
        todo!()
    }
}

// MultiwaySession
// 

*/
