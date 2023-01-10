use crate::error::ValidationError;
use crate::layers::traits::LayerObject;

// A session takes in raw bytes and outputs the type associated with the given session

trait Session {
    type Out: LayerObject;

    fn put(&mut self, pkt: &[u8]) -> Result<(), ValidationError>;

    fn get(&mut self) -> Option<Self::Out>;
}

trait DualSession {
    type Out1: LayerObject;
    type Out2: LayerObject;

    fn put1(&mut self, pkt: &[u8]) -> Result<(), ValidationError>;

    fn put2(&mut self, pkt: &[u8]) -> Result<(), ValidationError>;

    fn get1(&mut self) -> Option<Self::Out1>;

    fn get2(&mut self) -> Option<Self::Out2>;
}

trait MultiSession {
    type Out: LayerObject;

    fn new(session_cnt: usize) -> Self;

    fn put(&mut self, pkt: &[u8], idx: usize) -> Result<(), ValidationError>;

    fn get(&mut self, idx: usize) -> Option<Self::Out>;
}

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
