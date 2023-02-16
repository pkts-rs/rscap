use crate::error::ValidationError;
use crate::layers::traits::{LayerObject, LayerRef};
use crate::private;

// A session takes in raw bytes and outputs the type associated with the given session




trait Session {
    type Out<'a>: LayerRef<'a>;

    fn convert<'b>(bytes: &'b [u8]) -> Result<Self::Out<'b>, ValidationError>;

    /// Creates a packet from the given bytes without checking the syntactical
    /// validity of those bytes.
    fn convert_unchecked<'b>(bytes: &'b [u8]) -> Self::Out<'b>;

    /// Checks to see whether the given bytes form a syntactically valid packet
    /// within the context of the current sesson's state.
    fn validate(&self, bytes: &[u8]) -> Result<(), ValidationError>;
}

pub struct MysqlClientSession {
    state: MysqlClientState,
}

#[derive(Clone, Copy)]
pub enum MysqlClientState {
    Startup(MysqlStartupState),
    Error(MysqlErrorState),
}

#[derive(Clone, Copy)]
pub struct MysqlStartupState { }

impl MysqlStartupState {
    pub fn error(session: &mut MysqlClientSession) {
        session.state = MysqlClientState::Error(MysqlErrorState { });
    }
}

#[derive(Clone, Copy)]
pub struct MysqlErrorState { }



/*
pub struct MysqlClientSession<S: MysqlClientState> {
    _marker: core::marker::PhantomData<S>,
}

pub trait MysqlClientState: private::Sealed { }

pub struct MysqlStartupState { }

impl private::Sealed for MysqlStartupState { }

impl MysqlClientState for MysqlStartupState { }

impl MysqlClientSession<MysqlStartupState> {
    //pub fn transition(self, input: &Self::Out<'_>) -> 
}

impl Session for MysqlClientSession<MysqlStartupState> {
    type Out<'a>;

    fn convert<'b>(bytes: &'b [u8]) -> Result<Self::Out<'b>, ValidationError> {
        todo!()
    }

    fn convert_unchecked<'b>(bytes: &'b [u8]) -> Self::Out<'b> {
        todo!()
    }

    fn validate(&self, bytes: &[u8]) -> Result<(), ValidationError> {
        todo!()
    }
}
*/


/*
trait DualSession {
    type FrontendOut<'a>: LayerRef<'a>;
    type BackendOut<'a>: LayerRef<'a>;

    fn frontend_validate(bytes: &[u8]) -> Result<(), ValidationError>;

    fn frontend_convert<'b>(bytes: &'b [u8]) -> Result<Self::FrontendOut<'b>, ValidationError>;

    fn frontend_convert_unchecked<'b>(bytes: &'b [u8]) -> Self::FrontendOut<'b>;

    fn backend_validate(bytes: &[u8]) -> Result<(), ValidationError>;

    fn backend_convert<'b>(bytes: &'b [u8]) -> Result<Self::BackendOut<'b>, ValidationError>;

    fn backend_convert_unchecked<'b>(bytes: &'b [u8]) -> Self::BackendOut<'b>;
}

trait MultiSession {
    type Out: LayerObject;

    fn new(session_cnt: usize) -> Self;

    fn put(&mut self, pkt: &[u8], idx: usize) -> Result<(), ValidationError>;

    fn get(&mut self, idx: usize) -> Option<Self::Out>;
}
*/

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
