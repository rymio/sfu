use std::collections::HashMap;

use rtc::peer_connection::sdp::RTCSessionDescription;
use rtc::peer_connection::transport::RTCIceCandidateInit;

use crate::client::{ClientId, Mid};
use crate::room::RoomId;

pub type RequestId = u64;

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum SFUEvent {
    Ok {
        request_id: RequestId,
        room_id: Option<RoomId>,
        client_id: Option<ClientId>,
    },
    Err {
        request_id: RequestId,
        room_id: Option<RoomId>,
        client_id: Option<ClientId>,
        reason: String,
    },
    Join {
        request_id: RequestId,
        room_id: RoomId,
        client_id: ClientId,
    },
    SessionDescription {
        request_id: RequestId,
        room_id: RoomId,
        client_id: ClientId,
        sdp: RTCSessionDescription,
        /// For a server-initiated subscribe offer (`sdp.sdp_type ==
        /// Offer`), maps each new/existing forwarding m-line's `mid` (as
        /// it appears in *this* `sdp`, not the original publisher's own
        /// mid — each subscriber's peer connection numbers its own mids
        /// independently) to the `ClientId` of the publisher it forwards.
        /// Empty for every other case (answers to a client's own offer,
        /// and any inbound client-sent offer/answer) — there is no
        /// ambiguity to resolve there. Populated by `Room::poll_event`,
        /// which is the only place with both a subscriber's own mid
        /// assignments and the room's `ForwardTable` in scope at once.
        mid_publishers: HashMap<Mid, ClientId>,
    },
    IceCandidate {
        request_id: RequestId,
        room_id: RoomId,
        client_id: ClientId,
        candidate: RTCIceCandidateInit,
    },
    Leave {
        request_id: RequestId,
        room_id: RoomId,
        client_id: ClientId,
        reason: String,
    },
}

impl SFUEvent {
    pub fn request_id(&self) -> RequestId {
        match self {
            SFUEvent::Ok { request_id, .. } => *request_id,
            SFUEvent::Err { request_id, .. } => *request_id,
            SFUEvent::Join { request_id, .. } => *request_id,
            SFUEvent::SessionDescription { request_id, .. } => *request_id,
            SFUEvent::IceCandidate { request_id, .. } => *request_id,
            SFUEvent::Leave { request_id, .. } => *request_id,
        }
    }
    pub fn room_id(&self) -> Option<RoomId> {
        match self {
            SFUEvent::Ok { room_id, .. } => *room_id,
            SFUEvent::Err { room_id, .. } => *room_id,
            SFUEvent::Join { room_id, .. } => Some(*room_id),
            SFUEvent::SessionDescription { room_id, .. } => Some(*room_id),
            SFUEvent::IceCandidate { room_id, .. } => Some(*room_id),
            SFUEvent::Leave { room_id, .. } => Some(*room_id),
        }
    }

    pub fn client_id(&self) -> Option<ClientId> {
        match self {
            SFUEvent::Ok { client_id, .. } => *client_id,
            SFUEvent::Err { client_id, .. } => *client_id,
            SFUEvent::Join { client_id, .. } => Some(*client_id),
            SFUEvent::SessionDescription { client_id, .. } => Some(*client_id),
            SFUEvent::IceCandidate { client_id, .. } => Some(*client_id),
            SFUEvent::Leave { client_id, .. } => Some(*client_id),
        }
    }
}
