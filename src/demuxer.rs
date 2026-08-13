use crate::client::ClientId;
use crate::room::{RoomId, decode_local_ufrag};
use rtc::shared::FourTuple;
use rtc::shared::TaggedBytesMut;
use rtc::stun::attributes::ATTR_USERNAME;
use rtc::stun::message::{Message, is_stun_message};
use rtc::stun::textattrs::Username;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Default)]
pub(crate) struct Demuxer {
    affinity: HashMap<FourTuple, (RoomId, ClientId)>,
    reverse: HashMap<(RoomId, ClientId), HashSet<FourTuple>>,
}

impl Demuxer {
    pub(crate) fn demux(&mut self, pkt: &TaggedBytesMut) -> Option<(RoomId, ClientId)> {
        let four_tuple = FourTuple::from(&pkt.transport);
        if let Some(room_client) = self.affinity.get(&four_tuple) {
            return Some(*room_client);
        }

        self.demux_stun_username(pkt)
    }

    /// Forget every four-tuple learned for `(room_id, client_id)`.
    ///
    /// Reactive, not time-based: the sans-IO core has no clock of its own (see the crate
    /// README), so this is called from `Room`/`Sfu` when they already know a client left
    /// (`SFUEvent::Leave`) rather than aging entries against `Instant::now()`. This covers
    /// the realistic disconnect path — `examples/signaling`'s `teardown()` always sends
    /// `Leave` on WebSocket close, ungraceful or not — but not a client that vanishes
    /// without the signaling layer ever learning about it (e.g. a signaling-process crash
    /// mid-session). That residual case is a signaling-layer liveness concern (a
    /// heartbeat/timeout there), not something fixable inside a clockless demuxer.
    pub(crate) fn evict(&mut self, room_id: RoomId, client_id: ClientId) {
        if let Some(four_tuples) = self.reverse.remove(&(room_id, client_id)) {
            for four_tuple in four_tuples {
                self.affinity.remove(&four_tuple);
            }
        }
    }

    fn demux_stun_username(&mut self, pkt: &TaggedBytesMut) -> Option<(RoomId, ClientId)> {
        if !is_stun_message(pkt.message.as_ref()) {
            return None;
        }

        let mut stun = Message::new();
        stun.unmarshal_binary(pkt.message.as_ref()).ok()?;

        // USERNAME = local_ufrag ":" remote_ufrag; the local half is what the SFU issued,
        // so it carries the room and client (see `room::encode_local_ufrag`).
        let username = Username::get_from_as(&stun, ATTR_USERNAME).ok()?;
        let local_ufrag = username.text.split_once(':')?.0;
        let (room_id, client_id) = decode_local_ufrag(local_ufrag)?;

        let four_tuple = pkt.transport.into();
        self.affinity.insert(four_tuple, (room_id, client_id));
        self.reverse
            .entry((room_id, client_id))
            .or_default()
            .insert(four_tuple);

        Some((room_id, client_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn four_tuple(peer_port: u16) -> FourTuple {
        FourTuple {
            local_addr: "127.0.0.1:8000".parse().unwrap(),
            peer_addr: format!("127.0.0.1:{peer_port}").parse().unwrap(),
        }
    }

    #[test]
    fn evict_forgets_every_four_tuple_for_the_client() {
        let mut demuxer = Demuxer::default();
        let room: RoomId = Uuid::from_u128(1);
        let client: ClientId = 1;

        // A client can be learned on more than one four-tuple (e.g. an ICE restart
        // rebinding to a new local port before the old candidate pair is pruned).
        let a = four_tuple(40000);
        let b = four_tuple(40001);
        demuxer.affinity.insert(a, (room, client));
        demuxer.affinity.insert(b, (room, client));
        demuxer
            .reverse
            .insert((room, client), HashSet::from([a, b]));

        demuxer.evict(room, client);

        assert!(!demuxer.affinity.contains_key(&a));
        assert!(!demuxer.affinity.contains_key(&b));
        assert!(!demuxer.reverse.contains_key(&(room, client)));
    }

    #[test]
    fn evict_leaves_other_clients_alone() {
        let mut demuxer = Demuxer::default();
        let room: RoomId = Uuid::from_u128(1);
        let evicted: ClientId = 1;
        let other: ClientId = 2;

        let evicted_tuple = four_tuple(40000);
        let other_tuple = four_tuple(40001);
        demuxer.affinity.insert(evicted_tuple, (room, evicted));
        demuxer.affinity.insert(other_tuple, (room, other));
        demuxer
            .reverse
            .insert((room, evicted), HashSet::from([evicted_tuple]));
        demuxer
            .reverse
            .insert((room, other), HashSet::from([other_tuple]));

        demuxer.evict(room, evicted);

        assert!(!demuxer.affinity.contains_key(&evicted_tuple));
        assert_eq!(demuxer.affinity.get(&other_tuple), Some(&(room, other)));
        assert!(demuxer.reverse.contains_key(&(room, other)));
    }

    #[test]
    fn evict_of_unknown_client_is_a_harmless_no_op() {
        let mut demuxer = Demuxer::default();
        demuxer.evict(Uuid::from_u128(1), 1);
    }
}
