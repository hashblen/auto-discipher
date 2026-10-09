//! Parse network packets transmitted between the game and the server
//!
//! Packets are built up in following layers depending on the purpose of the packet:
//!
//! - Packets for connection management ([`GamePacket::Connection`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **[`ConnectionPacket`]**, containing events for connection establishment/disconnection
//! - Packets for game commands ([`GamePacket::Commands`])
//!     - **Ethernet/IP/UDP**, handled using [`etherparse`]
//!     - **KCP**, handled using [`kcp`]
//!         - The KCP header contains an extra field that needs to be removed
//!           to be compatible with the regular KCP protocol
//!     - **[`GameCommand`]**, encrypted using XOR
//!     - **Protobuf**, payload, needs to be parsed into using the types generated in [`gen::proto`]
//!
//! [`GameCommand`]s are encrypted using an XOR-key.
//! One of the first packets sent is a request for a new key from a seed.
//! That key is used for the rest of the packets.
//! This means the recording for packets needs to start before the game starts (train hyperdrive).
//!
//! ## Example
//! ```
//! use auto_discipher::{GamePacket, GameSniffer, ConnectionPacket};
//!
//! let packets: Vec<Vec<u8>> = vec![/**/];
//!
//! let mut sniffer = GameSniffer::new();
//! for packet in packets {
//!     match sniffer.receive_packet(packet) {
//!         Some(GamePacket::Connection(ConnectionPacket::Disconnected)) => {
//!             println!("Disconnected!");
//!             break;
//!         }
//!         Some(GamePacket::Commands(commands)) => {
//!             for command in commands {
//!                 println!("{:?}", command);
//!             }
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use protobuf::Message;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use std::fmt;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, info_span, instrument, trace, warn};

use crate::connection::parse_connection_packet;
use crate::crypto::{bruteforce, xor_decrypt, MIN_ORACLE_BYTES};
use crate::gen::protos::Unk;
use crate::kcp::KcpSniffer;
use crate::unk_util::{
    decode_list, find_achievement_list, matches_get_player_token_rsp, Achievement, AchievementList,
    Catalogue,
};
use crate::Key::Dispatch;

fn bytes_as_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut output, b| {
        let _ = write!(output, "{b:02x}");
        output
    })
}

// pub mod command_id;
pub mod gen;

mod connection;
mod crypto;
mod cs_rand;
mod kcp;
mod unk_util;

const PORTS: [u16; 2] = [20501, 20502];

/// Top-level packet sent by the game
pub enum GamePacket {
    Connection(ConnectionPacket),
    Commands(Vec<GameCommand>),
}

/// Packet for connection management
pub enum ConnectionPacket {
    HandshakeRequested,
    Disconnected,
    HandshakeEstablished,
    SegmentData(PacketDirection, Vec<u8>),
}

/// Game command header.
///
/// Contains the type of the command in `command_id`
/// and the data encoded in protobuf in `proto_data`
///
/// ## Bit Layout
/// | Bit indices     |  Type |  Name |
/// | - | - | - |
/// |   0..4      |  `u32`  |  Header (magic constant) |
/// |   4..6      |  `u16`  |  command_id |
/// |   6..8      |  `u16`  |  header_len |
/// |   8..12     |  `u32`  |  data_len |
/// |  12..12+data_len |  variable  |  proto_data |
/// | data_len..data_len+4  |  `u32`  |  Tail (magic constant) |
#[derive(Clone)]
pub struct GameCommand {
    pub command_id: u16,
    #[allow(unused)]
    pub header_len: u16,
    #[allow(unused)]
    pub data_len: u32,
    #[allow(unused)]
    pub proto_header: Vec<u8>,
    pub proto_data: Vec<u8>,
}

impl GameCommand {
    const HEADER_LEN: usize = 12;
    const TAIL_LEN: usize = 4;

    #[instrument(skip(bytes), fields(len = bytes.len()))]
    pub fn try_new(bytes: Vec<u8>) -> Option<Self> {
        let header_overhead = Self::HEADER_LEN + Self::TAIL_LEN;
        if bytes.len() < header_overhead {
            warn!(len = bytes.len(), "game command header incomplete");
            return None;
        }

        if bytes[0..4] != [0x01, 0x23, 0x45, 0x67]
            || bytes[bytes.len() - 4..] != [0x89, 0xAB, 0xCD, 0xEF]
        {
            error!("game command magic missing");
            return None;
        }

        // skip header magic const
        let command_id = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let header_len = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
        let data_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap());

        let data_start = 12 + header_len as usize;
        let data_end = data_start + data_len as usize;

        if data_end > bytes.len() {
            warn!(len = bytes.len(), "game command buffer too short");
            return None;
        }

        let proto_header = bytes[12..data_start].to_vec();
        let proto_data = bytes[data_start..data_end].to_vec();
        Some(GameCommand {
            command_id,
            header_len,
            data_len,
            proto_header,
            proto_data,
        })
    }

    pub fn apply_key(&mut self, key: &[u8]) {
        xor_decrypt(key, &mut self.proto_data)
    }

    pub fn parse_proto<T: protobuf::Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.proto_data)
    }

    pub fn parse_header<T: protobuf::Message>(&self) -> protobuf::Result<T> {
        T::parse_from_bytes(&self.proto_header)
    }
}

impl fmt::Debug for GameCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GameCommand")
            .field("command_id", &self.command_id)
            .field("header_len", &self.header_len)
            .field("data_len", &self.data_len)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub enum PacketDirection {
    Sent,
    Received,
}

pub enum Key {
    Dispatch(Vec<u8>),
    Session(Vec<u8>),
}

/// How many packets the key search keeps as its oracle.
///
/// Three agreeing already make a wrong key acceptance negligible, and more than
/// that is only reached when the search has failed for a while.
const MAX_PENDING: usize = 8;

#[derive(Default)]
pub struct GameSniffer {
    sent_kcp: Option<KcpSniffer>,
    recv_kcp: Option<KcpSniffer>,
    key: Option<Key>,
    initial_keys: Vec<Vec<u8>>,
    rsa_keys: Vec<RsaPrivateKey>,
    /// When the current packet was captured, which is what the key search is
    /// anchored on.
    timestamp_ms: u64,
    sent_time: Option<u64>,
    server_seed: u64,
    /// Raw bodies the key search is being run against. These must be the bodies
    /// as they arrived: a copy already XOR'd with the dispatch key has that key
    /// left in the XOR, so no candidate pad ever validates.
    pending: Vec<Vec<u8>>,
    catalogue: Catalogue,
    regular_list: Option<AchievementList>,
    arcade_list: Option<AchievementList>,
}

impl GameSniffer {
    pub fn new() -> Self {
        let pem_data_3 = include_str!("../keys/private_key_3.pem");

        let rsa_3 = RsaPrivateKey::from_pkcs1_pem(pem_data_3);

        GameSniffer {
            rsa_keys: vec![rsa_3]
                .iter()
                .filter_map(|rsa_key| rsa_key.clone().ok())
                .collect(),
            ..Default::default()
        }
    }

    // Initial keys: in ascending order of version releases (latest at the end).
    pub fn set_initial_keys(mut self, initial_keys: Vec<Vec<u8>>) -> Self {
        self.initial_keys = initial_keys;
        self
    }

    /// The achievement ids, as `(id, arcade)`.
    ///
    /// Achievement packets are found by matching their ids against this set, so
    /// without it no list can be recognised: the ids are opaque integers on the
    /// wire and cannot be told apart from any other varint field.
    pub fn set_achievement_ids(mut self, ids: impl IntoIterator<Item = (u32, bool)>) -> Self {
        self.catalogue = Catalogue::new(ids);
        info!(
            ids = self.catalogue.len(),
            arcade = self.catalogue.arcade_len(),
            "loaded achievement ids"
        );
        self
    }

    #[instrument(skip_all, fields(len = bytes.len()))]
    pub fn receive_packet(&mut self, bytes: Vec<u8>) -> Option<GamePacket> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as u64)
            .unwrap_or_default();
        self.receive_packet_at(bytes, now)
    }

    /// [`Self::receive_packet`], for a capture replayed after the fact. The
    /// clock the game stamped its request with comes from the capture rather
    /// than from the wall clock, so replaying a recording needs this instead.
    #[instrument(skip_all, fields(len = bytes.len()))]
    pub fn receive_packet_at(&mut self, bytes: Vec<u8>, timestamp_ms: u64) -> Option<GamePacket> {
        self.timestamp_ms = timestamp_ms;
        let packet = parse_connection_packet(&PORTS, bytes)?;
        match packet {
            ConnectionPacket::HandshakeRequested => {
                // Everything scoped to the session is stale from here on: the
                // keys, the seed, and whatever the detection concluded. Without
                // this a reconnect would mix two sessions' packets together.
                info!("handshake requested, resetting state");
                self.recv_kcp = None;
                self.sent_kcp = None;
                self.key = None;
                self.sent_time = None;
                self.server_seed = 0;
                self.pending.clear();
                self.regular_list = None;
                self.arcade_list = None;
                Some(GamePacket::Connection(packet))
            }
            ConnectionPacket::HandshakeEstablished | ConnectionPacket::Disconnected => {
                Some(GamePacket::Connection(packet))
            }

            ConnectionPacket::SegmentData(direction, kcp_seg) => {
                let commands = self.receive_kcp_segment(direction, &kcp_seg);
                match commands {
                    Some(commands) => Some(GamePacket::Commands(commands)),
                    None => Some(GamePacket::Connection(ConnectionPacket::SegmentData(
                        direction, kcp_seg,
                    ))),
                }
            }
        }
    }

    fn receive_kcp_segment(
        &mut self,
        direction: PacketDirection,
        kcp_seg: &[u8],
    ) -> Option<Vec<GameCommand>> {
        let kcp = match direction {
            PacketDirection::Sent => &mut self.sent_kcp,
            PacketDirection::Received => &mut self.recv_kcp,
        };

        if kcp.is_none() {
            let new_kcp = KcpSniffer::try_new(kcp_seg)?;
            *kcp = Some(new_kcp);
        }

        if let Some(kcp) = kcp {
            let commands = kcp
                .receive_segments(kcp_seg)
                .into_iter()
                .filter_map(|data| self.receive_command(data, direction))
                .collect();

            return Some(commands);
        }

        None
    }

    /// Read an achievement list out of a command.
    ///
    /// No protos, no packet ids and no known XOR constants are assumed: the shape
    /// of the list is searched for on the first list seen and reused afterwards.
    pub fn matches_achievement_packet(
        &mut self,
        game_command: &GameCommand,
    ) -> Option<Vec<Achievement>> {
        if self.catalogue.is_empty() {
            return None;
        }

        // Once a shape is known, decoding with it is cheap; before that it has to be
        // searched for, which is not. Both layouts are tried because the regular
        // list arrives in the login burst and the arcade one only when the player
        // opens arcade mode, so the second is always found after the first.
        let both_known = self.regular_list.is_some() && self.arcade_list.is_some();
        for known in [self.regular_list.as_ref(), self.arcade_list.as_ref()]
            .into_iter()
            .flatten()
        {
            if let Some(achievements) = decode_list(&game_command.proto_data, known) {
                return Some(achievements);
            }
        }

        // With both shapes in hand there is nothing left to search for.
        if both_known {
            return None;
        }

        let list = find_achievement_list(&game_command.proto_data, &self.catalogue)?;
        info!(
            command_id = game_command.command_id,
            list = list.describe(),
            arcade = list.arcade,
            "found achievement list"
        );

        let achievements = decode_list(&game_command.proto_data, &list)?;
        if list.arcade {
            self.arcade_list = Some(list);
        } else {
            self.regular_list = Some(list);
        }
        Some(achievements)
    }

    #[instrument(skip_all, fields(len = data.len()))]
    fn receive_command(
        &mut self,
        data: Vec<u8>,
        direction: PacketDirection,
    ) -> Option<GameCommand> {
        // The request's timestamp seeds the key search. The response follows within
        // ~400ms and the search covers +/-15s, so either would do.
        if direction == PacketDirection::Sent && self.sent_time.is_none() {
            self.sent_time = Some(self.timestamp_ms);
        }

        let mut command = GameCommand::try_new(data.clone())?;
        let key_r = match &self.key {
            None => {
                let mut found_key: Option<Vec<u8>> = None;
                // Shipped keys are tried newest first and the one that yields a
                // decodable message wins.
                for k in self.initial_keys.iter().rev() {
                    let mut test = command.proto_data.clone();
                    xor_decrypt(k, &mut test);

                    if Unk::parse_from_bytes(&test).is_ok() {
                        found_key = Some(k.clone());
                        break;
                    }
                }

                match found_key {
                    Some(key) => {
                        self.key = Some(Dispatch(key));
                        self.key.as_ref().unwrap()
                    }
                    None => {
                        error!("No dispatch key found");
                        return None;
                    }
                }
            }
            Some(Dispatch(k)) => {
                let mut test = command.proto_data.clone();
                xor_decrypt(k, &mut test);

                if Unk::parse_from_bytes(&test).is_ok() {
                    self.key.as_ref().unwrap()
                } else {
                    // The dispatch key stops decoding once the session key takes
                    // over, which is what signals it is time to look for one.
                    let pad = self.bruteforce(&command.proto_data)?;
                    self.key = Some(Key::Session(pad));
                    self.key.as_ref().unwrap()
                }
            }
            Some(Key::Session(k)) => {
                let mut test = command.proto_data.clone();
                xor_decrypt(k, &mut test);

                if Unk::parse_from_bytes(&test).is_ok() {
                    self.key.as_ref().unwrap()
                } else {
                    warn!("Invalidated session key");
                    self.key = None;
                    error!("Session key dead, relaunch game");
                    return None;
                }
            }
        };

        let key = match key_r {
            Dispatch(k) | Key::Session(k) => k,
        };

        command.apply_key(key);

        let span = info_span!("command", ?command);
        let _enter = span.enter();

        info!("received");
        trace!(data = BASE64_STANDARD.encode(&command.proto_data), "data");

        // The seed is only in PlayerGetTokenScRsp, so there is nothing to look for
        // in anything the client sends.
        if let Some(Dispatch(_)) = self.key {
            if direction == PacketDirection::Received && self.server_seed == 0 {
                if let Some(seed) =
                    matches_get_player_token_rsp(&command.proto_data, &self.rsa_keys)
                {
                    self.server_seed = seed;
                    info!(seed, "setting new possible session seeds");
                }
            }
        }

        Some(command)
    }

    /// Brute-force the session key from the server's seed.
    ///
    /// The oracle is a buffer of raw bodies rather than the one in hand: a short
    /// packet can fail by chance and would then veto a correct key, so the search
    /// waits for a longer one and then wants agreement rather than a single hit.
    fn bruteforce(&mut self, body: &[u8]) -> Option<Vec<u8>> {
        debug!("Running bruteforce loop.");

        if self.server_seed == 0 || body.len() < MIN_ORACLE_BYTES {
            return None;
        }

        // These must be the bodies as they arrived. A copy already XOR'd with the
        // dispatch key has that key left in the XOR, so nothing ever validates.
        self.pending.push(body.to_vec());
        if self.pending.len() > MAX_PENDING {
            self.pending.remove(0);
        }

        let key = bruteforce(self.sent_time?, self.server_seed, &self.pending)?;
        self.pending.clear();
        Some(key)
    }
}
