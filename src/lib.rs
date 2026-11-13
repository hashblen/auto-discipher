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
//!         Ok(Some(GamePacket::Connection(ConnectionPacket::Disconnected))) => {
//!             println!("Disconnected!");
//!             break;
//!         }
//!         Ok(Some(GamePacket::Commands(commands))) => {
//!             for command in commands {
//!                 println!("{:?}", command);
//!             }
//!         }
//!         Err(error) => {
//!             println!("{error}");
//!             break;
//!         }
//!         _ => {}
//!     }
//! }
//! ```
//!

use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};
use std::fmt;
use std::fmt::Write;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, info_span, instrument, trace, warn};

use crate::connection::parse_connection_packet;
use crate::crypto::{bruteforce, parses_with, xor_decrypt, MIN_ORACLE_BYTES};
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

/// Why the sniffer gave up on a connection.
///
/// The sniffer has reset itself by the time one of these is returned, so whatever
/// follows starts from scratch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffError {
    /// None of the initial keys fit the connection's first packets. Either the
    /// game has a new key, or the capture started after the login.
    InitialKeyMissing {
        /// The version the packets asked for, where the game has such a thing.
        version: Option<u32>,
        /// Whether the connection's handshake was captured. Without it the
        /// capture started late, and any version is just noise.
        saw_handshake: bool,
    },
    /// The initial key stopped fitting, but no session seed was ever seen.
    SessionSeedMissing,
    /// A session seed was seen, but no key derived from it decrypts the traffic.
    BruteforceFailed,
    /// The session key stopped decrypting the traffic.
    SessionKeyLost,
}

impl fmt::Display for SniffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitialKeyMissing { version, saw_handshake } => write!(
                f,
                "no initial key found (version: {version:?}, handshake seen: {saw_handshake})"
            ),
            Self::SessionSeedMissing => write!(f, "no session seed found"),
            Self::BruteforceFailed => write!(f, "could not bruteforce the session key"),
            Self::SessionKeyLost => write!(f, "the session key stopped working"),
        }
    }
}

impl std::error::Error for SniffError {}

/// Which key the sniffer is decrypting with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    None,
    Dispatch,
    Session,
}

/// How many long packets in a row may fail before a key is given up on. Only
/// packets of at least [`MIN_ORACLE_BYTES`] count, since shorter ones fail for
/// good keys too.
const MAX_KEY_FAILURES: u32 = 3;

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
    saw_handshake: bool,
    key_failures: u32,
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

    /// Forget the current connection, keeping the keys and the achievement ids the
    /// sniffer was set up with.
    pub fn reset(&mut self) {
        self.recv_kcp = None;
        self.sent_kcp = None;
        self.key = None;
        self.sent_time = None;
        self.server_seed = 0;
        self.pending.clear();
        self.regular_list = None;
        self.arcade_list = None;
        self.saw_handshake = false;
        self.key_failures = 0;
    }

    /// Which key the sniffer is decrypting with.
    pub fn key_state(&self) -> KeyState {
        match self.key {
            None => KeyState::None,
            Some(Key::Dispatch(_)) => KeyState::Dispatch,
            Some(Key::Session(_)) => KeyState::Session,
        }
    }

    #[instrument(skip_all, fields(len = bytes.len()))]
    pub fn receive_packet(&mut self, bytes: Vec<u8>) -> Result<Option<GamePacket>, SniffError> {
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
    pub fn receive_packet_at(
        &mut self,
        bytes: Vec<u8>,
        timestamp_ms: u64,
    ) -> Result<Option<GamePacket>, SniffError> {
        self.timestamp_ms = timestamp_ms;
        let result = self.process_packet(bytes);
        if result.is_err() {
            self.reset();
        }
        result
    }

    fn process_packet(&mut self, bytes: Vec<u8>) -> Result<Option<GamePacket>, SniffError> {
        let Some(packet) = parse_connection_packet(&PORTS, bytes) else {
            return Ok(None);
        };
        match packet {
            ConnectionPacket::HandshakeRequested => {
                // Everything scoped to the session is stale from here on: the
                // keys, the seed, and whatever the detection concluded. Without
                // this a reconnect would mix two sessions' packets together.
                info!("handshake requested, resetting state");
                self.reset();
                self.saw_handshake = true;
                Ok(Some(GamePacket::Connection(packet)))
            }
            ConnectionPacket::HandshakeEstablished | ConnectionPacket::Disconnected => {
                Ok(Some(GamePacket::Connection(packet)))
            }

            ConnectionPacket::SegmentData(direction, kcp_seg) => {
                let commands = self.receive_kcp_segment(direction, &kcp_seg)?;
                Ok(Some(match commands {
                    Some(commands) => GamePacket::Commands(commands),
                    None => GamePacket::Connection(ConnectionPacket::SegmentData(
                        direction, kcp_seg,
                    )),
                }))
            }
        }
    }

    fn receive_kcp_segment(
        &mut self,
        direction: PacketDirection,
        kcp_seg: &[u8],
    ) -> Result<Option<Vec<GameCommand>>, SniffError> {
        let kcp = match direction {
            PacketDirection::Sent => &mut self.sent_kcp,
            PacketDirection::Received => &mut self.recv_kcp,
        };

        if kcp.is_none() {
            let Some(new_kcp) = KcpSniffer::try_new(kcp_seg) else {
                return Ok(None);
            };
            *kcp = Some(new_kcp);
        }

        if let Some(kcp) = kcp {
            let mut commands = Vec::new();
            for data in kcp.receive_segments(kcp_seg) {
                commands.extend(self.receive_command(data, direction)?);
            }

            return Ok(Some(commands));
        }

        Ok(None)
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
                if self.catalogue.fits(&achievements) {
                    return Some(achievements);
                }
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
        if !self.catalogue.fits(&achievements) {
            return None;
        }
        if list.arcade {
            self.arcade_list = Some(list);
        } else {
            self.regular_list = Some(list);
        }
        Some(achievements)
    }

    /// Count a packet the current key can't decrypt, and give up on the connection
    /// once `limit` have failed in a row.
    fn key_failure<T>(&mut self, limit: u32, error: SniffError) -> Result<Option<T>, SniffError> {
        self.key_failures += 1;
        if self.key_failures >= limit {
            return Err(error);
        }
        Ok(None)
    }

    #[instrument(skip_all, fields(len = data.len()))]
    fn receive_command(
        &mut self,
        data: Vec<u8>,
        direction: PacketDirection,
    ) -> Result<Option<GameCommand>, SniffError> {
        // The request's timestamp seeds the key search. The response follows within
        // ~400ms and the search covers +/-15s, so either would do.
        if direction == PacketDirection::Sent && self.sent_time.is_none() {
            self.sent_time = Some(self.timestamp_ms);
        }

        let Some(mut command) = GameCommand::try_new(data) else {
            return Ok(None);
        };

        // The login burst has short frames that are not protobufs, so a failure on
        // one says nothing about the key, and a success (an empty body always
        // parses) says just as little. Without a key there's nothing to do with
        // them, and with one they are at most passed along.
        let is_oracle = command.proto_data.len() >= MIN_ORACLE_BYTES;

        let key = match &self.key {
            None => {
                if !is_oracle {
                    return Ok(None);
                }

                // Shipped keys are tried newest first and the one that yields a
                // decodable message wins.
                let found_key = self
                    .initial_keys
                    .iter()
                    .rev()
                    .find(|k| parses_with(&command.proto_data, k))
                    .cloned();

                match found_key {
                    Some(key) => {
                        self.key = Some(Dispatch(key.clone()));
                        key
                    }
                    None => {
                        error!("No dispatch key found");
                        return self.key_failure(
                            MAX_KEY_FAILURES,
                            SniffError::InitialKeyMissing {
                                version: None,
                                saw_handshake: self.saw_handshake,
                            },
                        );
                    }
                }
            }
            Some(Dispatch(k)) if parses_with(&command.proto_data, k) => k.clone(),
            Some(Dispatch(_)) => {
                if !is_oracle {
                    return Ok(None);
                }

                if self.server_seed == 0 {
                    error!("Dispatch key stopped working, but no session seed was seen");
                    return self.key_failure(MAX_PENDING as u32, SniffError::SessionSeedMissing);
                }

                // The dispatch key stops decoding once the session key takes
                // over, which is what signals it is time to look for one.
                match self.bruteforce(&command.proto_data) {
                    Some(pad) => {
                        self.key = Some(Key::Session(pad.clone()));
                        pad
                    }
                    // A full buffer means every candidate had its best chance.
                    None if self.pending.len() >= MAX_PENDING => {
                        error!("Couldn't bruteforce the session key");
                        return Err(SniffError::BruteforceFailed);
                    }
                    None => return Ok(None),
                }
            }
            Some(Key::Session(k)) if parses_with(&command.proto_data, k) => k.clone(),
            Some(Key::Session(_)) => {
                if !is_oracle {
                    return Ok(None);
                }

                warn!("Session key failed to decrypt a command");
                return self.key_failure(MAX_KEY_FAILURES, SniffError::SessionKeyLost);
            }
        };
        self.key_failures = 0;

        command.apply_key(&key);

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

        Ok(Some(command))
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

#[cfg(test)]
mod tests;
