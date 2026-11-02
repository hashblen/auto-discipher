use super::*;

/// XORs to itself, so a body with no valid protobuf tag stays invalid under it.
fn key() -> Vec<u8> {
    vec![0; 16]
}

fn sniffer() -> GameSniffer {
    GameSniffer::new().set_initial_keys(vec![key()])
}

fn command(body: &[u8]) -> Vec<u8> {
    let mut data = vec![0x01, 0x23, 0x45, 0x67, 0, 1, 0, 0];
    data.extend_from_slice(&(body.len() as u32).to_be_bytes());
    data.extend_from_slice(body);
    data.extend_from_slice(&[0x89, 0xAB, 0xCD, 0xEF]);
    data
}

fn good() -> Vec<u8> {
    // Field 1, varint, over and over.
    [0x08, 0x01].repeat(MIN_ORACLE_BYTES)
}

fn bad() -> Vec<u8> {
    vec![0xFF; MIN_ORACLE_BYTES]
}

fn receive(sniffer: &mut GameSniffer, body: &[u8]) -> Result<bool, SniffError> {
    sniffer
        .receive_command(command(body), PacketDirection::Received)
        .map(|command| command.is_some())
}

/// An Ethernet frame holding a UDP packet to the game's first port.
fn udp_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    etherparse::PacketBuilder::ethernet2([0; 6], [0; 6])
        .ipv4([1, 1, 1, 1], [2, 2, 2, 2], 64)
        .udp(5000, PORTS[0])
        .write(&mut frame, payload)
        .unwrap();
    frame
}

#[test]
fn malformed_packets_are_ignored() {
    let mut sniffer = GameSniffer::new();
    // Too short for a control code, for a KCP header, and with a KCP segment
    // that claims more content than there is.
    let mut lying = vec![0; 28];
    lying[24..28].copy_from_slice(&1000u32.to_le_bytes());
    for payload in [&[1u8, 2][..], &[0; 26][..], &lying[..]] {
        assert!(sniffer.receive_packet(udp_frame(payload)).is_ok());
    }
}

#[test]
fn short_and_empty_bodies_say_nothing_about_the_key() {
    let mut sniffer = sniffer();

    // An empty body parses under any key, and must not pick one.
    assert_eq!(receive(&mut sniffer, &[]), Ok(false));
    assert_eq!(sniffer.key_state(), KeyState::None);

    // Short frames that aren't protobufs never count against one.
    for _ in 0..MAX_PENDING * 2 {
        assert_eq!(receive(&mut sniffer, &[0xFF; 8]), Ok(false));
    }
    assert_eq!(sniffer.key_failures, 0);

    sniffer.key = Some(Key::Session(key()));
    for _ in 0..MAX_PENDING * 2 {
        assert_eq!(receive(&mut sniffer, &[0xFF; 8]), Ok(false));
    }
    assert_eq!(sniffer.key_state(), KeyState::Session);
    assert_eq!(sniffer.key_failures, 0);
}

#[test]
fn no_fitting_key_fails_after_a_few_long_packets() {
    let mut sniffer = sniffer();
    for _ in 1..MAX_KEY_FAILURES {
        assert_eq!(receive(&mut sniffer, &bad()), Ok(false));
    }
    assert_eq!(
        receive(&mut sniffer, &bad()),
        Err(SniffError::InitialKeyMissing {
            version: None,
            saw_handshake: false,
        })
    );
}

#[test]
fn no_seed_fails_once_the_dispatch_key_has_kept_failing() {
    let mut sniffer = sniffer();
    assert_eq!(receive(&mut sniffer, &good()), Ok(true));
    for _ in 1..MAX_PENDING {
        assert_eq!(receive(&mut sniffer, &bad()), Ok(false));
    }
    assert_eq!(receive(&mut sniffer, &bad()), Err(SniffError::SessionSeedMissing));
}

#[test]
fn a_wrong_seed_fails_once_the_search_had_every_chance() {
    let mut sniffer = sniffer();
    assert_eq!(receive(&mut sniffer, &good()), Ok(true));
    sniffer.server_seed = 1;
    sniffer.sent_time = Some(1_800_000_000_000);
    for _ in 1..MAX_PENDING {
        assert_eq!(receive(&mut sniffer, &bad()), Ok(false));
    }
    assert_eq!(receive(&mut sniffer, &bad()), Err(SniffError::BruteforceFailed));
}

#[test]
fn a_session_key_that_keeps_failing_is_lost() {
    let mut sniffer = sniffer();
    sniffer.key = Some(Key::Session(key()));
    for _ in 1..MAX_KEY_FAILURES {
        assert_eq!(receive(&mut sniffer, &bad()), Ok(false));
    }
    assert_eq!(receive(&mut sniffer, &good()), Ok(true));
    assert_eq!(sniffer.key_failures, 0);
    for _ in 1..MAX_KEY_FAILURES {
        assert_eq!(receive(&mut sniffer, &bad()), Ok(false));
    }
    assert_eq!(receive(&mut sniffer, &bad()), Err(SniffError::SessionKeyLost));
}

#[test]
fn a_reset_keeps_the_initial_keys() {
    let mut sniffer = sniffer();
    assert_eq!(receive(&mut sniffer, &good()), Ok(true));
    sniffer.server_seed = 1;
    sniffer.reset();
    assert_eq!(sniffer.key_state(), KeyState::None);
    assert_eq!(sniffer.server_seed, 0);
    assert_eq!(receive(&mut sniffer, &good()), Ok(true));
}
