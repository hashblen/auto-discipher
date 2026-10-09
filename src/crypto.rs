use protobuf::Message;
use rand_mt::Mt64;
use tracing::{debug, instrument, trace, warn};

use crate::bytes_as_hex;
use crate::cs_rand::Random;
use crate::gen::protos::Unk;

#[instrument(skip_all)]
pub fn xor_decrypt(key: &[u8], encrypted: &mut [u8]) {
    trace!(data = bytes_as_hex(encrypted), "before decryption");

    for i in 0..encrypted.len() {
        encrypted[i] ^= key[i % key.len()];
    }

    trace!(data = bytes_as_hex(encrypted), "after decryption");
}

pub fn new_key_from_seed(seed: u64) -> Vec<u8> {
    // mersenne twister generator, seeded straight from the seed
    let mut gen = Mt64::new(seed);

    let mut key = Vec::with_capacity(512);
    for _ in 0..512 {
        for b in gen.next_u64().to_be_bytes() {
            key.push(b);
        }
    }
    key
}

/// The shortest packet worth using as an oracle. The login burst has several
/// 6-20 byte frames that are not protobufs and never decode however good the key
/// is, so they make a correct key look wrong; they are also the weakest oracle.
pub const MIN_ORACLE_BYTES: usize = 64;

/// How far either side of the observed clock to look, in seconds.
const SEARCH_WINDOW_SECONDS: i64 = 15;

/// Reproduces the game's clock path bit-for-bit.
///
/// The float arithmetic is deliberate. ticks is ~6.4e17, well past 2^53, so the
/// game's CVTSI2SD rounds it to a multiple of 128 before the multiply, and that
/// rounding is part of the value we need; exact integer arithmetic does not
/// agree. The narrowing keeps only the low half, as the game's int32(int64(..))
/// does, which is why a whole second is the finest step worth searching.
fn derive_seed(ms: u64) -> i32 {
    let ticks = (ms.wrapping_mul(10_000).wrapping_add(621355968000000000)) & 0x3FFF_FFFF_FFFF_FFFF;
    ((ticks as f64 * 1e-7) as i64) as i32
}

/// The key for one clock value.
fn guess(ms: u64, server_seed: u64) -> Vec<u8> {
    let computed_seed = derive_seed(ms);
    let mut generator = Random::seeded(computed_seed);
    let client_seed = (computed_seed as u32 as u64) | ((generator.next_int() as u32 as u64) << 32);

    new_key_from_seed(client_seed ^ server_seed)
}

/// Whether `body` decodes once the pad is applied.
///
/// This is the only test available without the game's protos: a valid protobuf
/// message is what the pad has to produce. Noise survives it ~1.9% of the time
/// at 8 bytes and 0 of 8000 at 356, which is why a candidate is only accepted on
/// a quorum of buffered packets rather than one.
pub fn parses_with(body: &[u8], pad: &[u8]) -> bool {
    let mut clone = body.to_vec();
    xor_decrypt(pad, &mut clone);
    Unk::parse_from_bytes(&clone).is_ok()
}

/// Recover the session key from the server's seed and the clock the request went
/// out on, accepting a candidate only when a quorum of the buffered packets
/// agrees.
pub fn bruteforce(sent_ms: u64, server_seed: u64, bodies: &[Vec<u8>]) -> Option<Vec<u8>> {
    debug!("Running bruteforce loop.");

    let base = (sent_ms / 1000) as i64;
    // Screen on the longest packet first: it discards almost every candidate for
    // the cost of one parse.
    let strongest = bodies.iter().max_by_key(|body| body.len())?;

    for i in 0..=SEARCH_WINDOW_SECONDS * 2 {
        let delta = if i % 2 != 0 { -(i + 1) / 2 } else { i / 2 };
        let seconds = base + delta;
        if seconds < 0 {
            continue;
        }

        let pad = guess((seconds as u64) * 1000, server_seed);
        if !parses_with(strongest, &pad) {
            continue;
        }
        let quorum = match bodies.len() {
            0..=3 => bodies.len(),
            n => n - 2,
        };
        if bodies.iter().filter(|body| parses_with(body, &pad)).count() < quorum {
            continue;
        }

        debug!(seconds, "found encryption key seed");
        return Some(pad);
    }

    warn!("Unable to find the encryption key seed.");
    None
}

#[cfg(test)]
mod tests {
    /// The key derivation has to agree with the Go implementation bit for bit:
    /// it is the one piece of arithmetic that cannot be checked against a
    /// fixture, only against the other language.
    #[test]
    fn matches_go() {
        let key: String = super::guess(1791463462000, 12673862989460770854)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            key.starts_with(
                "2ce6b5989fd5e48969e36f7fe795cfcaf08f9e7f385e7503ec0149f3165724b000a41c51e9"
            ),
            "{key}"
        );
    }
}
