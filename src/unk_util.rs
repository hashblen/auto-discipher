use std::collections::{BTreeSet, HashMap, HashSet};

use base64::prelude::{BASE64_STANDARD, BASE64_STANDARD_NO_PAD};
use base64::Engine;
use protobuf::Message;
use protobuf::UnknownValueRef::*;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

use crate::gen::protos::Unk;

#[derive(Default, Debug, Clone, Copy)]
pub struct Achievement {
    pub id: u32,
    pub progress: u32,
    /// `finished` in the regular list, `completed` in the arcade one. The arcade
    /// list's `unlocked` is set on every entry, so it says nothing about whether
    /// the achievement was earned.
    pub completed: bool,
}

/// Find `server_rand_key` by RSA round-trip: a real blob decrypts to exactly 8
/// bytes, while the packet's other blob, `sign`, decrypts to 82. Exactly one
/// packet in 140 matches, and the count has to be exactly one because a wrong
/// blob lands on some 8-byte length often enough to matter.
pub fn matches_get_player_token_rsp(data: &[u8], rsa_keys: &[RsaPrivateKey]) -> Option<u64> {
    let msg = Unk::parse_from_bytes(data).ok()?;
    let mut seeds = Vec::new();

    for field in msg.unknown_fields().iter().map(|(_, field)| field) {
        let LengthDelimited(blob) = field else {
            continue;
        };
        let Some(blob) = decode_base64(blob) else {
            continue;
        };
        for key in rsa_keys {
            if let Ok(plain) = key.decrypt(Pkcs1v15Encrypt, &blob) {
                if let Ok(seed) = <[u8; 8]>::try_from(plain.as_slice()) {
                    seeds.push(u64::from_le_bytes(seed));
                }
            }
        }
    }

    (seeds.len() == 1).then(|| seeds[0])
}

fn decode_base64(bytes: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(bytes).ok()?;
    BASE64_STANDARD
        .decode(text)
        .or_else(|_| BASE64_STANDARD_NO_PAD.decode(text.trim_end_matches('=')))
        .ok()
}

/// Constraints on what may be called an achievement list. Swept across every
/// response in two 3.2.0 captures these admit exactly the two real packets.
///
/// The entry floor is strict on purpose: a 37-entry list matched the catalogue
/// at 81% and a 117-entry one at 97%, so below certainty is not evidence. The
/// cost is that a patch adding achievements before stardb updates stops
/// detection rather than returning a partial answer, which is the safer failure.
const MIN_ENTRIES: usize = 40;

/// Constants in the descriptor table are all small; unconstrained voting returns
/// arbitrary large ones such as 10773171, which are always spurious.
const MAX_XOR_KEY: u64 = 1 << 16;

/// Both lists sit two wrappers deep. The search descends further only so that it
/// does not depend on that.
const MAX_DEPTH: usize = 6;

/// The achievement ids, plus the arcade subset that tells the two ZZZ
/// achievement packets apart.
///
/// Ids are opaque integers on the wire so they cannot be recognised by shape,
/// but the valid ones are known.
#[derive(Default)]
pub struct Catalogue {
    all: HashSet<u32>,
    arcade: HashSet<u32>,
}

impl Catalogue {
    /// `arcade` marks the ids that only ever appear in the arcade list.
    pub fn new(ids: impl IntoIterator<Item = (u32, bool)>) -> Self {
        let mut catalogue = Self::default();
        for (id, arcade) in ids {
            catalogue.all.insert(id);
            if arcade {
                catalogue.arcade.insert(id);
            }
        }
        catalogue
    }

    pub fn len(&self) -> usize {
        self.all.len()
    }

    pub fn arcade_len(&self) -> usize {
        self.arcade.len()
    }

    pub fn is_empty(&self) -> bool {
        self.all.is_empty()
    }
}

/// A located achievement list: everything needed to read one back out of the
/// same packet, or of any later repeat of it.
#[derive(Clone, Debug)]
pub struct AchievementList {
    /// Tag chain from the packet root to the repeated field's parent.
    pub path: Vec<u32>,
    pub list_tag: u32,
    pub id_tag: u32,
    /// Constant the ids are stored under; zero for the regular list.
    pub xor_key: u64,
    /// True when every id is an arcade id, which separates the two packets.
    pub arcade: bool,
    pub entries: usize,
}

impl AchievementList {
    pub fn describe(&self) -> String {
        let path: Vec<String> = self.path.iter().map(|tag| format!("f{tag}")).collect();
        format!(
            "{}.f{} x{}, id field f{} xor {}",
            path.join("."),
            self.list_tag,
            self.entries,
            self.id_tag,
            self.xor_key
        )
    }
}

/// The tags each list carries progress and completion under. The numbers are what
/// the packets carry; the names are ours, as neither message appears in the
/// upstream descriptor table. A zero tag is one that list does not have.
struct ElemTags {
    progress: u32,
    completed: u32,
}

const REGULAR_ELEM: ElemTags = ElemTags {
    progress: 2,
    completed: 4,
};

const ARCADE_ELEM: ElemTags = ElemTags {
    progress: 14,
    completed: 15,
};

/// Search a response for an achievement list. Both ZZZ lists are repeated
/// submessages inside a larger response, the regular one three levels down
/// (GetMiscDataScRsp.15 -> 1067 -> 10). The walk descends through single
/// occurrences too, so the deep one is reached.
pub fn find_achievement_list(body: &[u8], catalogue: &Catalogue) -> Option<AchievementList> {
    let mut best = None;
    walk(body, &mut Vec::new(), 0, catalogue, &mut best);
    best
}

fn walk(
    body: &[u8],
    path: &mut Vec<u32>,
    depth: usize,
    catalogue: &Catalogue,
    best: &mut Option<AchievementList>,
) {
    if depth > MAX_DEPTH {
        return;
    }
    let Ok(msg) = Unk::parse_from_bytes(body) else {
        return;
    };

    // Group the length-delimited fields by tag so repeats are seen together.
    let mut subs: HashMap<u32, Vec<&[u8]>> = HashMap::new();
    for (tag, field) in msg.unknown_fields().iter() {
        if let LengthDelimited(bytes) = field {
            subs.entry(tag).or_default().push(bytes);
        }
    }

    for (tag, bodies) in subs {
        if bodies.len() >= MIN_ENTRIES {
            if let Some(found) = check_list(&bodies, catalogue) {
                let candidate = AchievementList {
                    path: path.clone(),
                    list_tag: tag,
                    ..found
                };
                if better(&candidate, best) {
                    *best = Some(candidate);
                }
            }
        }
        for sub in bodies {
            path.push(tag);
            walk(sub, path, depth + 1, catalogue, best);
            path.pop();
        }
    }
}

fn better(candidate: &AchievementList, best: &Option<AchievementList>) -> bool {
    match best {
        Some(best) => candidate.entries > best.entries,
        None => true,
    }
}

fn check_list(elements: &[&[u8]], catalogue: &Catalogue) -> Option<AchievementList> {
    let mut values: HashMap<u32, Vec<u64>> = HashMap::new();
    for element in elements {
        let msg = Unk::parse_from_bytes(element).ok()?;
        for (tag, field) in msg.unknown_fields().iter() {
            if let Varint(value) = field {
                values.entry(tag).or_default().push(value);
            }
        }
    }

    let mut best: Option<AchievementList> = None;
    for (id_tag, observed) in &values {
        if observed.len() < MIN_ENTRIES {
            continue;
        }
        let Some(xor_key) = find_xor_key(observed, &catalogue.all) else {
            continue;
        };

        let ids: Vec<u32> = observed.iter().map(|v| (v ^ xor_key) as u32).collect();
        // Ids are unique. This is what rejects the largest false positive: a
        // 104-entry list matched only 19 distinct ids, so it passed on count.
        if ids.iter().collect::<HashSet<_>>().len() != ids.len() {
            continue;
        }

        let candidate = AchievementList {
            path: Vec::new(),
            list_tag: 0,
            id_tag: *id_tag,
            xor_key,
            arcade: ids.iter().all(|id| catalogue.arcade.contains(id)),
            entries: elements.len(),
        };
        if better(&candidate, &best) {
            best = Some(candidate);
        }
    }
    best
}

/// Recover the constant applied to a set of observed values: the key below
/// [`MAX_XOR_KEY`] that maps every one of them onto a catalogue id.
///
/// Every value has to land on an id, so the first value alone narrows the
/// candidates to one per id, and each is then checked against the rest. That is
/// linear in the list, where voting over every (observed, id) pair and scoring
/// each vote was quadratic: seconds per packet on an 800-entry list, during which
/// the capture backs up.
///
/// Among keys that fit, the one landing on the most distinct ids wins, because
/// the catalogue is dense enough that low-bit keys come close -- key 4 matches
/// 57 of 65 entries while key 0 matches all 65.
fn find_xor_key(observed: &[u64], ids: &HashSet<u32>) -> Option<u64> {
    let first = *observed.first()?;
    // Sorted so that a tie goes the same way on every run.
    let candidates: BTreeSet<u64> = ids
        .iter()
        .map(|id| first ^ u64::from(*id))
        .filter(|key| *key < MAX_XOR_KEY)
        .collect();

    let mut best: Option<(u64, usize)> = None;
    for key in candidates {
        let mut distinct: HashSet<u32> = HashSet::new();
        let all_match = observed.iter().all(|observed| {
            let id = (observed ^ key) as u32;
            distinct.insert(id);
            ids.contains(&id)
        });
        if all_match && best.map_or(true, |(_, most)| distinct.len() > most) {
            best = Some((key, distinct.len()));
        }
    }
    best.map(|(key, _)| key)
}

/// Read a list back out of a packet using a layout found earlier.
pub fn decode_list(body: &[u8], list: &AchievementList) -> Option<Vec<Achievement>> {
    let mut current = body.to_vec();
    for tag in &list.path {
        current = step(&current, *tag)?;
    }

    let msg = Unk::parse_from_bytes(&current).ok()?;
    let elements: Vec<Vec<u8>> = msg
        .unknown_fields()
        .iter()
        .filter(|(tag, _)| *tag == list.list_tag)
        .map(|(_, field)| match field {
            LengthDelimited(bytes) => Some(bytes.to_vec()),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if elements.len() < MIN_ENTRIES {
        return None;
    }

    let tags = if list.arcade {
        &ARCADE_ELEM
    } else {
        &REGULAR_ELEM
    };

    let mut achievements = Vec::with_capacity(elements.len());
    for element in &elements {
        let msg = Unk::parse_from_bytes(element).ok()?;
        let mut achievement = Achievement::default();
        for (tag, field) in msg.unknown_fields().iter() {
            let Varint(value) = field else { continue };
            if tag == list.id_tag {
                achievement.id = (value ^ list.xor_key) as u32;
            } else if tag == tags.progress {
                achievement.progress = value as u32;
            } else if tag == tags.completed {
                achievement.completed = value != 0;
            }
        }
        achievements.push(achievement);
    }

    Some(achievements)
}

/// Descend one tag. The parse owns its bytes, so each step copies.
fn step(body: &[u8], tag: u32) -> Option<Vec<u8>> {
    let msg = Unk::parse_from_bytes(body).ok()?;
    match msg.unknown_fields().get(tag)? {
        LengthDelimited(bytes) => Some(bytes.to_vec()),
        _ => None,
    }
}
