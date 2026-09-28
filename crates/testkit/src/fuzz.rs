//! Inputs for testing that a parser survives what it is given.
//!
//! [`each_variant`] takes inputs that are valid, and calls the check with them
//! and with a great many that are not: every prefix, every byte replaced by an
//! edge value, and then random changes, some of them chained. It is a small
//! fuzzer that runs inside `cargo test`: it does not follow which code an input
//! reaches, as libFuzzer does, so it finds less, but it needs no tools and runs
//! wherever the tests do.
//!
//! The inputs are the same on every run, so a failure can be repeated. A panic
//! in the check is reported with the input that caused it, in hex, ready to be
//! made a test of its own. `GATIR_FUZZ_SCALE=100` tries a hundred times as
//! many random inputs, for a longer search.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

/// How long one call of a check may take before it counts as a failure: an
/// input that makes a parser this slow is a way to hold a task for ever.
const SLOWEST: Duration = Duration::from_secs(2);

/// Values that parsers tend to mishandle: zero, the edges of a signed and an
/// unsigned byte, and the bytes that end lines.
const EDGE_BYTES: [u8; 9] = [0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, b'\n', b'\r', b' '];

/// Pieces that give text parsers something to work with.
const TOKENS: &[&[u8]] = &[
    b";",
    b":",
    b"[",
    b"]",
    b"/",
    b",",
    b"=",
    b"\"",
    b"*",
    b"@",
    b"%",
    b"\r\n",
    b"\0",
    b"0",
    b"65535",
    b"65536",
    b"-1",
    b"99999999999999999999",
    b"::",
    b"..",
    b"0.0.0.0/33",
    b"\xff\xff",
    b"\xc3\xa9",
    b"\xf0\x9f\x98\x80",
    b"\xc3",
];

/// A small deterministic random generator (xorshift64*).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        // Zero would stay zero for ever.
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    /// A number below `bound`, or 0 if there is no such number.
    pub fn below(&mut self, bound: usize) -> usize {
        if bound == 0 {
            0
        } else {
            (self.next_u64() % bound as u64) as usize
        }
    }

    pub fn byte(&mut self) -> u8 {
        (self.next_u64() >> 24) as u8
    }
}

/// Changes `input` in one random way.
pub fn mutate(rng: &mut Rng, input: &mut Vec<u8>) {
    if input.is_empty() {
        let count = 1 + rng.below(4);
        input.extend((0..count).map(|_| rng.byte()));
        return;
    }
    let at = rng.below(input.len());
    match rng.below(9) {
        0 => input[at] ^= 1 << rng.below(8),
        1 => input[at] = EDGE_BYTES[rng.below(EDGE_BYTES.len())],
        2 => input[at] = rng.byte(),
        3 => input.insert(at, rng.byte()),
        4 => {
            let end = (at + 1 + rng.below(8)).min(input.len());
            input.drain(at..end);
        }
        5 => {
            // Repeats a piece, which is how a parser is made to see the same
            // field twice, or a list that is longer than it planned for.
            let end = (at + 1 + rng.below(16)).min(input.len());
            let piece = input[at..end].to_vec();
            input.splice(at..at, piece);
        }
        6 => {
            let token = TOKENS[rng.below(TOKENS.len())];
            input.splice(at..at, token.iter().copied());
        }
        7 => input.truncate(at),
        _ => {
            // A length or an offset that is far too big, in either byte order.
            const BIG: [&[u8]; 6] = [
                &[0xff, 0xff],
                &[0xff, 0xff, 0xff, 0xff],
                &[0x7f, 0xff, 0xff, 0xff],
                &[0x80, 0x00, 0x00, 0x00],
                &[0x00, 0x00, 0x00, 0x80],
                &[0xff, 0xff, 0xff, 0x7f],
            ];
            let value = BIG[rng.below(BIG.len())];
            for (place, byte) in input[at..].iter_mut().zip(value) {
                *place = *byte;
            }
        }
    }
}

/// The multiplier that `GATIR_FUZZ_SCALE` asks for: 1 if it says nothing usable.
fn scale(setting: Option<&str>) -> usize {
    setting
        .and_then(|text| text.trim().parse::<usize>().ok())
        .filter(|scale| *scale > 0)
        .unwrap_or(1)
}

/// The most places in a seed where every prefix and every edge value is tried,
/// so that a long seed does not take minutes. Its places are spread evenly.
const MOST_PLACES: usize = 512;

/// How far apart the places are in a seed of `length` bytes: 1 for all of them,
/// which is what a longer search (`scale` above 1) asks for.
fn spacing(length: usize, scale: usize) -> usize {
    if scale > 1 {
        1
    } else {
        length.div_ceil(MOST_PLACES).max(1)
    }
}

/// Calls `check` with each seed, every prefix of each, each seed with any one
/// byte replaced by an edge value, and then `rounds` random variations. The
/// check panics if the code under test misbehaves; that is reported with the
/// input. A seed of more than 512 bytes has its prefixes and edge values tried
/// at 512 places, evenly spread.
pub fn each_variant(seeds: &[&[u8]], rounds: usize, mut check: impl FnMut(&[u8])) {
    let scale = scale(std::env::var("GATIR_FUZZ_SCALE").ok().as_deref());
    let mut tried = 0usize;
    let mut run = |input: &[u8]| {
        tried += 1;
        let started = Instant::now();
        let outcome = catch_unwind(AssertUnwindSafe(|| check(input)));
        let elapsed = started.elapsed();
        let complaint = match outcome {
            Err(payload) => Some(format!("made the code panic: {}", describe(&*payload))),
            Ok(()) if elapsed > SLOWEST => Some(format!(
                "took {elapsed:?}, more than the {SLOWEST:?} that one call may take"
            )),
            Ok(()) => None,
        };
        if let Some(complaint) = complaint {
            panic!(
                "input number {tried} {complaint}\n  {} bytes, in hex: {}\n  as text: {:?}",
                input.len(),
                hex::encode(input),
                String::from_utf8_lossy(input)
            );
        }
    };

    for seed in seeds {
        run(seed);
        let spacing = spacing(seed.len(), scale);
        for length in (0..seed.len()).step_by(spacing) {
            run(&seed[..length]);
        }
        for at in (0..seed.len()).step_by(spacing) {
            for edge in EDGE_BYTES {
                let mut input = seed.to_vec();
                input[at] = edge;
                run(&input);
            }
        }
    }

    if seeds.is_empty() {
        return;
    }
    let mut rng = Rng::new(0x9e37_79b9_7f4a_7c15);
    let mut input = seeds[0].to_vec();
    for _ in 0..rounds * scale {
        // One in four goes on from the last input, so that changes pile up.
        if rng.below(4) != 0 {
            input = seeds[rng.below(seeds.len())].to_vec();
        }
        for _ in 0..1 + rng.below(3) {
            mutate(&mut rng, &mut input);
        }
        // Text that a parser is given is text.
        run(&input);
    }
}

/// Like [`each_variant`], for parsers of text: what is not UTF-8 becomes the
/// replacement character, which is text a parser can meet as well.
pub fn each_text_variant(seeds: &[&str], rounds: usize, mut check: impl FnMut(&str)) {
    let seeds: Vec<&[u8]> = seeds.iter().map(|seed| seed.as_bytes()).collect();
    each_variant(&seeds, rounds, |bytes| {
        check(&String::from_utf8_lossy(bytes));
    });
}

fn describe(payload: &(dyn std::any::Any + Send)) -> String {
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
        })
        .unwrap_or_else(|| "(no message)".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn collect(seeds: &[&[u8]], rounds: usize) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        each_variant(seeds, rounds, |input| all.push(input.to_vec()));
        all
    }

    #[test]
    fn the_same_inputs_come_every_time() {
        assert_eq!(
            collect(&[b"abc", b"xyz"], 200),
            collect(&[b"abc", b"xyz"], 200)
        );
    }

    #[test]
    fn the_seeds_their_prefixes_and_their_edge_bytes_are_all_tried() {
        let all = collect(&[b"abc"], 0);
        for expected in [&b"abc"[..], b"", b"a", b"ab", b"\0bc", b"a\xffc", b"ab\r"] {
            assert!(all.contains(&expected.to_vec()), "{expected:?}");
        }
        // The seed, its 3 prefixes shorter than it, and 3 places by 9 values.
        assert_eq!(all.len(), 1 + 3 + 3 * EDGE_BYTES.len());
    }

    #[test]
    fn the_random_variations_are_as_many_as_asked_for() {
        assert_eq!(
            collect(&[b"abc"], 50).len(),
            1 + 3 + 3 * EDGE_BYTES.len() + 50
        );
        assert!(collect(&[], 50).is_empty());
    }

    #[test]
    fn the_variations_grow_shrink_and_change() {
        let all = collect(&[b"some seed of a moderate length"], 2000);
        let seed_len = b"some seed of a moderate length".len();
        assert!(all.iter().any(|input| input.len() > seed_len));
        assert!(all.iter().any(|input| input.len() < seed_len));
        assert!(all.iter().any(|input| input.is_empty()));
        assert!(
            all.iter()
                .any(|input| input.windows(2).any(|w| w == b"\xff\xff"))
        );
    }

    #[test]
    fn a_panic_is_reported_with_the_input_that_caused_it() {
        let outcome = catch_unwind(|| {
            each_variant(&[b"boom"], 10, |input| {
                assert_ne!(input, b"bo", "not this one")
            });
        });
        let message = describe(&*outcome.expect_err("the check panicked"));
        assert!(message.contains("626f"), "{message}");
        assert!(message.contains("made the code panic"), "{message}");
        assert!(message.contains("not this one"), "{message}");
    }

    #[test]
    fn the_scale_is_one_unless_a_number_says_otherwise() {
        assert_eq!(scale(None), 1);
        assert_eq!(scale(Some("")), 1);
        assert_eq!(scale(Some("many")), 1);
        assert_eq!(scale(Some("0")), 1);
        assert_eq!(scale(Some(" 25 ")), 25);
    }

    #[test]
    fn a_long_seed_is_tried_at_places_spread_over_it() {
        let seed = vec![b'x'; 5_000];
        let all = collect(&[&seed], 0);
        // 5000 bytes, 10 apart: 500 prefixes and 500 places by 9 values.
        assert_eq!(all.len(), 1 + 500 + 500 * EDGE_BYTES.len());
        // The last bytes are reached, and so is the first.
        assert!(all.iter().any(|input| input.len() == 4_990));
        assert!(all.iter().any(|input| input.first() == Some(&0)));
    }

    #[test]
    fn places_are_all_of_them_for_a_short_seed_or_a_longer_search() {
        assert_eq!(spacing(0, 1), 1);
        assert_eq!(spacing(512, 1), 1);
        assert_eq!(spacing(513, 1), 2);
        assert_eq!(spacing(2_200, 1), 5);
        assert_eq!(spacing(100_000, 2), 1);
    }

    #[test]
    fn text_variants_are_text() {
        let mut count = 0;
        each_text_variant(&["PROXY a:1"], 100, |text| {
            count += 1;
            let _ = text.len();
        });
        assert!(count > 100);
    }
}
