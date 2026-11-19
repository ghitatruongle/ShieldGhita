//! Track 2 (0.1.5-alpha2): in-repo fuzz harness for the DNS wire parsers.
//!
//! Audit note: every slice/index operation in `packet.rs` is already
//! bounds-checked (guards on `pos < len` before every byte read, `pos + n >
//! len` before every slice) — the audit found no unchecked indexing. This
//! harness verifies that empirically: mutated packets must never panic or
//! hang (the 128-iteration loop guards prevent pathological expansion).
//!
//! Long-running by design: `cargo test --release -- --ignored`

use crate::modules::dns::DnsBlocker;

/// Deterministic xorshift64* RNG — no external crate needed.
struct FuzzRng(u64);

impl FuzzRng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Build a structurally valid DNS wire query.
fn valid_query(name: &str, qtype: u16) -> Vec<u8> {
    let mut p = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0x00);
    p.extend_from_slice(&qtype.to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]); // IN
    p
}

/// Valid response with one A/AAAA answer (for extract_min_ttl / is_private_ip_record).
fn valid_response(name: &str, qtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut r = valid_query(name, qtype);
    r[2] = 0x81; // QR=1, RD=1
    r[3] = 0x80; // RA=1
    r[7] = 0x01; // ANCOUNT=1
    r.extend_from_slice(&[0xC0, 0x0C]); // name pointer to offset 0x0C
    r.extend_from_slice(&qtype.to_be_bytes());
    r.extend_from_slice(&[0x00, 0x01]); // IN
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x1E]); // TTL 30
    r.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    r.extend_from_slice(rdata);
    r
}

/// Valid response whose answer name is a self-referential pointer chain.
fn valid_response_pointer_chain(name: &str, qtype: u16, rdata: &[u8]) -> Vec<u8> {
    let mut r = valid_response(name, qtype, rdata);
    r.extend_from_slice(&[0xC0, 0x0C]); // second answer: pointer name
    r.extend_from_slice(&1u16.to_be_bytes());
    r.extend_from_slice(&[0x00, 0x01]);
    r.extend_from_slice(&[0x00, 0x00, 0x00, 0x0A]);
    r.extend_from_slice(&[0x00, 0x04]);
    r.extend_from_slice(&[1, 2, 3, 4]);
    r
}

/// Seeds: valid queries/responses plus the nastiest historical shapes
/// (self-looping pointers, 127-label names, sinkhole responses, unicode).
fn seeds() -> Vec<Vec<u8>> {
    vec![
        valid_query("example.com", 1),
        valid_query("a.b.c.d.e.f.example.com", 28),
        valid_query("x", 16), // TXT
        valid_query("empty-name", 1),
        valid_response("example.com", 1, &[10, 0, 0, 1]),
        valid_response(
            "example.com",
            28,
            &[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        ),
        valid_response_pointer_chain("example.com", 1, &[10, 0, 0, 1]),
        DnsBlocker::build_sinkhole_a_record(&valid_query("ads.example.com", 1), [0, 0, 0, 0])
            .unwrap(),
        {
            // Name hitting the 128-iteration loop guard boundary.
            let mut p = vec![
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ];
            for _ in 0..127 {
                p.push(1);
                p.push(b'z');
            }
            p.push(0x00);
            p.extend_from_slice(&1u16.to_be_bytes());
            p.extend_from_slice(&[0x00, 0x01]);
            p
        },
    ]
}

/// Mutations: bit-flip, overwrite, truncate, insert, count-field chaos,
/// label-length overflow and compression-pointer injection.
fn mutate(pkt: &[u8], rng: &mut FuzzRng) -> Vec<u8> {
    let mut m = pkt.to_vec();
    if m.is_empty() {
        m.push(0x00);
    }
    match rng.below(8) {
        0 => {
            let i = rng.below(m.len());
            m[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(m.len());
            m[i] = rng.next() as u8;
        }
        2 => {
            let n = rng.below(m.len()) + 1;
            m.truncate(n);
        }
        3 => {
            let i = rng.below(m.len());
            m.insert(i, rng.next() as u8);
            m.truncate(512);
        }
        4 => {
            // QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT chaos.
            let i = 4 + rng.below(8);
            if i < m.len() {
                m[i] = 0xFF;
            }
        }
        5 => {
            // Label length byte overflow (including pointer range).
            if m.len() > 13 {
                let i = 12 + rng.below(m.len() - 12);
                m[i] = 0xFF;
            } else {
                let i = rng.below(m.len());
                m[i] ^= 0xFF;
            }
        }
        6 => {
            // Compression pointer anywhere after the header.
            if m.len() > 14 {
                let i = 12 + rng.below(m.len() - 14);
                m[i] = 0xC0;
                m[i + 1] = 0x0C;
            } else {
                let i = rng.below(m.len());
                m[i] ^= 0xFF;
            }
        }
        _ => {
            let i = rng.below(m.len());
            let j = rng.below(m.len());
            m.swap(i, j);
        }
    }
    m
}

fn build_corpus() -> Vec<Vec<u8>> {
    let mut rng = FuzzRng(0x5EED_0226u64); // fixed seed → deterministic
    let base_seeds = seeds();
    let mut corpus = Vec::new();
    for seed in &base_seeds {
        corpus.push(seed.clone());
        for k in 0..20 {
            let mut v = seed.clone();
            for _ in 0..=k % 3 {
                v = mutate(&v, &mut rng);
            }
            corpus.push(v);
        }
        for _ in 0..20 {
            corpus.push(mutate(seed, &mut rng));
        }
    }
    corpus
}

#[test]
#[ignore] // long-running: cargo test --release -- --ignored
fn fuzz_dns_wire_parsers_no_panic() {
    // Fixed default seed keeps runs deterministic; SHIELD_FUZZ_SEED varies it
    // for the longer manual gate (varied-seed mutation runs).
    let seed: u64 = std::env::var("SHIELD_FUZZ_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x5EED_0226);
    let mut rng = FuzzRng(seed);
    let corpus = build_corpus();
    assert!(
        corpus.len() >= 200,
        "corpus must have >=200 entries, got {}",
        corpus.len()
    );
    for _round in 0..50_000u32 {
        let pkt = corpus[rng.below(corpus.len())].clone();
        let pkt = mutate(&pkt, &mut rng);
        // Parsers — pure functions of the bytes, must never panic or hang.
        let _ = DnsBlocker::parse_query_info(&pkt);
        let _ = DnsBlocker::response_matches_query(&pkt, &corpus[0]);
        let _ = DnsBlocker::extract_min_ttl(&pkt);
        let _ = DnsBlocker::is_private_ip_record(&pkt);
        let _ = DnsBlocker::build_nxdomain(&pkt);
        let _ = DnsBlocker::build_sinkhole_a_record(&pkt, [0, 0, 0, 0]);
        let _ = DnsBlocker::build_sinkhole_aaaa_record(&pkt, [0u8; 16]);
        let _ = DnsBlocker::build_servfail(&pkt);
    }
}
