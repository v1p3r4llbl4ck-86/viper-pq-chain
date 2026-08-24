// SPDX-License-Identifier: BUSL-1.1
//! Integration test for the PQ provider activation on outbound HTTPS.
//!
//! What this test proves: after `pqcd::tls::init_pq_provider()` is
//! called, a default `reqwest::Client` produces a TLS ClientHello whose
//! `supported_groups` extension contains X25519MLKEM768 (named group
//! codepoint 0x11EC). Without the call, the same Client offers only
//! classical groups.
//!
//! Implementation note: we cannot reach into reqwest to extract the
//! ClientConfig directly. Instead, we spin a TCP listener that captures
//! the first ~512 bytes (the TLS record + ClientHello) and parses the
//! supported_groups extension. The reqwest call itself will fail the
//! handshake (no real cert), but it sends the ClientHello first — which
//! is all this test needs.

#![cfg(feature = "hybrid-kem-tls")]

use std::io::Read;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// IANA-assigned codepoint for X25519MLKEM768 hybrid PQ group
/// (draft-ietf-tls-ecdhe-mlkem-04, codepoint 0x11EC = 4588).
const NAMED_GROUP_X25519_MLKEM768: u16 = 0x11EC;

/// Parse the supported_groups extension from a TLS 1.3 ClientHello byte
/// buffer. Returns the list of named group codepoints found.
fn parse_supported_groups(buf: &[u8]) -> Vec<u16> {
    let mut cursor = 5 + 4 + 2 + 32; // record + handshake header + version + random
    if buf.len() < cursor + 1 {
        return vec![];
    }
    let sid_len = buf[cursor] as usize;
    cursor += 1 + sid_len;
    if buf.len() < cursor + 2 {
        return vec![];
    }
    let cs_len = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
    cursor += 2 + cs_len;
    if buf.len() < cursor + 1 {
        return vec![];
    }
    let cm_len = buf[cursor] as usize;
    cursor += 1 + cm_len;
    if buf.len() < cursor + 2 {
        return vec![];
    }
    let ext_total_len = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
    cursor += 2;
    let ext_end = (cursor + ext_total_len).min(buf.len());
    while cursor + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        let ext_len = u16::from_be_bytes([buf[cursor + 2], buf[cursor + 3]]) as usize;
        cursor += 4;
        if ext_type == 0x000A && cursor + 2 <= ext_end {
            let list_len = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
            let mut groups = Vec::new();
            let mut g = cursor + 2;
            while g + 2 <= cursor + 2 + list_len && g + 2 <= ext_end {
                groups.push(u16::from_be_bytes([buf[g], buf[g + 1]]));
                g += 2;
            }
            return groups;
        }
        cursor += ext_len;
    }
    vec![]
}

#[tokio::test]
async fn reqwest_offers_x25519_mlkem768_after_init_pq_provider() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let (tx, rx) = mpsc::channel::<Vec<u8>>();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
            let mut buf = vec![0u8; 4096];
            if let Ok(n) = stream.read(&mut buf) {
                buf.truncate(n);
                let _ = tx.send(buf);
            }
        }
    });

    pqcd::tls::init_pq_provider().expect("install PQ provider");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build reqwest client");
    let url = format!("https://127.0.0.1:{}/", addr.port());
    let _ = client.get(&url).send().await;

    let captured = rx
        .recv_timeout(Duration::from_secs(5))
        .expect("captured ClientHello bytes");
    let groups = parse_supported_groups(&captured);
    assert!(
        groups.contains(&NAMED_GROUP_X25519_MLKEM768),
        "ClientHello did not offer X25519MLKEM768 (0x11EC). Found groups: {:04X?}",
        groups
    );
}
