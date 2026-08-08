//! quic_parser_compliance — QUIC v1/v2 Initial packet compliance checker.
//!
//! Uses the `quic-parser` crate (independent implementation, canmi21/quic-parser)
//! to parse, decrypt, and extract CRYPTO frames from QUIC Initial packets
//! produced by jpssl, for both QUIC v1 (RFC 9000/9001) and v2 (RFC 9369):
//!   * long-header parsing (version, Fixed Bit, DCID/SCID, token, length);
//!   * v1/v2 Initial key derivation (RFC 9001 section 5.2 / RFC 9369
//!     section 3.3), header protection removal, and AEAD decryption;
//!   * CRYPTO frame parsing and reassembly into the TLS handshake stream,
//!     which must be a ClientHello (handshake type 0x01).

use std::env;
use std::fs;
use std::process::ExitCode;

/// RFC 9001 Appendix A.2 client Initial packet (complete, 1200 bytes),
/// used by `self-test` to validate this harness against the official vector.
const RFC9001_A2_HEX: &str = include_str!("../rfc9001_a2_initial.hex");

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    let clean: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    assert!(clean.len() % 2 == 0);
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).expect("valid hex"))
        .collect()
}

struct Expect<'a> {
    version: u32,
    dcid: Option<&'a str>,
    scid: Option<&'a str>,
}

fn check_packet(tag: &str, data: &[u8], expect: &Expect<'_>) -> Result<(), String> {
    let header = quic_parser::parse_initial(data)
        .map_err(|e| format!("{tag}: quic-parser header parse failed: {e}"))?;
    println!(
        "{tag}: version={:#010x} dcid={} scid={} token={}B payload={}B",
        header.version,
        hex(header.dcid),
        hex(header.scid),
        header.token.len(),
        header.payload.len()
    );

    if header.version != expect.version {
        return Err(format!(
            "{tag}: version mismatch, got {:#010x}, want {:#010x}",
            header.version, expect.version
        ));
    }
    if let Some(d) = expect.dcid {
        if hex(header.dcid) != d {
            return Err(format!(
                "{tag}: DCID mismatch, got {}, want {}",
                hex(header.dcid),
                d
            ));
        }
    }
    if let Some(s) = expect.scid {
        if hex(header.scid) != s {
            return Err(format!(
                "{tag}: SCID mismatch, got {}, want {}",
                hex(header.scid),
                s
            ));
        }
    }

    let decrypted = quic_parser::decrypt_initial(&header)
        .map_err(|e| format!("{tag}: quic-parser decrypt failed: {e}"))?;
    let frames = quic_parser::parse_crypto_frames(&decrypted)
        .map_err(|e| format!("{tag}: CRYPTO frame parse failed: {e}"))?;
    let stream = quic_parser::reassemble_crypto_stream(&frames);
    println!(
        "{tag}: decrypted={}B crypto_frames={} reassembled={}B",
        decrypted.len(),
        frames.len(),
        stream.len()
    );

    if stream.len() < 6 {
        return Err(format!(
            "{tag}: reassembled crypto stream too short ({})",
            stream.len()
        ));
    }
    let msg_type = stream[0];
    let hs_len = u32::from_be_bytes([0, stream[1], stream[2], stream[3]]) as usize;
    let tls_version = u16::from_be_bytes([stream[4], stream[5]]);
    if msg_type != 1 {
        return Err(format!(
            "{tag}: TLS handshake type {:#04x}, want 0x01 ClientHello",
            msg_type
        ));
    }
    if stream.len() < 4 + hs_len {
        return Err(format!(
            "{tag}: TLS handshake length {} exceeds crypto stream {}",
            hs_len,
            stream.len()
        ));
    }
    println!(
        "{tag}: TLS ClientHello len={} legacy_version={:#06x} OK",
        hs_len, tls_version
    );
    Ok(())
}

fn run_self_test() -> Result<(), String> {
    let packet = hex_decode(RFC9001_A2_HEX);
    if packet.len() != 1200 {
        return Err(format!(
            "self-test: RFC 9001 A.2 vector length {}, want 1200",
            packet.len()
        ));
    }
    check_packet(
        "self-test(rfc9001-a2)",
        &packet,
        &Expect {
            version: 0x0000_0001,
            dcid: Some("8394c8f03e515708"),
            scid: None,
        },
    )
}

fn usage() -> ! {
    eprintln!("usage: quic_parser_compliance self-test");
    eprintln!("       quic_parser_compliance check <packet-file> <version-hex> [dcid-hex] [scid-hex]");
    std::process::exit(2);
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    match args[0].as_str() {
        "self-test" => run_self_test(),
        "check" => {
            if args.len() < 3 {
                usage();
            }
            let version = u32::from_str_radix(args[2].trim_start_matches("0x"), 16)
                .map_err(|e| format!("invalid version hex: {e}"))?;
            let data = fs::read(&args[1]).map_err(|e| format!("read {}: {e}", args[1]))?;
            let expect = Expect {
                version,
                dcid: args.get(3).map(String::as_str),
                scid: args.get(4).map(String::as_str),
            };
            check_packet(&args[1], &data, &expect)
        }
        other => {
            eprintln!("unknown command: {other}");
            usage();
        }
    }
}

fn main() -> ExitCode {
    let result = run();
    match result {
        Ok(()) => {
            println!("RESULT: PASS");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("{e}");
            println!("RESULT: FAIL");
            ExitCode::FAILURE
        }
    }
}
