//! rustls_interop - jpssl <-> rustls TLS 1.2 / 1.3 互操作助手
//!
//! 与 tests/test_tls_rustls_interop.cpp 配合，实现与 wolfSSL/Mbed TLS 测试
//! 相同的 4 字节长度前缀交换协议（31 种长度，含大量非 8 字节对齐边界）。
//!
//! 用法：
//!   rustls_interop client --addr <ip:port> --suite <NAME> --version 1.3|1.2 --ca <ca.pem>
//!   rustls_interop server --port <PORT>  --suite <NAME> --version 1.3|1.2 --cert <cert.pem> --key <key.pem>
//!
//! rustls 0.23（ring provider）实际支持的套件全集：
//!   TLS 1.3: AES128-GCM / AES256-GCM / CHACHA20-POLY1305
//!   TLS 1.2: ECDHE-ECDSA/RSA x AES128-GCM / AES256-GCM / CHACHA20
//! （无 CBC、静态 RSA、DHE-RSA、PSK、AES-CCM 套件）

use std::env;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::StreamOwned;
use rustls::CipherSuite;
use rustls::SupportedCipherSuite;
use rustls::SupportedProtocolVersion;

/// 与 C++ 侧 kLengths 完全一致（含非 8/16 字节对齐边界）。
const LENGTHS: [usize; 31] = [
    1, 2, 3, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000,
    1001, 1024, 1025, 16383, 16384, 16385, 65535, 65536, 65537,
];

struct Suite {
    name: &'static str,
    cs: CipherSuite,
    supported: SupportedCipherSuite,
    tls13: bool,
}

const SUITES: &[Suite] = &[
    // TLS 1.3
    Suite {
        name: "AES128-GCM",
        cs: CipherSuite::TLS13_AES_128_GCM_SHA256,
        supported: rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        tls13: true,
    },
    Suite {
        name: "AES256-GCM",
        cs: CipherSuite::TLS13_AES_256_GCM_SHA384,
        supported: rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        tls13: true,
    },
    Suite {
        name: "CHACHA20-POLY1305",
        cs: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        supported: rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256,
        tls13: true,
    },
    // TLS 1.2
    Suite {
        name: "ECDHE-ECDSA-AES128-GCM",
        cs: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        supported: rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls13: false,
    },
    Suite {
        name: "ECDHE-ECDSA-AES256-GCM",
        cs: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        supported: rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls13: false,
    },
    Suite {
        name: "ECDHE-ECDSA-CHACHA20",
        cs: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        supported: rustls::crypto::ring::cipher_suite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        tls13: false,
    },
    Suite {
        name: "ECDHE-RSA-AES128-GCM",
        cs: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        supported: rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        tls13: false,
    },
    Suite {
        name: "ECDHE-RSA-AES256-GCM",
        cs: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        supported: rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls13: false,
    },
    Suite {
        name: "ECDHE-RSA-CHACHA20",
        cs: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        supported: rustls::crypto::ring::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        tls13: false,
    },
];

fn find_suite(name: &str) -> Option<&'static Suite> {
    SUITES.iter().find(|s| s.name == name)
}

fn find_version(spec: &str) -> Result<&'static SupportedProtocolVersion, String> {
    match spec {
        "1.3" | "13" | "tls13" => Ok(&rustls::version::TLS13),
        "1.2" | "12" | "tls12" => Ok(&rustls::version::TLS12),
        _ => Err(format!("unknown TLS version: {spec}")),
    }
}

fn pattern(len: usize) -> Vec<u8> {
    (0..len).map(|i| ((i * 31 + 7) & 0xff) as u8).collect()
}

fn exchange<S: Read + Write>(s: &mut S) -> Result<(), String> {
    for &len in &LENGTHS {
        let buf = pattern(len);
        let hdr = [
            (len >> 24) as u8,
            (len >> 16) as u8,
            (len >> 8) as u8,
            len as u8,
        ];
        s.write_all(&hdr).map_err(|e| format!("send hdr: {e}"))?;
        s.write_all(&buf).map_err(|e| format!("send data: {e}"))?;

        let mut rhdr = [0u8; 4];
        s.read_exact(&mut rhdr).map_err(|e| format!("recv hdr: {e}"))?;
        let rlen = ((rhdr[0] as usize) << 24)
            | ((rhdr[1] as usize) << 16)
            | ((rhdr[2] as usize) << 8)
            | rhdr[3] as usize;
        if rlen != len {
            return Err(format!("length mismatch: sent {len}, got {rlen}"));
        }
        let mut got = vec![0u8; len];
        s.read_exact(&mut got).map_err(|e| format!("recv data: {e}"))?;
        if got != buf {
            return Err(format!("payload mismatch at length {len}"));
        }
    }
    Ok(())
}

fn load_certs(path: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut r = BufReader::new(f);
    let certs: Vec<_> = rustls_pemfile::certs(&mut r)
        .collect::<Result<_, _>>()
        .map_err(|e| format!("parse certs {path}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("no certificates in {path}"));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<PrivateKeyDer<'static>, String> {
    let f = File::open(path).map_err(|e| format!("open {path}: {e}"))?;
    let mut r = BufReader::new(f);
    rustls_pemfile::private_key(&mut r)
        .map_err(|e| format!("parse key {path}: {e}"))?
        .ok_or_else(|| format!("no private key in {path}"))
}

fn make_provider(suite: &'static Suite) -> rustls::crypto::CryptoProvider {
    let base = rustls::crypto::ring::default_provider();
    rustls::crypto::CryptoProvider {
        cipher_suites: vec![suite.supported],
        ..base
    }
}

fn set_socket_timeouts(stream: &TcpStream) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| format!("set write timeout: {e}"))
}

fn run_client(args: &[String]) -> Result<(), String> {
    let addr = get_opt(args, "--addr").ok_or("missing --addr")?;
    let suite = find_suite(&get_opt(args, "--suite").ok_or("missing --suite")?)
        .ok_or("unknown suite")?;
    let ver = find_version(&get_opt(args, "--version").ok_or("missing --version")?)?;
    let ca = get_opt(args, "--ca").ok_or("missing --ca")?;
    if suite.tls13 != (ver.version == rustls::ProtocolVersion::TLSv1_3) {
        return Err(format!(
            "suite {} does not match version {:?}",
            suite.name, ver.version
        ));
    }

    let mut roots = rustls::RootCertStore::empty();
    for cert in load_certs(&ca)? {
        roots
            .add(cert)
            .map_err(|e| format!("add CA cert: {e}"))?;
    }

    let provider = make_provider(suite);
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[ver])
        .map_err(|e| format!("client versions: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();

    let server_name =
        ServerName::try_from("localhost").map_err(|_| "invalid server name".to_string())?;
    let conn =
        rustls::ClientConnection::new(Arc::new(config), server_name).map_err(|e| e.to_string())?;

    let stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    set_socket_timeouts(&stream)?;
    let mut s = StreamOwned::new(conn, stream);
    exchange(&mut s)?;

    let negotiated = s
        .conn
        .negotiated_cipher_suite()
        .ok_or("no negotiated ciphersuite")?
        .suite();
    if negotiated != suite.cs {
        return Err(format!("negotiated wrong suite: {:?}", negotiated));
    }
    Ok(())
}

fn run_server(args: &[String]) -> Result<(), String> {
    let port: u16 = get_opt(args, "--port")
        .ok_or("missing --port")?
        .parse()
        .map_err(|_| "invalid --port")?;
    let suite = find_suite(&get_opt(args, "--suite").ok_or("missing --suite")?)
        .ok_or("unknown suite")?;
    let ver = find_version(&get_opt(args, "--version").ok_or("missing --version")?)?;
    let cert_path = get_opt(args, "--cert").ok_or("missing --cert")?;
    let key_path = get_opt(args, "--key").ok_or("missing --key")?;
    if suite.tls13 != (ver.version == rustls::ProtocolVersion::TLSv1_3) {
        return Err(format!(
            "suite {} does not match version {:?}",
            suite.name, ver.version
        ));
    }

    let certs = load_certs(&cert_path)?;
    let key = load_key(&key_path)?;
    let provider = make_provider(suite);
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[ver])
        .map_err(|e| format!("server versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("server cert: {e}"))?;

    let listener =
        TcpListener::bind(("127.0.0.1", port)).map_err(|e| format!("bind {port}: {e}"))?;
    let (stream, _) = listener
        .accept()
        .map_err(|e| format!("accept: {e}"))?;
    set_socket_timeouts(&stream)?;

    let conn = rustls::ServerConnection::new(Arc::new(config)).map_err(|e| e.to_string())?;
    let mut s = StreamOwned::new(conn, stream);
    exchange(&mut s)?;

    let negotiated = s
        .conn
        .negotiated_cipher_suite()
        .ok_or("no negotiated ciphersuite")?
        .suite();
    if negotiated != suite.cs {
        return Err(format!("negotiated wrong suite: {:?}", negotiated));
    }
    Ok(())
}

fn get_opt<'a>(args: &'a [String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let mode = args.first().map(|s| s.as_str());
    let result = match mode {
        Some("client") => run_client(&args[1..]),
        Some("server") => run_server(&args[1..]),
        _ => Err("usage: rustls_interop client|server ...".to_string()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rustls_interop error: {e}");
            ExitCode::FAILURE
        }
    }
}
