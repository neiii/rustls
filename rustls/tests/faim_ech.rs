//! FAIM: a server opening a client's ECH with keys it holds, on a peeked hello and in
//! the handshake, across a `HelloRetryRequest` too (faim-http#600).

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use pki_types::EchConfigListBytes;
use rustls::client::{EchConfig, EchGreaseConfig, EchMode, EchStatus};
use rustls::crypto::hpke::{Hpke, HpkePublicKey};
use rustls::server::{Accepted, Acceptor, EchServerKey};
use rustls::{
    ClientConfig, ClientConnection, Error, HandshakeKind, PeerIncompatible, ServerConfig,
    ServerConnection,
};

use super::*;

mod common;
use common::*;

/// The name the server's certificate is for, which the inner hello asks for.
const INNER: &str = "testserver.com";
/// The ECH config's public name, which the outer hello carries, and which the server's
/// certificate is for too, so a client it rejects still completes the handshake.
const PUBLIC: &str = "second.testserver.com";

/// The HPKE suite the configs here name: X25519, HKDF-SHA256, AES-128-GCM.
fn hpke() -> &'static dyn Hpke {
    provider::hpke::DH_KEM_X25519_HKDF_SHA256_AES_128
}

/// One `ECHConfig` (version 0xfe0d) under `config_id` for `public_key`, naming
/// [`hpke`]'s suite and `public_name`.
fn ech_config(config_id: u8, public_key: &HpkePublicKey, public_name: &str) -> Vec<u8> {
    let mut contents = vec![config_id, 0x00, 0x20];
    contents.extend_from_slice(&(public_key.0.len() as u16).to_be_bytes());
    contents.extend_from_slice(&public_key.0);
    // One suite: HKDF-SHA256, AES-128-GCM; a maximum name length of 0.
    contents.extend_from_slice(&[0, 4, 0, 1, 0, 1, 0]);
    contents.push(public_name.len() as u8);
    contents.extend_from_slice(public_name.as_bytes());
    contents.extend_from_slice(&[0, 0]);
    let mut config = vec![0xfe, 0x0d];
    config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
    config.extend_from_slice(&contents);
    config
}

/// A config of [`PUBLIC`] under `config_id` and the key that opens what is sealed to it.
fn ech_key(config_id: u8) -> (Vec<u8>, Arc<EchServerKey>) {
    let (public_key, private_key) = hpke().generate_key_pair().unwrap();
    let config = ech_config(config_id, &public_key, PUBLIC);
    let key = EchServerKey::new(config.clone(), private_key, &[hpke()]).unwrap();
    (config, Arc::new(key))
}

/// A client offering real ECH under `config`, for [`INNER`].
fn ech_client(
    config: &[u8],
    kx_groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>,
) -> ClientConnection {
    let mut list = (config.len() as u16)
        .to_be_bytes()
        .to_vec();
    list.extend_from_slice(config);
    let ech = EchConfig::new(EchConfigListBytes::from(list), &[hpke()]).unwrap();
    client_with(EchMode::Enable(ech), kx_groups)
}

fn client_with(
    mode: EchMode,
    kx_groups: Option<Vec<&'static dyn rustls::crypto::SupportedKxGroup>>,
) -> ClientConnection {
    let mut provider = provider::default_provider();
    if let Some(kx_groups) = kx_groups {
        provider.kx_groups = kx_groups;
    }
    let builder = ClientConfig::builder_with_provider(provider.into())
        .with_ech(mode)
        .unwrap();
    let config = finish_client_config(KeyType::Rsa2048, builder);
    ClientConnection::new(Arc::new(config), server_name(INNER)).unwrap()
}

fn server_with(configure: impl FnOnce(&mut ServerConfig)) -> ServerConnection {
    let mut config = make_server_config(KeyType::Rsa2048, &provider::default_provider());
    configure(&mut config);
    ServerConnection::new(Arc::new(config)).unwrap()
}

/// The server's side of `client`'s first hello, peeked before any handshake.
fn peeked(client: &mut ClientConnection) -> Accepted {
    let mut records = Vec::new();
    client.write_tls(&mut records).unwrap();
    accepted(&records)
}

fn accepted(records: &[u8]) -> Accepted {
    let mut acceptor = Acceptor::default();
    acceptor
        .read_tls(&mut &records[..])
        .unwrap();
    acceptor.accept().unwrap().unwrap()
}

/// Where the payload of the outer `encrypted_client_hello` sits in `records`, a
/// `ClientHello` in one record.
fn ech_payload(records: &[u8]) -> std::ops::Range<usize> {
    let u16_at = |at: usize| usize::from(u16::from_be_bytes([records[at], records[at + 1]]));
    // Record header, handshake header, version and random.
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + usize::from(records[at]);
    at += 2 + u16_at(at);
    at += 1 + usize::from(records[at]);
    at += 2;
    loop {
        let (kind, len) = (u16_at(at), u16_at(at + 2));
        let end = at + 4 + len;
        if kind == 0xfe0d {
            // Its type, suite and config id, then `enc` and the payload, each after
            // its length.
            let enc_at = at + 4 + 1 + 4 + 1;
            let payload_at = enc_at + 2 + u16_at(enc_at);
            return payload_at + 2..end;
        }
        at = end;
    }
}

#[test]
fn a_hello_sealed_to_a_key_the_server_holds_is_accepted_and_answered_as_its_inner_hello() {
    let (config, key) = ech_key(7);
    let mut client = ech_client(&config, None);
    let mut server = server_with(|server| server.ech_keys = vec![key]);

    do_handshake(&mut client, &mut server);

    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(server.server_name(), Some(INNER));
}

#[test]
fn ech_is_accepted_across_a_hello_retry_request() {
    let (config, key) = ech_key(7);
    let kx = provider::default_provider().kx_groups;
    let x25519 = kx
        .iter()
        .find(|group| u16::from(group.name()) == 0x1d)
        .copied()
        .unwrap();
    let secp256r1 = kx
        .iter()
        .find(|group| u16::from(group.name()) == 0x17)
        .copied()
        .unwrap();
    // The client sends a key share for X25519 alone, which the server can't use.
    let mut client = ech_client(&config, Some(vec![x25519, secp256r1]));
    let mut server = {
        let mut config = make_server_config_with_kx_groups(
            KeyType::Rsa2048,
            vec![secp256r1],
            &provider::default_provider(),
        );
        config.ech_keys = vec![key];
        ServerConnection::new(Arc::new(config)).unwrap()
    };

    do_handshake(&mut client, &mut server);

    assert_eq!(
        server.handshake_kind(),
        Some(HandshakeKind::FullWithHelloRetryRequest)
    );
    assert_eq!(client.ech_status(), EchStatus::Accepted);
    assert_eq!(server.server_name(), Some(INNER));
}

#[test]
fn a_hello_under_another_key_is_rejected_with_the_retry_configs() {
    let (config, _) = ech_key(7);
    let (_, other) = ech_key(7);
    let (retry, _) = ech_key(8);
    let mut list = (retry.len() as u16)
        .to_be_bytes()
        .to_vec();
    list.extend_from_slice(&retry);
    let mut client = ech_client(&config, None);
    let mut server = server_with(|server| {
        server.ech_keys = vec![other];
        server.ech_retry_configs = Some(list.into());
    });

    let refused = do_handshake_until_error(&mut client, &mut server);

    assert!(
        matches!(
            &refused,
            Err(ErrorFromPeer::Client(Error::PeerIncompatible(
                PeerIncompatible::ServerRejectedEncryptedClientHello(Some(configs))
            ))) if configs.len() == 1
        ),
        "{refused:?}"
    );
}

#[test]
fn a_peeked_hello_opens_to_its_inner_hello_with_the_key_that_opens_it() {
    let (config, key) = ech_key(7);
    let (_, other) = ech_key(7);
    let mut client = ech_client(&config, None);

    let opened = peeked(&mut client)
        .open_ech(&[other, key])
        .unwrap();

    assert_eq!(opened.key(), 1);
    let inner = opened.inner_hello();
    assert_eq!(inner[0], 1, "a ClientHello");
    assert_eq!(
        inner.len(),
        4 + usize::from(u16::from_be_bytes([inner[2], inner[3]]))
    );
    assert!(
        inner
            .windows(INNER.len())
            .any(|window| window == INNER.as_bytes()),
        "the inner hello names {INNER}"
    );
    // The inner hello is one a server reads: it opens nothing further.
    assert!(
        accepted(&record(inner))
            .client_hello()
            .server_name()
            == Some(INNER)
    );
}

#[test]
fn a_hello_under_another_key_a_greased_hello_and_a_tampered_one_do_not_open() {
    let (config, key) = ech_key(7);
    let (other_config, _) = ech_key(7);
    let keys = [key];

    let mut other = ech_client(&other_config, None);
    assert!(
        peeked(&mut other)
            .open_ech(&keys)
            .is_none()
    );

    let (grease_key, _) = hpke().generate_key_pair().unwrap();
    let mut greased = client_with(
        EchMode::Grease(EchGreaseConfig::new(hpke(), grease_key)),
        None,
    );
    assert!(
        peeked(&mut greased)
            .open_ech(&keys)
            .is_none()
    );

    let mut client = ech_client(&config, None);
    let mut records = Vec::new();
    client.write_tls(&mut records).unwrap();
    assert!(
        accepted(&records)
            .open_ech(&keys)
            .is_some()
    );
    let payload = ech_payload(&records);
    records[payload.end - 1] ^= 1;
    assert!(
        accepted(&records)
            .open_ech(&keys)
            .is_none()
    );
}

/// `message`, a handshake message, in one TLS record.
fn record(message: &[u8]) -> Vec<u8> {
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(message.len() as u16).to_be_bytes());
    record.extend_from_slice(message);
    record
}

#[test]
fn a_key_for_a_config_naming_no_suite_it_has_is_refused() {
    let (public_key, private_key) = hpke().generate_key_pair().unwrap();
    let config = ech_config(7, &public_key, PUBLIC);

    let refused = EchServerKey::new(
        config,
        private_key,
        &[provider::hpke::DH_KEM_P256_HKDF_SHA256_AES_128],
    );

    assert!(refused.is_err());
}
