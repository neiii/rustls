//! FAIM: a QUIC client sending a hello template, with the connection's own transport
//! parameters in extension 57 where its client sent its own (faim-http#202).

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use faim_template::{ClientHello, ClientTemplate, Extension, ExtensionType, ProtocolVersion};
use rustls::ClientConfig;
use rustls::quic::{self, ClientConnection, ServerConnection};

use super::*;

mod common;
use common::*;

/// The `ClientHello` handshake message `client` writes first.
fn hello_of(client: &mut ClientConnection) -> Vec<u8> {
    let mut hello = Vec::new();
    assert!(client.write_hs(&mut hello).is_none());
    hello
}

/// A QUIC client under `config` sending `parameters`.
fn quic_client(config: ClientConfig, parameters: &[u8]) -> ClientConnection {
    ClientConnection::new(
        Arc::new(config),
        quic::Version::V1,
        server_name("localhost"),
        parameters.to_vec(),
    )
    .unwrap()
}

/// The template of the hello a QUIC client sends with `parameters` under `config`.
fn quic_template(config: &ClientConfig, parameters: &[u8]) -> ClientTemplate {
    let hello = hello_of(&mut quic_client(config.clone(), parameters));
    ClientHello::from_message(&hello, ProtocolVersion(0x0303))
        .unwrap()
        .template
}

/// The extension types `template` sends, in order.
fn kinds(template: &ClientTemplate) -> Vec<u16> {
    template
        .extensions()
        .iter()
        .map(|extension| extension.kind().0)
        .collect()
}

fn tls13_client() -> ClientConfig {
    make_client_config_with_versions(
        KeyType::Rsa2048,
        &[&rustls::version::TLS13],
        &provider::default_provider(),
    )
}

#[test]
fn a_quic_template_sends_its_clients_extension_order_with_the_connections_own_parameters() {
    let config = tls13_client();
    let recorded = quic_template(&config, b"the recorded client's parameters");
    let mut templated = config.clone();
    templated.hello_template = Some(Arc::new(recorded.clone()));

    let hello = hello_of(&mut quic_client(templated, b"this connection's"));

    let sent = ClientHello::from_message(&hello, ProtocolVersion(0x0303))
        .unwrap()
        .template;
    assert_eq!(kinds(&sent), kinds(&recorded));
    assert_eq!(
        sent.extensions()
            .iter()
            .find(|extension| extension.kind() == ExtensionType::QUIC_TRANSPORT_PARAMETERS),
        Some(&Extension::Other {
            kind: ExtensionType::QUIC_TRANSPORT_PARAMETERS,
            data: b"this connection's".to_vec(),
        })
    );
}

#[test]
fn a_server_handshakes_with_a_quic_template_and_reads_the_connections_own_parameters() {
    let config = tls13_client();
    let mut templated = config.clone();
    templated.hello_template = Some(Arc::new(quic_template(&config, b"recorded")));
    let mut client = quic_client(templated, b"this connection's");
    let mut server = ServerConnection::new(
        Arc::new(make_server_config(
            KeyType::Rsa2048,
            &provider::default_provider(),
        )),
        quic::Version::V1,
        b"the server's".to_vec(),
    )
    .unwrap();

    let mut flight = Vec::new();
    while client.is_handshaking() || server.is_handshaking() {
        flight.clear();
        client.write_hs(&mut flight);
        server.read_hs(&flight).unwrap();
        flight.clear();
        server.write_hs(&mut flight);
        client.read_hs(&flight).unwrap();
    }

    assert_eq!(
        server.quic_transport_parameters(),
        Some(&b"this connection's"[..])
    );
    assert_eq!(
        client.quic_transport_parameters(),
        Some(&b"the server's"[..])
    );
}
