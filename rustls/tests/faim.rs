//! FAIM: resumption through a hello template, tickets issued after the handshake, and
//! early data held open past the server's `Finished` (faim-http#199).

#![allow(clippy::disallowed_types, clippy::duplicate_mod)]

use std::io::{Read, Write};

use faim_template::{ClientHello, ClientTemplate};
use rustls::client::{ClientSessionMemoryCache, Resumption};
use rustls::server::ServerSessionMemoryCache;
use rustls::{
    ClientConfig, ClientConnection, Error, HandshakeKind, ServerConfig, ServerConnection,
};

use super::*;

mod common;
use common::*;

/// A TLS 1.3 client that keeps its sessions and can send early data, and a server that
/// issues two tickets a connection and accepts 1234 bytes of early data.
fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let kt = KeyType::Rsa2048;
    let provider = provider::default_provider();
    let mut client = make_client_config_with_versions(kt, &[&rustls::version::TLS13], &provider);
    client.enable_early_data = true;
    client.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(8)));
    let mut server = make_server_config(kt, &provider);
    server.session_storage = ServerSessionMemoryCache::new(32);
    server.max_early_data_size = 1234;
    (Arc::new(client), Arc::new(server))
}

/// The template of the hello a returning client sends: one more ticket stays in the store.
fn returning_template(
    client: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> Arc<ClientTemplate> {
    let (mut first, mut answering) = make_pair_for_arc_configs(client, server);
    do_handshake(&mut first, &mut answering);
    let (mut returning, _) = make_pair_for_arc_configs(client, server);
    let mut records = Vec::new();
    returning
        .write_tls(&mut records)
        .unwrap();
    Arc::new(
        ClientHello::from_records(&records)
            .unwrap()
            .template,
    )
}

fn with_template(client: &Arc<ClientConfig>, template: Arc<ClientTemplate>) -> ClientConfig {
    let mut config = (**client).clone();
    config.hello_template = Some(template);
    config
}

#[test]
fn a_template_hello_resumes_the_session_in_its_store() {
    let (client, server) = configs();
    let template = returning_template(&client, &server);
    let config = Arc::new(with_template(&client, template));

    let (mut client, mut server) = make_pair_for_arc_configs(&config, &server);
    do_handshake(&mut client, &mut server);

    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn a_template_hello_with_an_empty_store_offers_no_psk_and_handshakes_in_full() {
    let (client, server) = configs();
    let template = returning_template(&client, &server);
    let mut config = with_template(&client, template);
    config.resumption = Resumption::store(Arc::new(ClientSessionMemoryCache::new(8)));

    let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(config), &server);
    do_handshake(&mut client, &mut server);

    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
}

/// A template config with a verifier of its own, sharing `client`'s session store: what a
/// strict connection looks like beside a session made under another verifier.
fn under_another_verifier(
    client: &Arc<ClientConfig>,
    template: Arc<ClientTemplate>,
) -> ClientConfig {
    let provider = provider::default_provider();
    let mut config =
        make_client_config_with_versions(KeyType::Rsa2048, &[&rustls::version::TLS13], &provider);
    config.resumption = client.resumption.clone();
    config.hello_template = Some(template);
    config
}

#[test]
fn a_template_hello_wont_resume_a_session_made_under_another_verifier() {
    let (client, server) = configs();
    let template = returning_template(&client, &server);
    let config = under_another_verifier(&client, template);

    let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(config), &server);
    do_handshake(&mut client, &mut server);

    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Full));
}

#[test]
fn a_config_that_vouches_for_its_store_resumes_what_the_store_hands_it() {
    let (client, server) = configs();
    let template = returning_template(&client, &server);
    let mut config = under_another_verifier(&client, template);
    config.resumes_session_as_given = true;

    let (mut client, mut server) = make_pair_for_arc_configs(&Arc::new(config), &server);
    do_handshake(&mut client, &mut server);

    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
}

/// Runs `client` and `server` to the point the client holds its early data open.
fn hold(
    config: &Arc<ClientConfig>,
    server: &Arc<ServerConfig>,
) -> (ClientConnection, ServerConnection) {
    let (mut client, mut server) = make_pair_for_arc_configs(config, server);
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    (client, server)
}

fn holding_config(client: &Arc<ClientConfig>, server: &Arc<ServerConfig>) -> Arc<ClientConfig> {
    let template = returning_template(client, server);
    let mut config = with_template(client, template);
    config.hold_early_data = true;
    Arc::new(config)
}

#[test]
fn a_held_handshake_sends_what_is_written_as_early_data_until_it_is_ended() {
    let (client, server) = configs();
    let config = holding_config(&client, &server);
    let (mut client, mut server) = hold(&config, &server);

    assert!(client.early_data_held());
    assert!(!client.is_handshaking());
    assert!(client.is_early_data_accepted());
    client
        .writer()
        .write_all(b"hello")
        .unwrap();
    client.end_early_data().unwrap();
    assert!(!client.early_data_held());
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    assert!(!server.is_handshaking());
    let mut received = Vec::new();
    server
        .early_data()
        .expect("early data was accepted")
        .read_to_end(&mut received)
        .unwrap();
    assert_eq!(received, b"hello");
    assert_eq!(server.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn what_doesnt_fit_a_held_handshakes_early_data_goes_out_after_it_ends() {
    let (client, server) = configs();
    let config = holding_config(&client, &server);
    let (mut client, mut server) = hold(&config, &server);
    let plaintext = vec![7; 1300];

    let mut written = 0;
    while written < plaintext.len() {
        written += client
            .writer()
            .write(&plaintext[written..])
            .unwrap();
    }
    client.end_early_data().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let mut early = Vec::new();
    server
        .early_data()
        .unwrap()
        .read_to_end(&mut early)
        .unwrap();
    assert_eq!(early.len(), 1234);
    let mut rest = vec![0; 66];
    server
        .reader()
        .read_exact(&mut rest)
        .unwrap();
    assert_eq!(rest, vec![7; 66]);
}

#[test]
fn what_a_server_writes_before_a_held_handshake_ends_is_read_once_it_ends() {
    let (client, server) = configs();
    let config = holding_config(&client, &server);
    let mut halfway = (*server).clone();
    halfway.send_half_rtt_data = true;
    let (mut client, mut server) = make_pair_for_arc_configs(&config, &Arc::new(halfway));
    server
        .writer()
        .write_all(b"half rtt")
        .unwrap();

    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    // A read loop goes on processing while held, and the bytes behind `Finished` wait.
    client.process_new_packets().unwrap();

    assert!(client.early_data_held());
    client.end_early_data().unwrap();
    let mut read = vec![0; 8];
    client
        .reader()
        .read_exact(&mut read)
        .unwrap();
    assert_eq!(read, b"half rtt");
}

#[test]
fn what_was_written_before_the_hold_stays_ahead_of_what_is_written_during_it() {
    let (client, server) = configs();
    let config = holding_config(&client, &server);
    let (mut client, mut server) = make_pair_for_arc_configs(&config, &server);
    client
        .writer()
        .write_all(b"first")
        .unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();
    assert!(client.early_data_held());

    client
        .writer()
        .write_all(b"second")
        .unwrap();
    client.end_early_data().unwrap();
    transfer(&mut client, &mut server);
    server.process_new_packets().unwrap();

    let mut early = Vec::new();
    server
        .early_data()
        .unwrap()
        .read_to_end(&mut early)
        .unwrap();
    assert_eq!(early, b"");
    let mut read = vec![0; 11];
    server
        .reader()
        .read_exact(&mut read)
        .unwrap();
    assert_eq!(read, b"firstsecond");
}

#[test]
fn a_ticket_issued_after_the_handshake_carries_the_terms_asked_for_and_resumes() {
    let (client_config, server_config) = configs();
    let mut server_config = (*server_config).clone();
    server_config.send_tls13_tickets = 0;
    let server_config = Arc::new(server_config);
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    do_handshake(&mut client, &mut server);
    assert_eq!(client.tls13_tickets_received(), 0);

    server
        .issue_tls13_ticket(7200, 321)
        .unwrap();
    transfer(&mut server, &mut client);
    client.process_new_packets().unwrap();

    assert_eq!(client.tls13_tickets_received(), 1);
    let (mut client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);
    assert_eq!(
        client
            .early_data()
            .unwrap()
            .bytes_left(),
        321
    );
    do_handshake(&mut client, &mut server);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Resumed));
}

#[test]
fn issuing_a_ticket_before_the_handshake_completes_is_refused() {
    let (client_config, server_config) = configs();
    let (_client, mut server) = make_pair_for_arc_configs(&client_config, &server_config);

    assert_eq!(
        server.issue_tls13_ticket(7200, 0),
        Err(Error::HandshakeNotComplete)
    );
}

#[test]
fn ending_early_data_a_connection_isnt_holding_is_refused() {
    let (client_config, server_config) = configs();
    let (mut client, _) = make_pair_for_arc_configs(&client_config, &server_config);

    assert_eq!(client.end_early_data(), Err(Error::HandshakeNotComplete));

    // A refused call leaves the connection as it was.
    let mut server = ServerConnection::new(server_config).unwrap();
    do_handshake(&mut client, &mut server);
    assert_eq!(client.handshake_kind(), Some(HandshakeKind::Full));
}
