//! FAIM: the template client's checks, against a server written out by hand where no
//! rustls server sends what a test needs.

use super::*;
use crate::common_state::Side;

/// The largest plaintext record a client sends once a server answered with
/// `limit`, when `ClientConfig::max_fragment_size` is `configured`.
fn largest_record(configured: Option<usize>, limit: u16) -> usize {
    let mut common = CommonState::new(Side::Client);
    common
        .set_max_fragment_size(configured)
        .unwrap();
    let exts = ServerExtensions {
        record_size_limit: Some(limit),
        ..ServerExtensions::default()
    };
    apply_record_size_limit(&mut common, &exts, ProtocolVersion::TLSv1_3, configured).unwrap();
    let message = Message {
        version: ProtocolVersion::TLSv1_3,
        payload: MessagePayload::ApplicationData(Payload::new(vec![0; 20_000])),
    };
    common.send_msg(message, false);
    let mut records = Vec::new();
    common
        .sendable_tls
        .write_to(&mut records)
        .unwrap();
    fragments(&records)
        .map(|(_, fragment)| fragment.len())
        .max()
        .unwrap_or(0)
}

/// Each record in `records` as its content type and fragment.
fn fragments(mut records: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    core::iter::from_fn(move || {
        let [kind, _, _, high, low, rest @ ..] = records else {
            return None;
        };
        let (fragment, tail) = rest.split_at(usize::from(u16::from_be_bytes([*high, *low])));
        records = tail;
        Some((*kind, fragment))
    })
}

#[test]
fn a_record_size_limit_caps_the_records_the_client_sends() {
    // TLS 1.3 counts the content type byte in the limit.
    assert_eq!(largest_record(None, 1025), 1024);
}

#[test]
fn a_record_size_limit_never_raises_a_configured_fragment_size() {
    assert_eq!(largest_record(Some(517), 16385), 512);
}

#[macro_rules_attribute::apply(test_for_each_provider)]
mod scripted {
    use std::sync::OnceLock;

    use faim_template::ClientHello;
    use pki_types::pem::PemObject;
    use pki_types::{CertificateDer, PrivateKeyDer};

    use super::*;
    use crate::client::ClientConnection;
    use crate::crypto::CryptoProvider;
    use crate::crypto::hash;
    use crate::crypto::tls13::OkmBlock;
    use crate::msgs::message::PlainMessage;
    use crate::tls13::key_schedule::{
        derive_traffic_iv, derive_traffic_key, hkdf_expand_label_block,
    };
    use crate::tls13::{Tls13CipherSuite, construct_server_verify_message};
    use crate::{KeyLog, RootCertStore};

    /// `max_fragment_length` (RFC 6066): an answer caps every record the client sends,
    /// which the fork doesn't do.
    const MAX_FRAGMENT_LENGTH: u16 = faim_template::ExtensionType::MAX_FRAGMENT_LENGTH.0;

    /// A `trust_anchors` list naming one trust anchor ID, 32473.1, as a client's hello
    /// and a server's `EncryptedExtensions` carry it.
    const ONE_TRUST_ANCHOR: &[u8] = &[0, 5, 4, 0x81, 0xfd, 0x59, 0x01];

    /// X25519 alone, so the template sends one key share and the scripted server can
    /// pick its group.
    fn x25519_provider() -> CryptoProvider {
        CryptoProvider {
            kx_groups: vec![provider::kx_group::X25519],
            ..provider::default_provider()
        }
    }

    fn roots() -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_slice(include_bytes!(
                "../../../../../test-ca/rsa-2048/ca.der"
            )))
            .unwrap();
        roots
    }

    fn certificate_chain() -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_slice_iter(include_bytes!(
            "../../../../../test-ca/rsa-2048/end.fullchain"
        ))
        .collect::<Result<_, _>>()
        .unwrap()
    }

    fn private_key() -> PrivateKeyDer<'static> {
        PrivateKeyDer::from_pem_slice(include_bytes!("../../../../../test-ca/rsa-2048/end.key"))
            .unwrap()
    }

    /// A stock client config checking certificates against the test CA, offering TLS
    /// 1.2 and 1.3 and X25519 alone.
    fn stock_config() -> ClientConfig {
        ClientConfig::builder_with_provider(Arc::new(x25519_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots())
            .with_no_client_auth()
    }

    fn connect(config: ClientConfig) -> ClientConnection {
        ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("testserver.com").unwrap(),
        )
        .unwrap()
    }

    /// The template of a stock rustls hello that also offers `extensions`, each a type
    /// and its data, after its own.
    fn template_offering(extensions: &[(u16, &[u8])]) -> Arc<ClientTemplate> {
        let mut stock = Vec::new();
        connect(stock_config())
            .write_tls(&mut stock)
            .unwrap();
        let mut hello = handshake_bytes(&stock);
        // Past the handshake header, the version, the random, the session id, the
        // suites and the compression methods sits the extensions' length.
        let mut at = 4 + 2 + 32;
        at += 1 + usize::from(hello[at]);
        at += 2 + usize::from(u16::from_be_bytes([hello[at], hello[at + 1]]));
        at += 1 + usize::from(hello[at]);
        let added = encode_extensions(extensions);
        let added = &added[2..];
        let len = u16::from_be_bytes([hello[at], hello[at + 1]]) + added.len() as u16;
        hello[at..at + 2].copy_from_slice(&len.to_be_bytes());
        hello.extend_from_slice(added);
        let body = (hello.len() - 4) as u32;
        hello[1..4].copy_from_slice(&body.to_be_bytes()[1..]);
        Arc::new(
            ClientHello::from_records(&record(ContentType::Handshake, &hello))
                .unwrap()
                .template,
        )
    }

    /// A client sending `template`'s hello, logging its secrets to `server`.
    fn template_client(
        template: Arc<ClientTemplate>,
        server: &Arc<ScriptedServer>,
    ) -> ClientConnection {
        let mut config = stock_config();
        config.hello_template = Some(template);
        config.key_log = server.clone();
        connect(config)
    }

    /// A TLS 1.3 server written out by hand, since no rustls server answers an
    /// extension rustls doesn't handle. It picks X25519 with a made-up public key, so it
    /// can't derive the handshake secret itself: it reads the one its client derives
    /// from the client's key log, then encrypts its flight, signs it with the test CA's
    /// end-entity key and finishes it.
    #[derive(Debug, Default)]
    struct ScriptedServer {
        handshake_secret: OnceLock<Vec<u8>>,
    }

    impl KeyLog for ScriptedServer {
        fn will_log(&self, label: &str) -> bool {
            label == "SERVER_HANDSHAKE_TRAFFIC_SECRET"
        }

        fn log(&self, _label: &str, _client_random: &[u8], secret: &[u8]) {
            self.handshake_secret
                .set(secret.to_vec())
                .unwrap();
        }
    }

    impl ScriptedServer {
        /// Answers `client`'s hello in full: a `ServerHello`, then `EncryptedExtensions`
        /// carrying `answered`, the test CA's chain whose leaf entry carries
        /// `leaf_extensions`, `CertificateVerify` and `Finished`. The result is the
        /// client's verdict on the whole flight.
        fn answer(
            &self,
            client: &mut ClientConnection,
            answered: &[(u16, &[u8])],
            leaf_extensions: &[(u16, &[u8])],
        ) -> Result<(), Error> {
            let suite = provider::cipher_suite::TLS13_AES_128_GCM_SHA256
                .tls13()
                .unwrap();
            let mut transcript = suite.common.hash_provider.start();

            let mut sent = Vec::new();
            client.write_tls(&mut sent).unwrap();
            let hello = ClientHello::from_records(&sent).unwrap();
            transcript.update(&handshake_bytes(&sent));

            let mut key_share = vec![0x00, 0x1d, 0, 32];
            key_share.extend_from_slice(&[0xaa; 32]);
            let server_hello = server_hello(
                &hello.fresh.session_id,
                0x1301,
                &[(0x002b, &[3, 4]), (0x0033, &key_share)],
            );
            transcript.update(&server_hello);
            client
                .read_tls(&mut record(ContentType::Handshake, &server_hello).as_slice())
                .unwrap();
            client.process_new_packets()?;

            let secret = OkmBlock::new(self.handshake_secret.get().unwrap());
            let expander = suite
                .hkdf_provider
                .expander_for_okm(&secret);
            let mut encrypter = suite.aead_alg.encrypter(
                derive_traffic_key(expander.as_ref(), suite.aead_alg),
                derive_traffic_iv(expander.as_ref()),
            );

            let mut flight = vec![
                handshake(
                    HandshakeType::EncryptedExtensions,
                    &encode_extensions(answered),
                ),
                handshake(
                    HandshakeType::Certificate,
                    &certificate(&certificate_chain(), leaf_extensions),
                ),
            ];
            for message in &flight {
                transcript.update(message);
            }
            let key = provider::default_provider()
                .key_provider
                .load_private_key(private_key())
                .unwrap();
            let signer = key
                .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
                .unwrap();
            let signature = signer
                .sign(construct_server_verify_message(&transcript.fork_finish()).as_ref())
                .unwrap();
            let mut verify = Vec::new();
            SignatureScheme::RSA_PSS_SHA256.encode(&mut verify);
            (signature.len() as u16).encode(&mut verify);
            verify.extend_from_slice(&signature);
            let verify = handshake(HandshakeType::CertificateVerify, &verify);
            transcript.update(&verify);
            flight.push(verify);
            flight.push(handshake(
                HandshakeType::Finished,
                verify_data(expander.as_ref(), suite, &transcript.fork_finish()).as_ref(),
            ));

            let mut records = Vec::new();
            for (seq, message) in flight.into_iter().enumerate() {
                let plain = PlainMessage {
                    typ: ContentType::Handshake,
                    version: ProtocolVersion::TLSv1_2,
                    payload: Payload::new(message),
                };
                records.extend(
                    encrypter
                        .encrypt(plain.borrow_outbound(), seq as u64)
                        .unwrap()
                        .encode(),
                );
            }
            client
                .read_tls(&mut records.as_slice())
                .unwrap();
            client.process_new_packets().map(drop)
        }
    }

    /// The server's `Finished` for a transcript hashing to `transcript` (RFC 8446
    /// §4.4.4), keyed from the secret behind `expander`.
    fn verify_data(
        expander: &dyn crate::crypto::tls13::HkdfExpander,
        suite: &Tls13CipherSuite,
        transcript: &hash::Output,
    ) -> crate::crypto::hmac::Tag {
        let key = hkdf_expand_label_block(expander, b"finished", &[]);
        suite
            .hkdf_provider
            .hmac_sign(&key, transcript.as_ref())
    }

    /// The handshake messages in `records`, without their record headers.
    fn handshake_bytes(records: &[u8]) -> Vec<u8> {
        fragments(records)
            .filter(|(kind, _)| *kind == u8::from(ContentType::Handshake))
            .flat_map(|(_, fragment)| fragment.iter().copied())
            .collect()
    }

    fn record(kind: ContentType, fragment: &[u8]) -> Vec<u8> {
        let mut record = vec![u8::from(kind), 3, 3];
        record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
        record.extend_from_slice(fragment);
        record
    }

    fn handshake(kind: HandshakeType, body: &[u8]) -> Vec<u8> {
        let mut message = vec![u8::from(kind)];
        message.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        message.extend_from_slice(body);
        message
    }

    /// An extension list: its length, then each type, data length and data.
    fn encode_extensions(extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut list = Vec::new();
        for (kind, data) in extensions {
            list.extend_from_slice(&kind.to_be_bytes());
            list.extend_from_slice(&(data.len() as u16).to_be_bytes());
            list.extend_from_slice(data);
        }
        let mut encoded = (list.len() as u16)
            .to_be_bytes()
            .to_vec();
        encoded.extend(list);
        encoded
    }

    /// A `ServerHello` in TLS 1.2's legacy version echoing `session_id`, with `suite`
    /// and `extensions`.
    fn server_hello(session_id: &[u8], suite: u16, extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend_from_slice(&[7; 32]);
        body.push(session_id.len() as u8);
        body.extend_from_slice(session_id);
        body.extend_from_slice(&suite.to_be_bytes());
        body.push(0);
        body.extend(encode_extensions(extensions));
        handshake(HandshakeType::ServerHello, &body)
    }

    /// A TLS 1.3 `Certificate` body: no request context, then `chain` with
    /// `leaf_extensions` on its first entry and none on the others.
    fn certificate(chain: &[CertificateDer<'_>], leaf_extensions: &[(u16, &[u8])]) -> Vec<u8> {
        let mut entries = Vec::new();
        for (index, cert) in chain.iter().enumerate() {
            entries.extend_from_slice(&(cert.len() as u32).to_be_bytes()[1..]);
            entries.extend_from_slice(cert);
            let extensions = if index == 0 { leaf_extensions } else { &[] };
            entries.extend(encode_extensions(extensions));
        }
        let mut body = vec![0];
        body.extend_from_slice(&(entries.len() as u32).to_be_bytes()[1..]);
        body.extend(entries);
        body
    }

    #[test]
    fn a_server_answering_trust_anchors_in_encrypted_extensions_completes_the_handshake() {
        // A server that has a path to the anchor answers with the IDs it has paths for,
        // and marks the leaf entry of that path with an empty trust_anchors.
        let server = Arc::new(ScriptedServer::default());
        let mut client = template_client(
            template_offering(&[(TRUST_ANCHORS, ONE_TRUST_ANCHOR)]),
            &server,
        );

        let verdict = server.answer(
            &mut client,
            &[(TRUST_ANCHORS, ONE_TRUST_ANCHOR)],
            &[(TRUST_ANCHORS, &[])],
        );

        assert_eq!(verdict, Ok(()));
        assert!(!client.is_handshaking());
        assert_eq!(
            client.peer_certificates(),
            Some(certificate_chain().as_slice())
        );
    }

    #[test]
    fn a_server_answering_another_extension_the_fork_doesnt_handle_is_a_shortfall_naming_it() {
        let server = Arc::new(ScriptedServer::default());
        let mut client = template_client(
            template_offering(&[
                (TRUST_ANCHORS, ONE_TRUST_ANCHOR),
                (MAX_FRAGMENT_LENGTH, &[1]),
            ]),
            &server,
        );

        let verdict = server.answer(&mut client, &[(MAX_FRAGMENT_LENGTH, &[1])], &[]);

        assert_eq!(
            verdict,
            Err(Error::Shortfall(Shortfall::Extension(
                faim_template::ExtensionType::MAX_FRAGMENT_LENGTH
            )))
        );
    }

    #[cfg(feature = "tls12")]
    #[test]
    fn a_tls12_server_hello_answering_trust_anchors_is_a_shortfall_naming_it() {
        // The draft defines trust_anchors for TLS 1.3 alone. ECDHE-RSA-AES128-GCM-SHA256,
        // with a session id of the server's own.
        let mut client = template_client(
            template_offering(&[(TRUST_ANCHORS, ONE_TRUST_ANCHOR)]),
            &Arc::new(ScriptedServer::default()),
        );
        let mut hello = Vec::new();
        client.write_tls(&mut hello).unwrap();
        let server_hello = server_hello(&[5; 32], 0xc02f, &[(TRUST_ANCHORS, ONE_TRUST_ANCHOR)]);

        client
            .read_tls(&mut record(ContentType::Handshake, &server_hello).as_slice())
            .unwrap();

        assert_eq!(
            client.process_new_packets().map(drop),
            Err(Error::Shortfall(Shortfall::Extension(
                faim_template::ExtensionType(TRUST_ANCHORS)
            )))
        );
    }
}
