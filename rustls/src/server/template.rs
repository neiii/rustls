//! FAIM: the server answers its client from a server template (faim-http#196).
//!
//! `ServerConfig::hello_template` holds the answer a real server gave: its
//! `ServerHello`, `EncryptedExtensions` and certificate message. faim-template fits it to
//! the client's hello as an [`Answer`]; the handshake then picks the server's version,
//! suite and group, and sends the `ServerHello` and `EncryptedExtensions` the template
//! renders, so the client sees the server's JA4S, ALPN and ALPS. What the fork leaves
//! out is recorded as a [`ServerShortfall`], which `ServerConnection::template_shortfalls`
//! returns.

use alloc::string::ToString;
use alloc::vec::Vec;

use faim_template::{Answer, ServerHelloValues, ServerShortfall};

use super::hs::ServerContext;
use crate::common_state::{CommonState, Protocol};
use crate::crypto::SupportedKxGroup;
use crate::enums::{
    AlertDescription, CipherSuite, HandshakeType, ProtocolVersion, SignatureAlgorithm,
    SignatureScheme,
};
use crate::error::{Error, PeerMisbehaved};
use crate::hash_hs::HandshakeHash;
use crate::msgs::base::Payload;
use crate::msgs::fragmenter::{MAX_FRAGMENT_LEN, PACKET_OVERHEAD};
use crate::msgs::handshake::{HandshakeMessagePayload, HandshakePayload, ProtocolName};
use crate::msgs::message::{Message, MessagePayload};
use crate::server::ServerConfig;
use crate::sign;
use crate::{SupportedCipherSuite, compress};

/// The template's answer to the client's hello `m`, or `None` when there is no
/// template or it can't answer this client, which is then recorded as a shortfall.
pub(super) fn answer(
    config: &ServerConfig,
    m: &Message<'_>,
    cx: &mut ServerContext<'_>,
) -> Option<Answer> {
    let template = config.hello_template.as_ref()?;
    if cx.common.is_quic() {
        cx.data
            .template_shortfalls
            .push(ServerShortfall::Quic);
        return None;
    }
    let MessagePayload::Handshake { encoded, .. } = &m.payload else {
        return None;
    };
    let version = faim_template::ProtocolVersion(u16::from(m.version));
    let Ok(hello) = faim_template::ClientHello::from_message(encoded.bytes(), version) else {
        cx.data
            .template_shortfalls
            .push(ServerShortfall::ClientHello);
        return None;
    };
    match template.answer(&hello.template) {
        Ok(answer) => Some(answer),
        Err(shortfall) => {
            cx.data
                .template_shortfalls
                .push(shortfall);
            None
        }
    }
}

/// Records `answer`'s shortfalls on the connection, once it answers the client.
pub(super) fn adopt(answer: &mut Answer, cx: &mut ServerContext<'_>) {
    cx.data
        .template_shortfalls
        .append(&mut answer.shortfalls);
}

/// The version to answer in: the template's, where `stock` (what rustls would pick)
/// differs and `tls12_enabled` allows it. `None` when the template's version can't be
/// answered in, or the fork can't complete its group, either of which drops the
/// template before rustls's version is replaced: a TLS 1.2 answer the fork then
/// couldn't send would leave a client offering TLS 1.3 a stock TLS 1.2 answer with
/// rustls's downgrade marker, which it refuses.
pub(super) fn version(
    answer: &Answer,
    config: &ServerConfig,
    stock: ProtocolVersion,
    tls12_enabled: bool,
    cx: &mut ServerContext<'_>,
) -> Option<ProtocolVersion> {
    let wanted = ProtocolVersion::from(answer.version.0);
    let possible = match wanted {
        ProtocolVersion::TLSv1_3 => stock == ProtocolVersion::TLSv1_3,
        ProtocolVersion::TLSv1_2 => tls12_enabled,
        _ => false,
    };
    if !possible {
        cx.data
            .template_shortfalls
            .push(ServerShortfall::Version(answer.version));
        return None;
    }
    if let Some(group) = answer.group {
        if group_for(config, wanted, group).is_none() {
            cx.data
                .template_shortfalls
                .push(ServerShortfall::Group(group));
            return None;
        }
    }
    Some(wanted)
}

/// The provider's key exchange for `group` on `version`.
fn group_for(
    config: &ServerConfig,
    version: ProtocolVersion,
    group: faim_template::NamedGroup,
) -> Option<&'static dyn SupportedKxGroup> {
    config
        .provider
        .kx_groups
        .iter()
        .find(|kxg| kxg.usable_for_version(version) && u16::from(kxg.name()) == group.0)
        .copied()
}

/// The suite and group to answer with: the template's, where the fork's provider
/// completes them, else rustls's own `stock` picks. [`version`] has already dropped a
/// template whose group the fork can't complete.
pub(super) fn suite_and_group(
    answer: &Answer,
    config: &ServerConfig,
    version: ProtocolVersion,
    sig_key_algorithm: SignatureAlgorithm,
    protocol: Protocol,
    stock: (SupportedCipherSuite, &'static dyn SupportedKxGroup),
    cx: &mut ServerContext<'_>,
) -> (SupportedCipherSuite, &'static dyn SupportedKxGroup) {
    let (stock_suite, stock_group) = stock;
    let group = answer
        .group
        .and_then(|group| group_for(config, version, group))
        .unwrap_or(stock_group);
    let suite = match answer.cipher_suite {
        Some(suite) => {
            let found = config
                .provider
                .cipher_suites
                .iter()
                .find(|found| {
                    u16::from(found.suite()) == suite.0
                        && found.version().version == version
                        && found.usable_for_signature_algorithm(sig_key_algorithm)
                        && found.usable_for_protocol(protocol)
                        && found.usable_for_kx_algorithm(group.name().key_exchange_algorithm())
                });
            match found {
                Some(found) => *found,
                None => {
                    cx.data
                        .template_shortfalls
                        .push(ServerShortfall::CipherSuite(suite));
                    stock_suite
                }
            }
        }
        None => stock_suite,
    };
    (suite, group)
}

/// The `ServerHello` handshake message the template renders with this connection's
/// `random`, `session_id`, `suite` and, on TLS 1.3, its key share, carried as
/// rendered so its extensions keep the server's order.
pub(super) fn server_hello(
    answer: &Answer,
    random: [u8; 32],
    session_id: &[u8],
    suite: CipherSuite,
    key_share: Option<(crate::msgs::enums::NamedGroup, &[u8])>,
    selected_psk: Option<u16>,
) -> Result<HandshakeMessagePayload<'static>, Error> {
    let values = ServerHelloValues {
        random,
        session_id: session_id.to_vec(),
        cipher_suite: faim_template::CipherSuite(u16::from(suite)),
        key_share: key_share.map(|(group, key)| {
            faim_template::KeyShare::new(faim_template::NamedGroup(u16::from(group)), key.to_vec())
        }),
        selected_psk,
    };
    let rendered = answer
        .render_server_hello(&values)
        .map_err(|error| Error::General(error.to_string()))?;
    Ok(raw(HandshakeType::ServerHello, &rendered))
}

/// The record version a template's `ServerHello` goes out in.
pub(super) fn record_version(answer: &Answer) -> ProtocolVersion {
    ProtocolVersion::from(answer.record_version().0)
}

/// The `EncryptedExtensions` the template renders, noting ALPS, which the client answers
/// before its `Finished`. The caller has already called [`agree`], since whether early
/// data can be accepted depends on the ALPN it picks.
pub(super) fn encrypted_extensions(
    answer: &Answer,
    cx: &mut ServerContext<'_>,
) -> Result<HandshakeMessagePayload<'static>, Error> {
    cx.data.template_alps = answer.alps.map(|kind| kind.0);
    let rendered = answer
        .render_encrypted_extensions()
        .map_err(|error| Error::General(error.to_string()))?;
    Ok(raw(HandshakeType::EncryptedExtensions, &rendered))
}

/// Applies what the template's answer agrees to on a connection of `version`: the
/// protocol ALPN picked, and the record size the client asked for, keeping a
/// `configured` `ServerConfig::max_fragment_size` that is smaller.
pub(super) fn agree(
    answer: &Answer,
    cx: &mut ServerContext<'_>,
    version: ProtocolVersion,
    configured: Option<usize>,
) -> Result<(), Error> {
    cx.common.alpn_protocol = answer
        .alpn
        .clone()
        .map(ProtocolName::from);
    cap_records(cx.common, answer, version, configured)
}

/// Caps what the server sends at what the template's answer agreed to: the client's
/// `record_size_limit` (RFC 8449), which on TLS 1.3 counts the content type byte, and
/// a `max_fragment_length` (RFC 6066 §4). A `configured` fragment size below the cap
/// stays, as the client side keeps it.
fn cap_records(
    common: &mut CommonState,
    answer: &Answer,
    version: ProtocolVersion,
    configured: Option<usize>,
) -> Result<(), Error> {
    let mut plaintext = MAX_FRAGMENT_LEN;
    if let Some(limit) = answer.record_size_limit {
        if limit < 64 {
            return Err(common.send_fatal_alert(
                AlertDescription::IllegalParameter,
                PeerMisbehaved::IllegalRecordSizeLimit,
            ));
        }
        plaintext = plaintext.min(match version {
            ProtocolVersion::TLSv1_3 => usize::from(limit) - 1,
            _ => usize::from(limit),
        });
    }
    if let Some(code @ 1..=4) = answer.max_fragment_length {
        plaintext = plaintext.min(1 << (8 + usize::from(code)));
    }
    if plaintext == MAX_FRAGMENT_LEN {
        return Ok(());
    }
    let capped = plaintext + PACKET_OVERHEAD;
    common.set_max_fragment_size(Some(configured.map_or(capped, |size| size.min(capped))))
}

/// Keeps `ocsp` only where the template's answer staples one, recording a shortfall
/// and leaving it out of the answer where it staples one the fork doesn't have.
pub(super) fn staple<'a>(
    answer: &mut Answer,
    ocsp: Option<&'a [u8]>,
    cx: &mut ServerContext<'_>,
) -> Option<&'a [u8]> {
    match (answer.staple, ocsp) {
        (true, Some(ocsp)) => Some(ocsp),
        (true, None) => {
            answer.drop_staple();
            cx.data
                .template_shortfalls
                .push(ServerShortfall::CertificateExtension(
                    faim_template::ExtensionType::STATUS_REQUEST,
                ));
            None
        }
        (false, _) => None,
    }
}

/// The compressor to send the certificate with: the template's algorithm, where the
/// fork has a compressor for it; none where the server sent it uncompressed.
pub(super) fn compressor(
    answer: &Answer,
    config: &ServerConfig,
    cx: &mut ServerContext<'_>,
) -> Option<&'static dyn compress::CertCompressor> {
    let algorithm = answer.certificate_compression?;
    let found = config
        .cert_compressors
        .iter()
        .find(|compressor| u16::from(compressor.algorithm()) == algorithm.0)
        .copied();
    if found.is_none() {
        cx.data
            .template_shortfalls
            .push(ServerShortfall::CertificateCompression(algorithm));
    }
    found
}

/// The schemes TLS 1.2's `ServerKeyExchange` may be signed with: the template's alone,
/// where the client offered it and `key` can sign with it, else `stock`.
pub(super) fn key_exchange_schemes(
    answer: &Answer,
    stock: Vec<SignatureScheme>,
    key: &dyn sign::SigningKey,
    cx: &mut ServerContext<'_>,
) -> Vec<SignatureScheme> {
    let Some(wanted) = answer.signature_scheme else {
        return stock;
    };
    let scheme = SignatureScheme::from(wanted.0);
    if stock.contains(&scheme) && key.choose_scheme(&[scheme]).is_some() {
        alloc::vec![scheme]
    } else {
        cx.data
            .template_shortfalls
            .push(ServerShortfall::SignatureScheme(wanted));
        stock
    }
}

/// Reads the client's `EncryptedExtensions`, which a client that agreed to ALPS sends
/// before its `Finished`, into `transcript`. Its settings are the client's, which
/// faim-http#198 reads.
pub(super) fn read_client_encrypted_extensions(
    cx: &mut ServerContext<'_>,
    m: &Message<'_>,
    transcript: &mut HandshakeHash,
) -> Result<(), Error> {
    require_handshake_msg!(
        m,
        HandshakeType::EncryptedExtensions,
        HandshakePayload::EncryptedExtensions
    )?;
    cx.data.template_alps = None;
    transcript.add_message(m);
    Ok(())
}

/// The handshake message `rendered`, header included, carried as it is.
fn raw(kind: HandshakeType, rendered: &[u8]) -> HandshakeMessagePayload<'static> {
    let body = rendered.get(4..).unwrap_or_default();
    HandshakeMessagePayload(HandshakePayload::Unknown((
        kind,
        Payload::new(body.to_vec()),
    )))
}
