//! FAIM: sending a client's hello from its template.
//!
//! When `ClientConfig::hello_template` holds a template, the client sends the hello
//! the template renders in place of its own. Whatever the server then picks is checked
//! against what the template offered, as stock rustls checks it against what its own
//! hello offered: a pick the template never offered is refused as stock rustls refuses
//! one, and a pick it offered that the fork can't complete is a [`Shortfall`].
//! `PATCHES.md` lists every place this reaches into rustls.

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

pub(in crate::client) use faim_template::Shortfall;
use faim_template::{ClientTemplate, EchPayload, Fresh, KeyShare, KeyShareSlot, RetryRequest};
use pki_types::ServerName;

use super::{
    ClientContext, ClientHelloInput, ExpectServerHello, ExpectServerHelloOrHelloRetryRequest,
    NextStateOrError,
};
use crate::SupportedCipherSuite;
use crate::client::{ClientConfig, EchStatus, tls13};
use crate::common_state::{CommonState, HandshakeFlightTls13, KxState};
use crate::crypto::{ActiveKeyExchange, SecureRandom};
use crate::enums::{
    AlertDescription, CertificateCompressionAlgorithm, CipherSuite, ContentType, HandshakeType,
    ProtocolVersion, SignatureScheme,
};
use crate::error::{Error, InvalidMessage, PeerIncompatible, PeerMisbehaved};
use crate::hash_hs::HandshakeHashBuffer;
use crate::msgs::base::Payload;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::{ExtensionType, NamedGroup};
use crate::msgs::fragmenter::{MAX_FRAGMENT_LEN, PACKET_OVERHEAD};
use crate::msgs::handshake::{
    ClientExtensionsInput, HandshakeMessagePayload, HandshakePayload, HelloRetryRequest,
    ServerExtensions, ServerHelloPayload, SessionId,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::sync::Arc;

/// The `delegated_credential` extension (RFC 9345). A server that sends one signs the
/// handshake with the credential's key, which the fork can't verify.
const DELEGATED_CREDENTIAL: u16 = 0x0022;

/// The two `application_settings` codepoints Chromium has sent for ALPS.
const APPLICATION_SETTINGS: [u16; 2] = [0x4469, 0x44cd];

/// A session id as long as `template`'s, of random bytes.
pub(in crate::client) fn session_id(
    template: &ClientTemplate,
    secure_random: &dyn SecureRandom,
) -> Result<SessionId, Error> {
    let len = template.session_id_len();
    let mut encoded = vec![0; len + 1];
    encoded[0] = len as u8;
    secure_random.fill(&mut encoded[1..])?;
    SessionId::read(&mut Reader::init(&encoded)).map_err(Error::from)
}

/// A server's `HelloRetryRequest`, and the suite it picked.
pub(super) struct Retry<'a> {
    pub(super) request: &'a HelloRetryRequest,
    pub(super) suite: SupportedCipherSuite,
}

/// Sends the hello `template` renders, reshaped for `retry` when the server asked for
/// one, and returns the state that awaits the server's answer.
///
/// Each key share the template offers gets a fresh key: one from `shares` (the shares
/// a first hello sent) when one is for its group, else one the provider makes. A group
/// the provider can't make a key for gets random bytes of the recorded length, since a
/// server that picks it gets a [`Shortfall`] anyway; a retry sends those bytes again.
pub(super) fn emit_client_hello(
    template: Arc<ClientTemplate>,
    mut transcript_buffer: HandshakeHashBuffer,
    retry: Option<Retry<'_>>,
    mut shares: Vec<Box<dyn ActiveKeyExchange>>,
    extra_exts: ClientExtensionsInput<'static>,
    mut input: ClientHelloInput,
    cx: &mut ClientContext<'_>,
) -> NextStateOrError<'static> {
    let config = Arc::clone(&input.config);
    let retryreq = retry
        .as_ref()
        .map(|retry| retry.request);
    let template = match retryreq {
        Some(hrr) => Cow::Owned(
            template.retry(&RetryRequest::new(
                hrr.key_share.map(named_group),
                hrr.cookie
                    .as_ref()
                    .map(|cookie| cookie.0.clone()),
            )),
        ),
        None => Cow::Borrowed(&*template),
    };
    let random = config.provider.secure_random;

    let mut fresh = Fresh::new(input.random.0, input.session_id.as_ref().to_vec());
    fresh.server_name = match &input.server_name {
        // RFC 6066: no trailing dot, as stock rustls's `ServerNamePayload` sends it.
        ServerName::DnsName(name) if config.enable_sni => {
            let name = name.as_ref();
            Some(
                name.strip_suffix('.')
                    .unwrap_or(name)
                    .to_string(),
            )
        }
        _ => None,
    };

    let sent_before = core::mem::take(&mut input.template_key_shares);
    let mut active = Vec::new();
    for slot in template.key_share_slots() {
        let KeyShareSlot::Key { group, len } = slot else {
            continue;
        };
        let named = NamedGroup::from(group.0);
        let reused = shares
            .iter()
            .position(|share| share.group() == named)
            .map(|at| shares.swap_remove(at));
        let made = match reused {
            Some(share) => Some(share),
            None => config
                .find_kx_group(named, ProtocolVersion::TLSv1_3)
                .map(|skxg| skxg.start())
                .transpose()?,
        };
        let key = match made {
            Some(share) => {
                let key = share.pub_key().to_vec();
                active.push(share);
                key
            }
            // The server asked for this group, so it would pick it.
            None if retryreq.and_then(|hrr| hrr.key_share) == Some(named) => {
                return Err(cx.common.send_fatal_alert(
                    AlertDescription::HandshakeFailure,
                    Shortfall::Group(*group),
                ));
            }
            // A retry that asks for no group gets the same bytes (RFC 8446 §4.1.2).
            None => match sent_before
                .iter()
                .find(|share| share.group == *group)
            {
                Some(share) => share.key.clone(),
                None => random_bytes(random, usize::from(*len))?,
            },
        };
        fresh
            .key_shares
            .push(KeyShare::new(*group, key));
    }
    input.template_key_shares = fresh.key_shares.clone();

    // GREASE ECH in the client's shape (faim-http#200). A retry sends the first hello's bytes
    // again (RFC 9849 §6.2).
    fresh.ech = match (template.ech(), input.template_ech.take()) {
        (None, _) => None,
        (Some(_), Some(sent)) => Some(sent),
        (Some(shape), None) => Some(EchPayload::new(
            random_bytes(random, shape.enc_len())?,
            random_bytes(random, shape.payload_len())?,
        )),
    };
    if fresh.ech.is_some() {
        // A server's retry configs are then ignored rather than refused.
        cx.data.ech_status = EchStatus::Grease;
    }
    input.template_ech = fresh.ech.clone();

    let rendered = template
        .render(&fresh)
        .map_err(|error| Error::General(error.to_string()))?;
    // rustls reads the hello it sends, as it would its own, for what it checks the
    // server's answer against.
    let payload = MessagePayload::new(
        ContentType::Handshake,
        ProtocolVersion::TLSv1_2,
        &rendered.message,
    )?
    .into_owned();
    let MessagePayload::Handshake {
        parsed: HandshakeMessagePayload(HandshakePayload::ClientHello(hello)),
        ..
    } = &payload
    else {
        return Err(Error::General(
            "a template rendered something other than a ClientHello".to_string(),
        ));
    };
    input.hello.sent_extensions = rendered
        .offered
        .iter()
        .map(|kind| ExtensionType::from(kind.0))
        .collect();
    input.hello.offered_cipher_suites = hello.cipher_suites.clone();
    input.hello.alpn_protocols = hello
        .protocols
        .clone()
        .unwrap_or_default();
    input.hello.offered_cert_compression = hello
        .certificate_compression_algorithms
        .is_some();
    let offers_tls13 = template.offers_version(protocol_version(ProtocolVersion::TLSv1_3));

    let ch = Message {
        version: match retryreq {
            Some(_) => ProtocolVersion::TLSv1_2,
            None => ProtocolVersion::from(template.record_version().0),
        },
        payload,
    };
    if retryreq.is_some() {
        tls13::emit_fake_ccs(&mut input.sent_tls13_fake_ccs, cx.common);
    }
    transcript_buffer.add_message(&ch);
    cx.common.send_msg(ch, false);

    let mut active = active.into_iter();
    let next = ExpectServerHello {
        input,
        transcript_buffer,
        early_data_key_schedule: None,
        offered_key_share: active.next(),
        template_shares: active.collect(),
        suite: retry.map(|retry| retry.suite),
        ech_state: None,
    };
    Ok(if offers_tls13 && retryreq.is_none() {
        Box::new(ExpectServerHelloOrHelloRetryRequest {
            next,
            extra_exts: extra_exts.into_owned(),
        })
    } else {
        Box::new(next)
    })
}

/// Checks the protocol version a server picked against what `template` offered.
pub(super) fn check_version(
    common: &mut CommonState,
    template: &ClientTemplate,
    version: ProtocolVersion,
) -> Result<(), Error> {
    let speakable = matches!(version, ProtocolVersion::TLSv1_2 | ProtocolVersion::TLSv1_3);
    if !template.offers_version(protocol_version(version)) {
        return Err(common.send_fatal_alert(
            AlertDescription::ProtocolVersion,
            match speakable {
                true => PeerIncompatible::ServerTlsVersionIsDisabledByOurConfig,
                false => PeerIncompatible::ServerDoesNotSupportTls12Or13,
            },
        ));
    }
    if !speakable {
        return Err(common.send_fatal_alert(
            AlertDescription::ProtocolVersion,
            Shortfall::Version(protocol_version(version)),
        ));
    }
    Ok(())
}

/// The error for `suite`, which a server picked and the provider can't complete: a
/// [`Shortfall`] when `template` offered it, else `unoffered` with its alert.
pub(super) fn unknown_cipher_suite(
    common: &mut CommonState,
    template: &ClientTemplate,
    suite: CipherSuite,
    unoffered: (AlertDescription, PeerMisbehaved),
) -> Error {
    match template.offers_cipher_suite(cipher_suite(suite)) {
        true => common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Shortfall::CipherSuite(cipher_suite(suite)),
        ),
        false => common.send_fatal_alert(unoffered.0, unoffered.1),
    }
}

/// Whether `template`'s hello sent a key share for `group`, as a key or as random bytes.
pub(super) fn sent_key_share(template: &ClientTemplate, group: NamedGroup) -> bool {
    template.key_share_slots().any(
        |slot| matches!(slot, KeyShareSlot::Key { group: sent, .. } if *sent == named_group(group)),
    )
}

/// The key share for the group `server_hello` picked, which must be one `template`'s
/// hello sent a key for: the hybrid X25519MLKEM768 share's X25519 half is no share of
/// its own. A group the template offered that the fork can't compute is a [`Shortfall`].
pub(super) fn choose_key_share(
    offered: Option<Box<dyn ActiveKeyExchange>>,
    extra: Vec<Box<dyn ActiveKeyExchange>>,
    server_hello: &ServerHelloPayload,
    template: &ClientTemplate,
    config: &ClientConfig,
    cx: &mut ClientContext<'_>,
) -> Result<Box<dyn ActiveKeyExchange>, Error> {
    let Some(theirs) = server_hello
        .key_share
        .as_ref()
        .map(|share| share.group)
    else {
        return Err(cx.common.send_fatal_alert(
            AlertDescription::MissingExtension,
            PeerMisbehaved::MissingKeyShare,
        ));
    };
    let skxg = config.find_kx_group(theirs, ProtocolVersion::TLSv1_3);
    let mut shares: Vec<_> = offered
        .into_iter()
        .chain(extra)
        .collect();
    if let (Some(at), Some(skxg)) = (
        shares
            .iter()
            .position(|share| share.group() == theirs),
        skxg,
    ) {
        cx.common.kx_state = KxState::Start(skxg);
        return Ok(shares.swap_remove(at));
    }
    Err(match (template.offers_group(named_group(theirs)), skxg) {
        (true, None) => cx.common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Shortfall::Group(named_group(theirs)),
        ),
        // Unoffered, or a group the fork could compute that the server had to ask
        // for with a retry.
        _ => cx.common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::WrongGroupForKeyShare,
        ),
    })
}

/// Checks the curve a TLS 1.2 server picked against what `template` offered.
pub(in crate::client) fn check_curve(
    common: &mut CommonState,
    template: &ClientTemplate,
    config: &ClientConfig,
    group: NamedGroup,
) -> Result<(), Error> {
    if !template.offers_group(named_group(group)) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::SelectedUnofferedKxGroup,
        ));
    }
    match config.find_kx_group(group, ProtocolVersion::TLSv1_2) {
        Some(_) => Ok(()),
        None => Err(common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Shortfall::Group(named_group(group)),
        )),
    }
}

/// Checks the scheme a server signed its handshake with against what a template
/// offered: refused when it never offered it, a [`Shortfall`] when the verifier can't
/// check it. Rustls's own hello needs no check here.
pub(in crate::client) fn check_signature_scheme(
    common: &mut CommonState,
    config: &ClientConfig,
    scheme: SignatureScheme,
) -> Result<(), Error> {
    let Some(template) = config.hello_template.as_deref() else {
        return Ok(());
    };
    let named = faim_template::SignatureScheme(u16::from(scheme));
    if !template.offers_signature_scheme(named) {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    if !config
        .verifier
        .supported_verify_schemes()
        .contains(&scheme)
    {
        return Err(common.send_fatal_alert(
            AlertDescription::HandshakeFailure,
            Shortfall::SignatureScheme(named),
        ));
    }
    Ok(())
}

/// Checks the algorithm a server compressed its certificate with against what
/// `template` offered and what the fork can decompress.
pub(in crate::client) fn check_certificate_compression(
    common: &mut CommonState,
    template: &ClientTemplate,
    config: &ClientConfig,
    algorithm: CertificateCompressionAlgorithm,
) -> Result<(), Error> {
    let named = faim_template::CertificateCompression(u16::from(algorithm));
    if !template.offers_certificate_compression(named) {
        return Err(common.send_fatal_alert(
            AlertDescription::BadCertificate,
            PeerMisbehaved::SelectedUnofferedCertCompression,
        ));
    }
    match config
        .cert_decompressors
        .iter()
        .any(|decompressor| decompressor.algorithm() == algorithm)
    {
        true => Ok(()),
        false => Err(common.send_fatal_alert(
            AlertDescription::BadCertificate,
            Shortfall::CertificateCompression(named),
        )),
    }
}

/// Caps what the client sends at the `record_size_limit` (RFC 8449) the server
/// answered with in `exts`, on a connection of `version`. TLS 1.3 counts the content
/// type byte in the limit. A `configured` `ClientConfig::max_fragment_size` below the
/// limit stays.
pub(in crate::client) fn apply_record_size_limit(
    common: &mut CommonState,
    exts: &ServerExtensions<'_>,
    version: ProtocolVersion,
    configured: Option<usize>,
) -> Result<(), Error> {
    let Some(limit) = exts.record_size_limit else {
        return Ok(());
    };
    if limit < 64 {
        return Err(common.send_fatal_alert(
            AlertDescription::IllegalParameter,
            PeerMisbehaved::IllegalRecordSizeLimit,
        ));
    }
    let plaintext = match version {
        ProtocolVersion::TLSv1_3 => usize::from(limit) - 1,
        _ => usize::from(limit),
    };
    let limited = plaintext.min(MAX_FRAGMENT_LEN) + PACKET_OVERHEAD;
    common.set_max_fragment_size(Some(configured.map_or(limited, |size| size.min(limited))))
}

/// Refuses a server's answer to an extension the template offered that rustls doesn't
/// handle, other than those in `handled`. Such an answer can oblige the client to
/// something the fork doesn't do (an acked `max_fragment_length` caps every record), so
/// it's a [`Shortfall`] FAIM passes through rather than a connection that breaks later.
pub(in crate::client) fn check_unhandled_extensions(
    common: &mut CommonState,
    exts: &ServerExtensions<'_>,
    handled: &[u16],
) -> Result<(), Error> {
    match exts
        .unknown_extensions
        .iter()
        .find(|kind| !handled.contains(kind))
    {
        Some(kind) => Err(common.send_fatal_alert(
            AlertDescription::UnsupportedExtension,
            Shortfall::Extension(faim_template::ExtensionType(*kind)),
        )),
        None => Ok(()),
    }
}

/// Notes what a template's hello asked of the client that the server's
/// `EncryptedExtensions` agreed to: ALPS, to answer before the client's `Finished`, and
/// a record size limit. An answer to any other extension rustls doesn't handle is a
/// shortfall.
pub(in crate::client) fn note_encrypted_extensions(
    cx: &mut ClientContext<'_>,
    exts: &ServerExtensions<'_>,
    config: &ClientConfig,
) -> Result<(), Error> {
    check_unhandled_extensions(cx.common, exts, &APPLICATION_SETTINGS)?;
    cx.data.template_alps = exts
        .unknown_extensions
        .iter()
        .copied()
        .find(|kind| APPLICATION_SETTINGS.contains(kind));
    apply_record_size_limit(
        cx.common,
        exts,
        ProtocolVersion::TLSv1_3,
        config.max_fragment_size,
    )
}

/// Sends the client's `EncryptedExtensions` with an `application_settings` of type
/// `kind`, for a server that agreed to ALPS. The client's settings travel encrypted, so
/// the recorded hello doesn't carry them; the settings go out empty until faim-http#198 fills
/// them from the client's HTTP/2 SETTINGS.
pub(in crate::client) fn emit_client_alps(flight: &mut HandshakeFlightTls13<'_>, kind: u16) {
    let mut body = Vec::new();
    4u16.encode(&mut body);
    kind.encode(&mut body);
    0u16.encode(&mut body);
    flight.add(HandshakeMessagePayload(HandshakePayload::Unknown((
        HandshakeType::EncryptedExtensions,
        Payload::new(body),
    ))));
}

/// Checks the certificate entry extensions a server sent, of types `unknown`, which
/// rustls doesn't handle: each must answer one of `offered`, what a template's hello
/// offered (none, for rustls's own hello), and none may be a delegated credential,
/// whose key the fork can't verify with.
pub(in crate::client) fn check_certificate_extensions(
    common: &mut CommonState,
    offered: &[ExtensionType],
    mut unknown: impl Iterator<Item = u16>,
) -> Result<(), Error> {
    unknown.try_for_each(|kind| {
        if !offered.contains(&ExtensionType::from(kind)) {
            return Err(common.send_fatal_alert(
                AlertDescription::DecodeError,
                InvalidMessage::UnknownCertificateExtension,
            ));
        }
        if kind == DELEGATED_CREDENTIAL {
            return Err(common.send_fatal_alert(
                AlertDescription::HandshakeFailure,
                Shortfall::Extension(faim_template::ExtensionType(kind)),
            ));
        }
        Ok(())
    })
}

/// `version` as the template crate names it.
pub(super) fn protocol_version(version: ProtocolVersion) -> faim_template::ProtocolVersion {
    faim_template::ProtocolVersion(u16::from(version))
}

/// `suite` as the template crate names it.
pub(super) fn cipher_suite(suite: CipherSuite) -> faim_template::CipherSuite {
    faim_template::CipherSuite(u16::from(suite))
}

/// `group` as the template crate names it.
pub(in crate::client) fn named_group(group: NamedGroup) -> faim_template::NamedGroup {
    faim_template::NamedGroup(u16::from(group))
}

/// `len` random bytes.
fn random_bytes(secure_random: &dyn SecureRandom, len: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = vec![0; len];
    secure_random.fill(&mut bytes)?;
    Ok(bytes)
}

impl From<Shortfall> for Error {
    fn from(shortfall: Shortfall) -> Self {
        Self::Shortfall(shortfall)
    }
}

#[cfg(test)]
mod tests {
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
        let mut largest = 0;
        let mut rest = &records[..];
        while let [_, _, _, high, low, tail @ ..] = rest {
            let len = usize::from(u16::from_be_bytes([*high, *low]));
            largest = largest.max(len);
            rest = &tail[len..];
        }
        largest
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
}
