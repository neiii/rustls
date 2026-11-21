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
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

pub(in crate::client) use faim_template::Shortfall;
use faim_template::{
    ClientTemplate, EchPayload, Fresh, KeyShare, KeyShareSlot, Psk, PskIdentity, RenderedHello,
    RetryRequest,
};
use pki_types::ServerName;

use super::{
    ClientContext, ClientHelloInput, ExpectServerHello, ExpectServerHelloOrHelloRetryRequest,
    NextStateOrError,
};
use crate::SupportedCipherSuite;
use crate::client::ech::EchState;
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
    ServerExtensions, ServerHelloPayload, SessionId, TransportParameters,
};
use crate::msgs::message::{Message, MessagePayload};
use crate::msgs::persist;
use crate::sync::Arc;
use crate::tls13::key_schedule::KeyScheduleEarly;

/// The `delegated_credential` extension (RFC 9345). A server that sends one signs the
/// handshake with the credential's key, which the fork can't verify.
const DELEGATED_CREDENTIAL: u16 = 0x0022;

/// The two `application_settings` codepoints Chromium has sent for ALPS.
const APPLICATION_SETTINGS: [u16; 2] = [0x4469, 0x44cd];

/// The `trust_anchors` extension (draft-ietf-tls-trust-anchor-ids), which Chrome offers.
/// A server's answer in `EncryptedExtensions` lists the anchors it has paths for, which
/// a client uses only to retry after a certificate error (§5.6): it obliges the client
/// to nothing in a handshake that succeeds.
const TRUST_ANCHORS: u16 = 0xca34;

/// The extensions rustls doesn't parse that a server's TLS 1.3 `EncryptedExtensions` may
/// answer: ALPS, which the fork answers before its `Finished`, and `trust_anchors`. The
/// destructuring stops compiling when `APPLICATION_SETTINGS` gains a codepoint, so this
/// list can't leave one out.
const ENCRYPTED_EXTENSIONS_ANSWERED: [u16; 3] = {
    let [alps, alps_old] = APPLICATION_SETTINGS;
    [alps, alps_old, TRUST_ANCHORS]
};

/// The handshake messages a server answered a template's hello with, kept for
/// [`ClientConnection::server_flight`].
///
/// [`ClientConnection::server_flight`]: crate::client::ClientConnection::server_flight
#[derive(Debug, Default)]
pub(in crate::client) struct KeptFlight {
    pub(in crate::client) server_hello: Vec<u8>,
    pub(in crate::client) encrypted_extensions: Option<Vec<u8>>,
    pub(in crate::client) certificate: Vec<u8>,
    pub(in crate::client) certificate_compression: Option<faim_template::CertificateCompression>,
    pub(in crate::client) certificate_status: Option<Vec<u8>>,
    pub(in crate::client) server_key_exchange: Option<Vec<u8>>,
}

impl KeptFlight {
    /// The flight as `faim_template` reads it, once it holds a `ServerHello`. A
    /// resumed handshake has no `Certificate` to keep.
    pub(in crate::client) fn as_flight(&self) -> Option<faim_template::ServerFlight<'_>> {
        if self.server_hello.is_empty() {
            return None;
        }
        Some(faim_template::ServerFlight {
            server_hello: &self.server_hello,
            encrypted_extensions: self.encrypted_extensions.as_deref(),
            certificate: &self.certificate,
            certificate_compression: self.certificate_compression,
            certificate_status: self.certificate_status.as_deref(),
            server_key_exchange: self.server_key_exchange.as_deref(),
            new_session_tickets: &[],
        })
    }
}

/// `m`'s bytes as they came, with its four-byte header; empty for a message that isn't
/// a handshake message, which no caller passes.
pub(in crate::client) fn encoded<'a>(m: &'a Message<'_>) -> &'a [u8] {
    match &m.payload {
        MessagePayload::Handshake { encoded, .. } => encoded.bytes(),
        _ => &[],
    }
}

/// Keeps the `ServerHello` `m` as a TLS record in the version it came in, the form
/// `faim_template` reads. rustls has joined whatever records carried it. One too long
/// for a single record is left out, and the flight with it: no server sends one.
pub(in crate::client) fn keep_server_hello(cx: &mut ClientContext<'_>, m: &Message<'_>) {
    let message = encoded(m);
    let Ok(len) = u16::try_from(message.len()) else {
        return;
    };
    let mut record = Vec::with_capacity(message.len() + 5);
    record.push(u8::from(ContentType::Handshake));
    record.extend_from_slice(&u16::from(m.version).to_be_bytes());
    record.extend_from_slice(&len.to_be_bytes());
    record.extend_from_slice(message);
    cx.data.template_flight.server_hello = record;
}

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
///
/// With `ech_state`, the hello sends real ECH (faim-http#601): the template's inner hello,
/// sealed under the config `ech_state` was made from, with the outer hello naming that
/// config's public name. A retry after a `HelloRetryRequest` that rejected the ECH sends
/// the first hello's ECH bytes again, as stock rustls does.
#[allow(clippy::too_many_arguments)]
pub(super) fn emit_client_hello(
    template: Arc<ClientTemplate>,
    mut transcript_buffer: HandshakeHashBuffer,
    retry: Option<Retry<'_>>,
    mut shares: Vec<Box<dyn ActiveKeyExchange>>,
    extra_exts: ClientExtensionsInput<'static>,
    mut input: ClientHelloInput,
    cx: &mut ClientContext<'_>,
    mut ech_state: Option<EchState>,
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
    // Under real ECH the outer hello names the config real ECH goes out under, which may
    // not be the one its client named, and the inner hello is the one that may resume and
    // send early data.
    let template = match &ech_state {
        Some(ech) => {
            let (config_id, suite) = ech.template_config();
            Cow::Owned(template.under_ech_config(config_id, suite))
        }
        None => template,
    };
    let resuming_hello = match &ech_state {
        Some(_) => template.inner().unwrap_or(&template),
        None => &template,
    };

    // FAIM: the session this connection resumes, if faim-http gave it one. A retry resumes
    // it only under a suite that can (RFC 8446 §4.2.11).
    let resuming = input.resuming.take();
    let session = tls13_session(&resuming, retry.as_ref());
    // Early data needs a session that allows it, on a first hello that offers it.
    let early_data = session
        .as_ref()
        .filter(|session| {
            config.enable_early_data
                && retryreq.is_none()
                && session.max_early_data_size() > 0
                && resuming_hello.offers(faim_template::ExtensionType::EARLY_DATA)
        })
        .map(|session| session.max_early_data_size() as usize);
    let template = match early_data {
        Some(_) => template,
        None => Cow::Owned(template.without_early_data()),
    };

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
    // FAIM: a QUIC connection's own transport parameters go out in the template's
    // extension 57, where its client sent its own, which carry the client's source
    // connection id (faim-http#202).
    fresh.quic_transport_parameters = quic_transport_parameters(&extra_exts)?;

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
    if fresh.ech.is_some() && ech_state.is_none() {
        // A server's retry configs are then ignored rather than refused.
        cx.data.ech_status = EchStatus::Grease;
    }

    let psk = session.as_ref().map(|session| {
        cx.common.suite = Some(session.suite().into());
        let binder = vec![
            0;
            session
                .suite()
                .common
                .hash_provider
                .output_len()
        ];
        Psk::new(vec![PskIdentity::new(
            session.ticket().to_vec(),
            session.obfuscated_ticket_age(),
            binder,
        )])
    });

    let (rendered, early_data_key_schedule) = match ech_state.as_mut() {
        Some(ech) if cx.data.ech_status != EchStatus::Rejected => {
            let inner = InnerFresh {
                server_name: fresh.server_name.take(),
                psk,
            };
            // The outer hello names the config's public name.
            fresh.server_name = Some(ech.outer_name.as_ref().to_string());
            let sent = seal_inner(
                &template,
                &mut fresh,
                inner,
                ech,
                session.as_ref(),
                retryreq.is_some(),
                random,
            )?;
            cx.data.ech_status = EchStatus::Offered;
            cx.data.ech_inner_hello = Some(ech.sent_inner_hello.clone());
            sent
        }
        // A `HelloRetryRequest` rejected the ECH: the outer hello goes again with the
        // first hello's ECH bytes (RFC 9849 §6.1.5), still naming the public name, and
        // with a GREASE PSK in the inner one's shape, so nothing resumes in the clear.
        Some(ech) => {
            fresh.server_name = Some(ech.outer_name.as_ref().to_string());
            fresh.psk = psk
                .as_ref()
                .map(|psk| grease_psk(psk, random))
                .transpose()?;
            let rendered = template
                .render(&fresh)
                .map_err(render_error)?;
            (rendered, None)
        }
        None => {
            fresh.psk = psk;
            let mut rendered = template
                .render(&fresh)
                .map_err(render_error)?;
            let early_data_key_schedule = session.as_ref().map(|session| {
                tls13::fill_in_template_psk_binder(
                    session,
                    &transcript_buffer,
                    &mut rendered.message,
                )
            });
            (rendered, early_data_key_schedule)
        }
    };
    input.template_ech = fresh.ech.clone();
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

    if let (Some(session), Some(schedule), Some(max)) =
        (&session, &early_data_key_schedule, early_data)
    {
        cx.data.early_data.enable(max);
        // Under real ECH, the inner hello's transcript and random (RFC 9849 §6.1).
        let (early_transcript, early_random) = match ech_state
            .as_ref()
            .filter(|_| cx.data.ech_status == EchStatus::Offered)
        {
            Some(ech) => (&ech.inner_hello_transcript, &ech.inner_hello_random.0),
            None => (&transcript_buffer, &input.random.0),
        };
        tls13::derive_early_traffic_secret(
            &*config.key_log,
            cx,
            session.suite().common.hash_provider,
            schedule,
            &mut input.sent_tls13_fake_ccs,
            early_transcript,
            early_random,
        );
    }
    drop(session);
    input.resuming = resuming;

    let mut active = active.into_iter();
    let next = ExpectServerHello {
        input,
        transcript_buffer,
        early_data_key_schedule,
        offered_key_share: active.next(),
        template_shares: active.collect(),
        suite: retry.map(|retry| retry.suite),
        ech_state,
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

/// The TLS 1.3 session in `resuming` to offer, if there is one a `retry` can still offer.
fn tls13_session<'a>(
    resuming: &'a Option<persist::Retrieved<super::ClientSessionValue>>,
    retry: Option<&Retry<'_>>,
) -> Option<persist::Retrieved<&'a persist::Tls13ClientSessionValue>> {
    let session = resuming
        .as_ref()?
        .map(|value| value.tls13())?;
    if session.ticket().is_empty() {
        return None;
    }
    match retry.map(|retry| retry.suite) {
        None => {}
        Some(SupportedCipherSuite::Tls13(suite)) => {
            suite.can_resume_from(session.suite())?;
        }
        #[cfg(feature = "tls12")]
        Some(SupportedCipherSuite::Tls12(_)) => return None,
    }
    Some(session)
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
/// a record size limit. A `trust_anchors` answer obliges the client to nothing. An
/// answer to any other extension rustls doesn't handle is a shortfall.
pub(in crate::client) fn note_encrypted_extensions(
    cx: &mut ClientContext<'_>,
    exts: &ServerExtensions<'_>,
    config: &ClientConfig,
) -> Result<(), Error> {
    check_unhandled_extensions(cx.common, exts, &ENCRYPTED_EXTENSIONS_ANSWERED)?;
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

/// What an inner hello sends of the connection's own: the name it asks for, and the
/// session it resumes.
struct InnerFresh {
    server_name: Option<String>,
    psk: Option<Psk>,
}

/// The transport parameters a QUIC connection sends in its hello, for a template to send
/// in its client's place; `None` over TCP. QUIC drafts sent them in another extension,
/// which a template from a QUIC v1 or v2 hello doesn't carry, so a draft connection
/// can't send a template.
fn quic_transport_parameters(
    extra_exts: &ClientExtensionsInput<'static>,
) -> Result<Option<Vec<u8>>, Error> {
    match &extra_exts.transport_parameters {
        Some(TransportParameters::Quic(parameters)) => Ok(Some(parameters.bytes().to_vec())),
        Some(TransportParameters::QuicDraft(_)) => Err(Error::General(
            "a hello template can't send a QUIC draft's transport parameters".into(),
        )),
        None => Ok(None),
    }
}

/// The outer hello `template` sends with `fresh`, its inner hello sealed inside under
/// `ech` (RFC 9849 §6.1, faim-http#601), and the early key schedule of a session the
/// inner hello resumes.
///
/// The inner hello takes the outer hello's fresh keys, group by group, and a group only
/// it sends a key share for is a [`Shortfall`]. It is padded to the length its client
/// sealed, so the payload is as long as the client's. The outer hello carries a GREASE
/// PSK of the inner one's shape (§6.1.2), and the inner hello goes into `ech`'s transcript.
fn seal_inner(
    template: &ClientTemplate,
    fresh: &mut Fresh,
    inner: InnerFresh,
    ech: &mut EchState,
    session: Option<&persist::Retrieved<&persist::Tls13ClientSessionValue>>,
    retrying: bool,
    random: &'static dyn SecureRandom,
) -> Result<(RenderedHello, Option<KeyScheduleEarly>), Error> {
    let (Some(inner_template), Some(shape)) = (template.inner(), template.ech()) else {
        return Err(Error::General(
            "a template sends real ECH only with an inner hello and an outer ECH extension"
                .to_string(),
        ));
    };
    let mut inner_fresh = Fresh::new(ech.inner_hello_random.0, Vec::new());
    inner_fresh.server_name = inner.server_name;
    // An inner hello that sends its own transport parameters, rather than naming the
    // outer hello's in `ech_outer_extensions`, sends this connection's too.
    if inner_template
        .extensions()
        .iter()
        .any(|extension| {
            extension.kind() == faim_template::ExtensionType::QUIC_TRANSPORT_PARAMETERS
        })
    {
        inner_fresh.quic_transport_parameters = fresh.quic_transport_parameters.clone();
    }
    for slot in inner_template.key_share_slots() {
        let KeyShareSlot::Key { group, .. } = slot else {
            continue;
        };
        let share = fresh
            .key_shares
            .iter()
            .find(|share| share.group == *group)
            .ok_or(Shortfall::InnerKeyShare(*group))?;
        inner_fresh
            .key_shares
            .push(share.clone());
    }
    fresh.psk = inner
        .psk
        .as_ref()
        .map(|psk| grease_psk(psk, random))
        .transpose()?;
    inner_fresh.psk = inner.psk;

    // A hello after a `HelloRetryRequest` carries no `enc` (RFC 9849 §6.1.5).
    let enc = match retrying {
        true => Vec::new(),
        false => ech.template_enc().to_vec(),
    };
    let tag_len = ech.template_tag_len();
    let padded_len = shape
        .payload_len()
        .saturating_sub(tag_len);
    fresh.ech = Some(EchPayload::new(enc.clone(), vec![0; shape.payload_len()]));
    let mut outer = template
        .render(fresh)
        .map_err(render_error)?;
    let mut sealed = inner_template
        .render_inner(&inner_fresh, &outer.message, padded_len)
        .map_err(render_error)?;
    let early_key_schedule = match session {
        Some(session) => {
            let schedule = tls13::fill_in_template_psk_binder(
                session,
                &ech.inner_hello_transcript,
                &mut sealed.hello.message,
            );
            // The binder goes into the sealed hello too, where the PSK comes last as well.
            let hash_len = session
                .suite()
                .common
                .hash_provider
                .output_len();
            let message = &sealed.hello.message;
            let binder = message[message.len() - hash_len..].to_vec();
            if let Some(identity) = inner_fresh
                .psk
                .as_mut()
                .and_then(|psk| psk.identities.first_mut())
            {
                identity.binder = binder;
            }
            sealed = inner_template
                .render_inner(&inner_fresh, &outer.message, padded_len)
                .map_err(render_error)?;
            Some(schedule)
        }
        None => None,
    };
    let payload_len = sealed.encoded.len() + tag_len;
    if payload_len != shape.payload_len() {
        fresh.ech = Some(EchPayload::new(enc.clone(), vec![0; payload_len]));
        outer = template
            .render(fresh)
            .map_err(render_error)?;
    }
    // The AAD is the outer hello's body with its payload zeroed (RFC 9849 §5.2).
    let payload = ech.seal_template_inner(&outer.message[4..], &sealed.encoded)?;
    fresh.ech = Some(EchPayload::new(enc, payload));
    let outer = template
        .render(fresh)
        .map_err(render_error)?;

    let inner_message = Message {
        version: ProtocolVersion::TLSv1_2,
        payload: MessagePayload::new(
            ContentType::Handshake,
            ProtocolVersion::TLSv1_2,
            &sealed.hello.message,
        )?
        .into_owned(),
    };
    let sent = sealed
        .hello
        .offered
        .iter()
        .map(|kind| ExtensionType::from(kind.0))
        .collect();
    ech.take_template_inner(&inner_message, sent);
    Ok((outer, early_key_schedule))
}

/// A GREASE PSK in `psk`'s shape: random identities, ages and binders of the same
/// lengths (RFC 9849 §6.1.2).
fn grease_psk(psk: &Psk, random: &dyn SecureRandom) -> Result<Psk, Error> {
    let identities = psk
        .identities
        .iter()
        .map(|identity| {
            let mut age = [0; 4];
            random.fill(&mut age)?;
            Ok(PskIdentity::new(
                random_bytes(random, identity.identity.len())?,
                u32::from_be_bytes(age),
                random_bytes(random, identity.binder.len())?,
            ))
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(Psk::new(identities))
}

/// A template that didn't render, as rustls's error.
fn render_error(error: faim_template::RenderError) -> Error {
    Error::General(error.to_string())
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
mod tests;
