//! FAIM: opening a client's ECH with keys the server holds (RFC 9849 §7.1,
//! faim-http#600).
//!
//! Stock rustls has no server side of ECH. FAIM substitutes its own keys into the ECH
//! configs its clients read (faim-http's ADR-0026), so its client leg opens what they
//! seal: on a peeked hello before any handshake ([`Accepted::open_ech`]), and in the
//! handshake, which then runs on the inner hello ([`ServerConfig::ech_keys`]).
//!
//! Everything here works on the bytes the client sent, never on a hello decoded and
//! encoded again: the AAD is the outer hello as sent, and the inner hello is rebuilt
//! from the client's own extension bytes, so the transcript is the client's.
//!
//! [`Accepted::open_ech`]: crate::server::Accepted::open_ech
//! [`ServerConfig::ech_keys`]: crate::server::ServerConfig::ech_keys

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use crate::crypto::hpke::{EncapsulatedSecret, Hpke, HpkeOpener, HpkePrivateKey};
use crate::enums::{
    AlertDescription, ContentType, EchClientHelloType, HandshakeType, ProtocolVersion,
};
use crate::error::{EncryptedClientHelloError, Error};
use crate::msgs::codec::{Codec, Reader, u24};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{EchConfigPayload, HpkeSymmetricCipherSuite};
use crate::msgs::message::{Message, MessagePayload};
use crate::sync::Arc;

/// FAIM: an ECH config a server opens a client's ECH under, with the private key of
/// the config's public key.
pub struct EchServerKey {
    /// The config as published, its version and length included: HPKE's `info` is
    /// made of these bytes.
    config: Vec<u8>,
    config_id: u8,
    /// The HPKE suites the config names that the server can open with.
    suites: Vec<&'static dyn Hpke>,
    private_key: HpkePrivateKey,
}

impl EchServerKey {
    /// `config`, one `ECHConfig` as its publisher encoded it, whose public key
    /// `private_key` is the private key of, opened with those of `hpke_suites` the
    /// config names.
    ///
    /// # Errors
    ///
    /// [`EncryptedClientHelloError::InvalidConfigList`] when `config` isn't one whole
    /// `ECHConfig` of the version rustls reads, and
    /// [`EncryptedClientHelloError::NoCompatibleConfig`] when it names no suite of
    /// `hpke_suites`.
    pub fn new(
        config: Vec<u8>,
        private_key: HpkePrivateKey,
        hpke_suites: &[&'static dyn Hpke],
    ) -> Result<Self, Error> {
        let mut reader = Reader::init(&config);
        let parsed = EchConfigPayload::read(&mut reader)
            .ok()
            .filter(|_| !reader.any_left());
        let Some(EchConfigPayload::V18(contents)) = parsed else {
            return Err(EncryptedClientHelloError::InvalidConfigList.into());
        };
        let key_config = &contents.key_config;
        let suites: Vec<&'static dyn Hpke> = hpke_suites
            .iter()
            .filter(|hpke| {
                let suite = hpke.suite();
                suite.kem == key_config.kem_id
                    && key_config
                        .symmetric_cipher_suites
                        .contains(&suite.sym)
            })
            .copied()
            .collect();
        if suites.is_empty() {
            return Err(EncryptedClientHelloError::NoCompatibleConfig.into());
        }
        Ok(Self {
            config_id: key_config.config_id,
            config,
            suites,
            private_key,
        })
    }

    /// The config, as given.
    pub fn config(&self) -> &[u8] {
        &self.config
    }

    /// HPKE's `info` for a hello sealed to this config (RFC 9849 §6.1).
    fn info(&self) -> Vec<u8> {
        let mut info = Vec::with_capacity(self.config.len() + 8);
        info.extend_from_slice(b"tls ech\0");
        info.extend_from_slice(&self.config);
        info
    }
}

impl fmt::Debug for EchServerKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The private key stays out of logs.
        f.debug_struct("EchServerKey")
            .field("config_id", &self.config_id)
            .finish_non_exhaustive()
    }
}

/// FAIM: a client's ECH as one of the server's keys opened it.
#[derive(Debug, Clone)]
pub struct OpenedEch {
    inner_hello: Vec<u8>,
    key: usize,
}

impl OpenedEch {
    /// The inner `ClientHello`, rebuilt as the client sent it to its transcript: a
    /// handshake message, its type and length included.
    pub fn inner_hello(&self) -> &[u8] {
        &self.inner_hello
    }

    /// Which of the keys it was given opened it, as an index into them.
    pub fn key(&self) -> usize {
        self.key
    }
}

/// The ECH a handshake accepted on its first hello: what opens the second hello after
/// a `HelloRetryRequest` (RFC 9849 §7.1.1).
pub(super) struct Accepting {
    opener: Box<dyn HpkeOpener>,
    config_id: u8,
    cipher_suite: HpkeSymmetricCipherSuite,
}

/// Opens the ECH of `m`, a first `ClientHello`, with the first of `keys` that opens
/// it. `None` when the hello carries no outer ECH, or none of `keys` opens it, or what
/// it opens to isn't an inner hello: a server reads all of those as GREASE.
pub(super) fn open(m: &Message<'_>, keys: &[Arc<EchServerKey>]) -> Option<(OpenedEch, Accepting)> {
    let outer = Outer::read(handshake_bytes(m)?)?;
    if !outer.ech.enc.is_empty() {
        for (index, key) in keys.iter().enumerate() {
            if key.config_id != outer.ech.config_id {
                continue;
            }
            for hpke in &key.suites {
                if hpke.suite().sym != outer.ech.cipher_suite {
                    continue;
                }
                let Ok(mut opener) = hpke.setup_opener(
                    &EncapsulatedSecret(outer.ech.enc.to_vec()),
                    &key.info(),
                    &key.private_key,
                ) else {
                    continue;
                };
                let Some(inner_hello) = outer.open_with(&mut *opener) else {
                    continue;
                };
                let opened = OpenedEch {
                    inner_hello,
                    key: index,
                };
                let accepting = Accepting {
                    opener,
                    config_id: outer.ech.config_id,
                    cipher_suite: outer.ech.cipher_suite,
                };
                return Some((opened, accepting));
            }
        }
    }
    None
}

impl Accepting {
    /// Opens the ECH of `m`, the second `ClientHello` of a handshake whose first ECH
    /// this accepted, into its inner hello, or the alert the handshake ends with where
    /// it can't go on (RFC 9849 §7.1.1): `missing_extension` for a hello with no outer
    /// ECH, `illegal_parameter` for one under another config or suite or with an
    /// `enc`, and `decrypt_error` for one that doesn't open.
    pub(super) fn open_retry(&mut self, m: &Message<'_>) -> Result<Vec<u8>, AlertDescription> {
        let outer = handshake_bytes(m)
            .and_then(Outer::read)
            .ok_or(AlertDescription::MissingExtension)?;
        let same = outer.ech.config_id == self.config_id
            && outer.ech.cipher_suite == self.cipher_suite
            && outer.ech.enc.is_empty();
        if !same {
            return Err(AlertDescription::IllegalParameter);
        }
        outer
            .open_with(&mut *self.opener)
            .ok_or(AlertDescription::DecryptError)
    }
}

/// The config id the outer ECH of `m`, a first `ClientHello`, names; `None` when it
/// carries none.
pub(super) fn config_id(m: &Message<'_>) -> Option<u8> {
    Outer::read(handshake_bytes(m)?).map(|outer| outer.ech.config_id)
}

/// The encoded bytes of `m`, a handshake message.
fn handshake_bytes<'a>(m: &'a Message<'_>) -> Option<&'a [u8]> {
    match &m.payload {
        MessagePayload::Handshake { encoded, .. } => Some(encoded.bytes()),
        _ => None,
    }
}

/// `inner_hello`, an inner `ClientHello` handshake message, as a message the handshake
/// can run on.
pub(super) fn inner_message(inner_hello: &[u8]) -> Result<Message<'_>, Error> {
    let payload = MessagePayload::new(
        ContentType::Handshake,
        ProtocolVersion::TLSv1_2,
        inner_hello,
    )?;
    Ok(Message {
        version: ProtocolVersion::TLSv1_2,
        payload,
    })
}

/// An outer `ClientHello`'s ECH, as it sits in the hello's bytes.
struct OuterEch<'a> {
    cipher_suite: HpkeSymmetricCipherSuite,
    config_id: u8,
    enc: &'a [u8],
    /// Where the encrypted payload sits in the hello's body.
    payload: Range<usize>,
}

/// An outer `ClientHello` carrying ECH, read from its bytes.
struct Outer<'a> {
    /// The hello's body: the handshake message without its type and length.
    body: &'a [u8],
    /// Its session id, which the inner hello takes (RFC 9849 §5.1).
    session_id: &'a [u8],
    /// Its extensions, each whole: type, length and data.
    extensions: Vec<(ExtensionType, &'a [u8])>,
    ech: OuterEch<'a>,
}

impl<'a> Outer<'a> {
    /// The outer hello in `message`, a whole `ClientHello` handshake message; `None`
    /// when it isn't one, or carries no outer ECH.
    fn read(message: &'a [u8]) -> Option<Self> {
        let mut r = Reader::init(message);
        if HandshakeType::read(&mut r).ok()? != HandshakeType::ClientHello {
            return None;
        }
        let len = usize::from(u24::read(&mut r).ok()?);
        let body = r.take(len)?;
        if r.any_left() {
            return None;
        }
        let mut r = Reader::init(body);
        r.take(2 + 32)?;
        let session_id = prefixed8(&mut r)?;
        prefixed16(&mut r)?;
        prefixed8(&mut r)?;
        let all = prefixed16(&mut r)?;
        let start = r.used() - all.len();
        if r.any_left() {
            return None;
        }
        let mut r = Reader::init(all);
        let mut extensions = Vec::new();
        let mut ech = None;
        while r.any_left() {
            let at = r.used();
            let kind = ExtensionType::read(&mut r).ok()?;
            let data = prefixed16(&mut r)?;
            extensions.push((kind, all.get(at..r.used())?));
            if kind == ExtensionType::EncryptedClientHello {
                let data_at = start + r.used() - data.len();
                ech = Some(OuterEch::read(data, data_at)?);
            }
        }
        Some(Self {
            body,
            session_id,
            extensions,
            ech: ech?,
        })
    }

    /// Opens the payload with `opener` and rebuilds the inner hello it holds.
    fn open_with(&self, opener: &mut dyn HpkeOpener) -> Option<Vec<u8>> {
        // The AAD is the outer hello with its payload zeroed (RFC 9849 §5.2).
        let mut aad = self.body.to_vec();
        aad.get_mut(self.ech.payload.clone())?
            .fill(0);
        let payload = self
            .body
            .get(self.ech.payload.clone())?;
        let encoded = opener.open(&aad, payload).ok()?;
        self.inner_hello(&encoded)
    }

    /// The `ClientHello` an `EncodedClientHelloInner` stands for (RFC 9849 §5.1): the
    /// outer hello's session id, and each `ech_outer_extensions` replaced by the outer
    /// extensions it names, in its order. `None` when it doesn't parse, names an
    /// extension the outer hello lacks or lists out of order, or its padding isn't
    /// zeros.
    fn inner_hello(&self, encoded: &[u8]) -> Option<Vec<u8>> {
        let mut r = Reader::init(encoded);
        let version_and_random = r.take(2 + 32)?;
        if !prefixed8(&mut r)?.is_empty() {
            return None;
        }
        let at = r.used();
        prefixed16(&mut r)?;
        prefixed8(&mut r)?;
        let suites_and_compression = encoded.get(at..r.used())?;
        let extensions = prefixed16(&mut r)?;
        if r.rest().iter().any(|byte| *byte != 0) {
            return None;
        }

        let mut rebuilt = Vec::with_capacity(encoded.len() + self.body.len());
        let mut outer = self.extensions.iter();
        let mut r = Reader::init(extensions);
        while r.any_left() {
            let at = r.used();
            let kind = ExtensionType::read(&mut r).ok()?;
            let data = prefixed16(&mut r)?;
            if kind != ExtensionType::EncryptedClientHelloOuterExtensions {
                rebuilt.extend_from_slice(extensions.get(at..r.used())?);
                continue;
            }
            let mut named = Reader::init(data);
            let mut types = Reader::init(prefixed8(&mut named)?);
            if named.any_left() || !types.any_left() {
                return None;
            }
            while types.any_left() {
                let wanted = ExtensionType::read(&mut types).ok()?;
                if wanted == ExtensionType::EncryptedClientHello {
                    return None;
                }
                // In the outer hello's order: each is looked for after the last.
                let (_, whole) = outer.find(|(kind, _)| *kind == wanted)?;
                rebuilt.extend_from_slice(whole);
            }
        }

        let mut body = Vec::with_capacity(rebuilt.len() + 128);
        body.extend_from_slice(version_and_random);
        body.push(u8::try_from(self.session_id.len()).ok()?);
        body.extend_from_slice(self.session_id);
        body.extend_from_slice(suites_and_compression);
        body.extend_from_slice(
            &u16::try_from(rebuilt.len())
                .ok()?
                .to_be_bytes(),
        );
        body.extend_from_slice(&rebuilt);

        let mut message = Vec::with_capacity(body.len() + 4);
        HandshakeType::ClientHello.encode(&mut message);
        u24(u32::try_from(body.len()).ok()?).encode(&mut message);
        message.extend_from_slice(&body);
        Some(message)
    }
}

impl<'a> OuterEch<'a> {
    /// An outer `ECHClientHello` from `data`, an extension's data starting at `at` in
    /// the hello's body; `None` for an inner one, or one that doesn't parse.
    fn read(data: &'a [u8], at: usize) -> Option<Self> {
        let mut r = Reader::init(data);
        if EchClientHelloType::read(&mut r).ok()? != EchClientHelloType::ClientHelloOuter {
            return None;
        }
        let cipher_suite = HpkeSymmetricCipherSuite::read(&mut r).ok()?;
        let config_id = u8::read(&mut r).ok()?;
        let enc = prefixed16(&mut r)?;
        let payload = prefixed16(&mut r)?;
        if r.any_left() || payload.is_empty() {
            return None;
        }
        let end = at + data.len();
        Some(Self {
            cipher_suite,
            config_id,
            enc,
            payload: end - payload.len()..end,
        })
    }
}

fn prefixed8<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let len = u8::read(r).ok()?;
    r.take(usize::from(len))
}

fn prefixed16<'a>(r: &mut Reader<'a>) -> Option<&'a [u8]> {
    let len = u16::read(r).ok()?;
    r.take(usize::from(len))
}
