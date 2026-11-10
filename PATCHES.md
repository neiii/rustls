# FAIM's rustls fork

This is rustls 0.23.46, from the upstream tag `v/0.23.46` (commit `f04804f`), on the `faim` branch of `neiii/rustls`, with the changes below. [FAIM](https://github.com/neiii/faim-http) mirrors the hello each client sends it toward the server (its ADR-0011), and this fork sends that hello. FAIM pins one commit of this branch with `[patch.crates-io]`, never the branch itself.

Every change is listed with its reason, so a rebase onto a later release can redo each one on purpose: start a new branch from the new tag and reapply the commits in `git log v/0.23.46..faim`. Code the fork adds is marked `FAIM:` in a comment, and most of it sits in one new file, `rustls/src/client/hs/template.rs`. The template logic itself (parsing a hello, rendering it, reshaping it for a retry or a PSK, which extensions count as offered) is plain data in faim-http's `crates/faim-template`, which the fork calls and which doesn't know rustls.

`git diff v/0.23.46 faim` shows every change against the release.

## Building and testing

The fork's `rustls` crate depends on `faim-template = "0.1"`, which crates.io doesn't have. FAIM's own workspace supplies it with `[patch.crates-io]`. Here, this workspace's `[patch.crates-io]` takes it from a faim-http checkout beside this one, at `../faim-http`. faim-template builds on FAIM's nightly toolchain (the `rust` line of faim-http's `mise.toml`), so the fork does too.

- rustls's own tests: `cargo test -p rustls`.
- BoGo: `cd bogo && BOGO_SHIM_PROVIDER=aws-lc-rs ./runme`, with Go installed.

The `faim` workflow (`.github/workflows/faim.yml`) runs both on every push and pull request to this branch, after checking that the `rustls` crate still compiles across upstream's feature builds (no std, either provider). faim-http is private, so the workflow checks it out with the `FAIM_HTTP_TOKEN` secret, a fine-grained token with Contents: read on `neiii/faim-http`. It builds against the faim-http commit named in `FAIM_HTTP_REF`, a one-line file at the root. A commit, not a branch, so a green run says what it was built against. A change here that needs a faim-template change faim-http hasn't merged names the faim-http commit that has it; otherwise the file names a commit on faim-http's `master`. A run started by hand can name another ref with `faim-http-ref`.

A change that touches both repositories merges here first. faim-http then pins the new commit.

## The tree

- **`Cargo.toml`**: `[patch.crates-io]` supplies `faim-template` from `../faim-http` (see above).
- **`Cargo.lock`**: `aws-lc-rs` 1.19.0 and `aws-lc-sys` 0.47.0, the versions FAIM builds with, so the fork's tests run on the crypto FAIM ships, and `faim-template` with its dependencies. A change that bumps `aws-lc-rs` in faim-http's `Cargo.lock` bumps it here too (`cargo update -p aws-lc-rs --precise <version>`).
- **`rustls/Cargo.toml`**: depends on `faim-template = "0.1"`.
- **`FAIM_HTTP_REF`** (new): the faim-http commit the `faim` workflow builds faim-template from (see above).
- **`.github/workflows/`**: upstream's workflows are removed. They build without faim-template, so every one would fail here, and FAIM doesn't need their release or docs jobs. `faim.yml` replaces them, and keeps their feature builds. Their fuzzing and dependency checks aren't replaced here: faim-http's `mise run check` audits the dependency tree it builds this fork into, and fuzzing the template path needs faim-http's corpus.

## The client sends a template's hello

- **`ClientConfig::hello_template`** (`client/client_conn.rs`, default `None` in `client/builder.rs`): the template to send in place of rustls's own hello. `None` leaves the client stock, so FAIM's default upstream leg is unchanged until faim-http#167's switch gate passes.
- **`client/hs/template.rs`** (new): renders the template with fresh values (rustls's random, a session id of the template's length, a fresh key for each key share slot, random bytes for a slot whose group aws-lc-rs can't compute, and GREASE ECH bytes in the client's shape, faim-http#200), and sends it in the record version the template recorded. It reads the hello back with rustls's own decoder to fill `ClientHelloDetails`: the extensions a server may answer (every one the template carries but GREASE and `padding`, so ALPS and certificate compression among them), its cipher suites and its ALPN. It holds the helpers the other patches call.
- **What the server picks is checked against the template's offer, not the config.** Stock rustls offers everything its config has, so it checks a server's pick against the config. A template offers what its client offered, and faim-http's `faim_proxy::template::client_config` enables every group, suite and decompressor aws-lc-rs has, so the fork asks the template (`ClientTemplate::offers_version`, `offers_cipher_suite`, `offers_group`, `offers_signature_scheme`, `offers_certificate_compression`). A pick the template never offered is refused with the error stock rustls gives an unoffered pick. A pick it offered that the fork can't complete is `Error::Shortfall` naming it (faim-http#197 turns that into a passthrough). GREASE values are never offered.
- **`client/hs.rs`**:
  - A connection with a template offers no session to resume (resumption is faim-http#199) and gets a session id of the template's length (`ClientHelloInput::new`).
  - `start_handshake` hands a template's hello to `template::emit_client_hello`. A config that also asks for real ECH (`EchMode::Enable`) is refused with `Error::General`, since the template greases ECH in its client's shape and would silently drop it. A QUIC connection is refused with `Shortfall::Quic`, before any hello goes out: the template carries its client's recorded `quic_transport_parameters`, not the connection's, and FAIM passes QUIC through until it intercepts it (faim-http#167). The SNI goes out without a trailing dot, as stock rustls sends it (RFC 6066).
  - `ExpectServerHello` keeps the template's other key shares (`template_shares`) beside `offered_key_share`, and a TLS 1.3 `ServerHello` takes the share for the group the server picked (`template::choose_key_share`). Stock rustls sends one share and has no use for more. A template's X25519MLKEM768 share doesn't stand in for an X25519 share it didn't send, as stock rustls's hybrid share does for its own.
  - A `HelloRetryRequest` sends the template again reshaped as the client would (`ClientTemplate::retry`), reusing the first hello's keys and ECH bytes, and the random bytes of a slot the fork can't compute when the retry names no group (RFC 8446 §4.1.2). A retry for a group or suite the template didn't offer, or for a group its hello already sent a key share for, is refused. A template's hello may send no key share the fork can complete, so a retry no longer requires one. rustls's own hello always sends one, and where stock rustls would `unwrap` it, the fork fails with `IllegalHelloRetryRequestWithOfferedGroup`.
  - The version and suite checks (`template::check_version`, `template::unknown_cipher_suite`).
  - A template that offered no TLS 1.3 takes a TLS 1.2 `ServerHello` whose random carries the downgrade marker, which every TLS 1.3 server sets when it answers TLS 1.2.
  - A TLS 1.2 server's `record_size_limit` caps what the client sends. A smaller `ClientConfig::max_fragment_size` stays (here and in TLS 1.3).
- **`client/tls13.rs`**:
  - `EncryptedExtensions`: notes ALPS (`application_settings`, 0x4469 or 0x44cd) and applies `record_size_limit`, and keeps what the template offered for the certificate's entries to answer. An answer to any other offered extension rustls doesn't handle is `Shortfall::Extension` (`template::check_unhandled_extensions`), since it can oblige the client to something the fork doesn't do: an acked `max_fragment_length` caps every record. The same goes for a TLS 1.2 `ServerHello`.
  - A TLS 1.3 `ServerHello` carrying an extension rustls doesn't parse is refused as `UnexpectedCleartextExtension` (`validate_server_hello`), as stock rustls refuses it as unsolicited. `only_contains` sees only the extensions rustls parses, and a template offers others.
  - `Certificate`: an entry's extension rustls doesn't handle must answer one the template offered, and a delegated credential is a `Shortfall`, since the handshake is then signed with the credential's key.
  - `CompressedCertificate`: the algorithm checked against the template's offer, then against the fork's decompressors.
  - `CertificateVerify`: the scheme checked against the template's `signature_algorithms`, then against what the verifier can check.
  - `Finished`: a server that agreed to ALPS gets the client's `EncryptedExtensions` with its `application_settings` before the client's `Finished`, as Chromium sends it. The settings go out empty until faim-http#198 fills them from the client's HTTP/2 SETTINGS.
- **`client/tls12.rs`**: a `ServerKeyExchange`'s curve and signature scheme checked against the template's offer, then against what aws-lc-rs can compute and verify.
- **`ClientConnectionData`** (`client/client_conn.rs`): `template_alps` and `template_offered`, carried from `EncryptedExtensions` to the states after it.

## Messages and errors

- **`Error::Shortfall(faim_template::Shortfall)`** and **`PeerMisbehaved::IllegalRecordSizeLimit`** (`error.rs`).
- **`ExtensionType::RecordSizeLimit`** (`msgs/enums.rs`) and **`ServerExtensions::record_size_limit`** (`msgs/handshake.rs`): read so a template that offered it can honour the server's limit. A stock client never offers it, so a server that sends it is still refused as unsolicited.
- **`CertificateExtensions::unknown_extensions`** (`msgs/handshake.rs`): decoding a certificate entry no longer refuses an extension rustls doesn't handle. It records the type, and the state that reads the certificate decides, since only it knows what its hello offered. `CertificatePayloadTls13::unknown_extensions` lists them. A stock client and the server refuse any, with the alert and error decoding gave before (`DecodeError`, `UnknownCertificateExtension`).
- **`msgs/handshake_test.rs`**: the sample payloads gain the two new fields.

## The server

- **`ServerConfig::ech_retry_configs`** (`server/server_conn.rs`, default `None` in `server/builder.rs`; sent from `server/tls13.rs`): ECH configs to send a client that offered ECH, since the server accepts none (RFC 9849 §7.1). Configs that don't parse, or parse to an empty list the extension doesn't allow, are left out with a warning rather than failing the handshake after `ServerHello` or sending an invalid extension. FAIM's test harness uses it to show that a greased ECH ignores them (faim-http#200). A server template sends the server's own as part of its `EncryptedExtensions`, in their place.
- **`server/tls13.rs`**: a client certificate entry with an extension rustls doesn't handle is refused here, where decoding used to refuse it (see `CertificateExtensions` above).

## The server answers from a server template (faim-http#196)

FAIM answers its client in the shape of the answer the real server gave (its ADR-0011), so the client sees the server's JA4S, ALPN and ALPS. The template is plain data in faim-http's `crates/faim-template` (`ServerTemplate`), which fits it to the client's hello as an `Answer`: what of the server's answer goes out to this client, and what is left out as a `ServerShortfall`. The fork only picks what the answer names and sends what it renders.

- **`ServerConfig::hello_template`** (`server/server_conn.rs`, default `None` in `server/builder.rs`): the server's answer to answer the client with. `None` leaves the server stock. The template's ALPN takes the place of `alpn_protocols`.
- **`ServerConnection::template_shortfalls`** and `ServerConnectionData::template_shortfalls` (`server/server_conn.rs`): what of the template the connection couldn't send its client, for faim-http#197 to record on the connection.
- **`server/template.rs`** (new) holds the steps below, which the handshake calls.
- **`server/hs.rs`**, on a first hello:
  - The client's hello is read back with faim-template (`ClientHello::from_message`, from the hello's encoded bytes, so the extensions rustls doesn't parse count too) and the template fitted to it. A template that can't answer this client (another version, no key share for the server's group, a QUIC connection, a hello faim-template doesn't read) is a shortfall, and the server answers stock.
  - The template's version takes the place of rustls's pick: TLS 1.2 where the server answered in TLS 1.2, even to a client offering TLS 1.3 (faim-template refuses a template whose random says the server speaks TLS 1.3, which such a client would refuse).
  - The template's suite and group take the place of rustls's picks, where the crypto provider completes them. A suite it can't is a shortfall and rustls's pick stays. A group it can't drops the template, whose `ServerHello` names the group, and is checked before the template's version replaces rustls's: a TLS 1.2 template dropped after that would leave a client offering TLS 1.3 a stock TLS 1.2 answer carrying rustls's downgrade marker, which it refuses.
  - The server random ends with the template's downgrade marker where the server's did, and rustls's own marker is left off.
- **`server/tls13.rs`**:
  - `ServerHello`: the template's, rendered with the connection's random, the client's session id, the suite and the key share, and sent as rendered (`HandshakePayload::Unknown`), so its extensions keep the server's order.
  - `EncryptedExtensions`: the template's, rendered and sent as rendered. Its ALPN protocol becomes the connection's; a `record_size_limit` or `max_fragment_length` it agrees to caps what the server sends; early data is never accepted, since nothing here resumes.
  - `Certificate`: compressed with the template's algorithm where the server compressed its own and the config has a compressor for it, uncompressed otherwise; an OCSP response stapled only where the template's answer staples one, and a shortfall where it does and the certified key has none.
  - `ExpectFinished`: a client that agreed to the template's ALPS sends its own `EncryptedExtensions` before its `Finished`, as Chromium does; it goes into the transcript.
- **`server/tls12.rs`**:
  - `ServerHello`: the template's, rendered with the connection's random, an empty session id (no resumption until faim-http#199) and the suite, and sent as rendered. No ticket is issued. ALPN and record size limits apply as on TLS 1.3.
  - Extended master secret only where the template's answer agreed to it.
  - `ServerKeyExchange`: signed with the template's scheme where the client offered it and the key signs with it, else rustls's pick and a shortfall.
  - `CertificateStatus`: sent where the template's answer staples, as on TLS 1.3; where the key has no response, `status_request` is left out of the `ServerHello` too.

