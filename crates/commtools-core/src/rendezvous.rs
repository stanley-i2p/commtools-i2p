use base64::{Engine as _, engine::general_purpose};
use crypto_secretbox::{
    Key, Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const REQUEST_PREFIX: &str = "COMMTOOLS-I2P-RENDEZVOUS-REQUEST-v1:";
pub const RESPONSE_PREFIX: &str = "COMMTOOLS-I2P-RENDEZVOUS-RESPONSE-v1:";
pub const AUTH_SIGNAL_PREFIX: &str = "__SIGNAL__:RENDEZVOUS-AUTH-v1:";
pub const VALIDITY_MS: u64 = 15 * 60 * 1_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
pub const MAX_ENCODED_LEN: usize = 16 * 1_024;

const REQUEST_FORMAT: &str = "COMMTOOLS-I2P-RENDEZVOUS-REQUEST-v1";
const RESPONSE_FORMAT: &str = "COMMTOOLS-I2P-RENDEZVOUS-RESPONSE-v1";
const RESPONSE_PAYLOAD_FORMAT: &str = "COMMTOOLS-I2P-RENDEZVOUS-PAYLOAD-v1";
const RESPONSE_KDF_DOMAIN: &[u8] = b"COMMTOOLS-I2P-RENDEZVOUS-RESPONSE-KDF-v1";
const AUTH_DOMAIN: &[u8] = b"COMMTOOLS-I2P-RENDEZVOUS-AUTH-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Request,
    Response,
    Unknown,
}

#[derive(Clone)]
pub struct PendingRequest {
    request_id: [u8; 16],
    private_key: [u8; 32],
    request_nonce: [u8; 24],
    expires_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuedState {
    Available,
    Reserved,
    Consumed,
    Revoked,
}

#[derive(Clone)]
pub struct IssuedAccess {
    request_id: [u8; 16],
    call_secret: [u8; 32],
    expires_ms: u64,
    state: IssuedState,
}

#[derive(Clone)]
pub struct OutgoingAccess {
    request_id: [u8; 16],
    call_secret: [u8; 32],
    destination_b32: String,
    expires_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestWire {
    format: String,
    request_id: String,
    public_key: String,
    created_ms: u64,
    expires_ms: u64,
    nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseWire {
    format: String,
    request_id: String,
    public_key: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponsePayload {
    format: String,
    request_id: String,
    destination_b32: String,
    call_secret: String,
    expires_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuthProof {
    request_id: String,
    nonce: String,
    mac: String,
}

impl PendingRequest {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}

impl IssuedAccess {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }

    pub fn state(&self) -> IssuedState {
        self.state
    }

    pub fn reserve(&mut self) -> Result<(), RendezvousError> {
        if self.state != IssuedState::Available {
            return Err("rendezvous invitation is not available".into());
        }
        self.state = IssuedState::Reserved;
        Ok(())
    }

    pub fn release(&mut self) {
        if self.state == IssuedState::Reserved {
            self.state = IssuedState::Available;
        }
    }

    pub fn consume(&mut self) -> Result<(), RendezvousError> {
        if !matches!(self.state, IssuedState::Available | IssuedState::Reserved) {
            return Err("rendezvous invitation cannot be consumed".into());
        }
        self.state = IssuedState::Consumed;
        Ok(())
    }

    pub fn revoke(&mut self) {
        self.state = IssuedState::Revoked;
    }
}

impl OutgoingAccess {
    pub fn request_id(&self) -> [u8; 16] {
        self.request_id
    }

    pub fn destination_b32(&self) -> &str {
        &self.destination_b32
    }

    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}

impl std::fmt::Debug for PendingRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingRequest")
            .field("request_id", &encode(&self.request_id))
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for IssuedAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedAccess")
            .field("request_id", &encode(&self.request_id))
            .field("expires_ms", &self.expires_ms)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for OutgoingAccess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OutgoingAccess")
            .field("request_id", &encode(&self.request_id))
            .field("destination_b32", &self.destination_b32)
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

pub fn input_kind(value: &str) -> InputKind {
    let trimmed = value.trim();
    if decode_json::<RequestWire>(trimmed, REQUEST_PREFIX)
        .is_ok_and(|wire| wire.format == REQUEST_FORMAT)
    {
        return InputKind::Request;
    }
    if decode_json::<ResponseWire>(trimmed, RESPONSE_PREFIX)
        .is_ok_and(|wire| wire.format == RESPONSE_FORMAT)
    {
        return InputKind::Response;
    }
    InputKind::Unknown
}

pub fn response_matches_pending(value: &str, pending: &PendingRequest) -> bool {
    let Ok(wire) = decode_json::<ResponseWire>(value, RESPONSE_PREFIX) else {
        return false;
    };
    wire.format == RESPONSE_FORMAT
        && decode_array::<16>(&wire.request_id, "request id")
            .is_ok_and(|request_id| request_id == pending.request_id)
}

pub fn generate_request(now_ms: u64) -> Result<(PendingRequest, String), RendezvousError> {
    let private = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&private);
    let mut request_id = [0u8; 16];
    let mut request_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut request_id);
    OsRng.fill_bytes(&mut request_nonce);
    let expires_ms = now_ms.saturating_add(VALIDITY_MS);

    let wire = RequestWire {
        format: REQUEST_FORMAT.to_string(),
        request_id: encode(&request_id),
        public_key: encode(public.as_bytes()),
        created_ms: now_ms,
        expires_ms,
        nonce: encode(&request_nonce),
    };
    let encoded = encode_json(REQUEST_PREFIX, &wire)?;

    Ok((
        PendingRequest {
            request_id,
            private_key: private.to_bytes(),
            request_nonce,
            expires_ms,
        },
        encoded,
    ))
}

pub fn answer_request(
    encoded_request: &str,
    destination_b32: &str,
    now_ms: u64,
) -> Result<(IssuedAccess, String), RendezvousError> {
    let wire: RequestWire = decode_json(encoded_request, REQUEST_PREFIX)?;
    if wire.format != REQUEST_FORMAT {
        return Err("unsupported rendezvous request format".into());
    }
    validate_times(wire.created_ms, wire.expires_ms, now_ms)?;

    let request_id = decode_array::<16>(&wire.request_id, "request id")?;
    let request_public = decode_array::<32>(&wire.public_key, "request public key")?;
    let request_nonce = decode_array::<24>(&wire.nonce, "request nonce")?;
    let response_private = StaticSecret::random_from_rng(OsRng);
    let response_public = PublicKey::from(&response_private);
    let shared = response_private
        .diffie_hellman(&PublicKey::from(request_public))
        .to_bytes();
    reject_zero_shared(&shared)?;
    let key = derive_response_key(&shared, &request_id, &request_nonce);

    let mut call_secret = [0u8; 32];
    let mut response_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut call_secret);
    OsRng.fill_bytes(&mut response_nonce);
    let expires_ms = wire.expires_ms.min(now_ms.saturating_add(VALIDITY_MS));
    let payload = ResponsePayload {
        format: RESPONSE_PAYLOAD_FORMAT.to_string(),
        request_id: encode(&request_id),
        destination_b32: destination_b32.trim().to_ascii_lowercase(),
        call_secret: encode(&call_secret),
        expires_ms,
    };
    let plaintext = serde_json::to_vec(&payload)?;
    let ciphertext = XSalsa20Poly1305::new(Key::from_slice(&key))
        .encrypt(Nonce::from_slice(&response_nonce), plaintext.as_slice())
        .map_err(|_| RendezvousError::from("rendezvous response encryption failed"))?;
    let response = ResponseWire {
        format: RESPONSE_FORMAT.to_string(),
        request_id: encode(&request_id),
        public_key: encode(response_public.as_bytes()),
        nonce: encode(&response_nonce),
        ciphertext: encode(&ciphertext),
    };

    Ok((
        IssuedAccess {
            request_id,
            call_secret,
            expires_ms,
            state: IssuedState::Available,
        },
        encode_json(RESPONSE_PREFIX, &response)?,
    ))
}

pub fn open_response(
    encoded_response: &str,
    pending: &PendingRequest,
    now_ms: u64,
) -> Result<OutgoingAccess, RendezvousError> {
    if pending.expires_ms <= now_ms {
        return Err("rendezvous request expired".into());
    }
    let wire: ResponseWire = decode_json(encoded_response, RESPONSE_PREFIX)?;
    if wire.format != RESPONSE_FORMAT {
        return Err("unsupported rendezvous response format".into());
    }
    let request_id = decode_array::<16>(&wire.request_id, "request id")?;
    if request_id != pending.request_id {
        return Err("rendezvous response does not match this request".into());
    }

    let response_public = decode_array::<32>(&wire.public_key, "response public key")?;
    let response_nonce = decode_array::<24>(&wire.nonce, "response nonce")?;
    let ciphertext = decode_bytes(&wire.ciphertext, "response ciphertext")?;
    let shared = StaticSecret::from(pending.private_key)
        .diffie_hellman(&PublicKey::from(response_public))
        .to_bytes();
    reject_zero_shared(&shared)?;
    let key = derive_response_key(&shared, &request_id, &pending.request_nonce);
    let plaintext = XSalsa20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&response_nonce), ciphertext.as_slice())
        .map_err(|_| RendezvousError::from("rendezvous response authentication failed"))?;
    let payload: ResponsePayload = serde_json::from_slice(&plaintext)
        .map_err(|_| RendezvousError::from("invalid rendezvous response"))?;
    if payload.format != RESPONSE_PAYLOAD_FORMAT {
        return Err("unsupported rendezvous response payload".into());
    }
    if decode_array::<16>(&payload.request_id, "payload request id")? != request_id {
        return Err("rendezvous response request id mismatch".into());
    }
    if payload.expires_ms <= now_ms || payload.expires_ms > pending.expires_ms {
        return Err("rendezvous response expired or has invalid lifetime".into());
    }

    Ok(OutgoingAccess {
        request_id,
        call_secret: decode_array::<32>(&payload.call_secret, "call secret")?,
        destination_b32: payload.destination_b32,
        expires_ms: payload.expires_ms,
    })
}

pub fn make_auth_signal(
    access: &OutgoingAccess,
    caller_b32: &str,
    receiver_b32: &str,
    now_ms: u64,
) -> Result<String, RendezvousError> {
    if access.expires_ms <= now_ms {
        return Err("rendezvous response expired".into());
    }
    let mut nonce = [0u8; 16];
    OsRng.fill_bytes(&mut nonce);
    let mac = auth_mac(
        &access.call_secret,
        &access.request_id,
        &nonce,
        caller_b32,
        receiver_b32,
    )?;
    let proof = AuthProof {
        request_id: encode(&access.request_id),
        nonce: encode(&nonce),
        mac: encode(&mac),
    };
    Ok(format!(
        "{AUTH_SIGNAL_PREFIX}{}",
        encode(&serde_json::to_vec(&proof)?)
    ))
}

pub fn verify_auth_signal(
    body: &str,
    issued: &IssuedAccess,
    caller_b32: &str,
    receiver_b32: &str,
    now_ms: u64,
) -> Result<(), RendezvousError> {
    if issued.state != IssuedState::Available {
        return Err("rendezvous invitation is not available".into());
    }
    if issued.expires_ms <= now_ms {
        return Err("rendezvous invitation expired".into());
    }
    let encoded = body
        .strip_prefix(AUTH_SIGNAL_PREFIX)
        .ok_or_else(|| RendezvousError::from("not a rendezvous proof"))?;
    if encoded.len() > MAX_ENCODED_LEN {
        return Err("rendezvous proof is too large".into());
    }
    let bytes = decode_bytes(encoded, "rendezvous proof")?;
    let proof: AuthProof = serde_json::from_slice(&bytes)
        .map_err(|_| RendezvousError::from("invalid rendezvous proof"))?;
    let request_id = decode_array::<16>(&proof.request_id, "proof request id")?;
    if request_id != issued.request_id {
        return Err("rendezvous proof request id mismatch".into());
    }
    let nonce = decode_array::<16>(&proof.nonce, "proof nonce")?;
    let received_mac = decode_array::<32>(&proof.mac, "proof authenticator")?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&issued.call_secret)
        .map_err(|_| RendezvousError::from("invalid rendezvous call secret"))?;
    mac.update(&auth_transcript(
        &request_id,
        &nonce,
        caller_b32,
        receiver_b32,
    ));
    mac.verify_slice(&received_mac)
        .map_err(|_| RendezvousError::from("rendezvous proof authentication failed"))
}

fn auth_mac(
    secret: &[u8; 32],
    request_id: &[u8; 16],
    nonce: &[u8; 16],
    caller_b32: &str,
    receiver_b32: &str,
) -> Result<[u8; 32], RendezvousError> {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(secret)
        .map_err(|_| RendezvousError::from("invalid rendezvous call secret"))?;
    mac.update(&auth_transcript(
        request_id,
        nonce,
        caller_b32,
        receiver_b32,
    ));
    let bytes = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    Ok(output)
}

fn auth_transcript(
    request_id: &[u8; 16],
    nonce: &[u8; 16],
    caller_b32: &str,
    receiver_b32: &str,
) -> Vec<u8> {
    let mut transcript = Vec::new();
    append_field(&mut transcript, AUTH_DOMAIN);
    append_field(&mut transcript, request_id);
    append_field(&mut transcript, nonce);
    append_field(&mut transcript, caller_b32.to_ascii_lowercase().as_bytes());
    append_field(
        &mut transcript,
        receiver_b32.to_ascii_lowercase().as_bytes(),
    );
    transcript
}

fn derive_response_key(
    shared: &[u8; 32],
    request_id: &[u8; 16],
    request_nonce: &[u8; 24],
) -> [u8; 32] {
    let mut material = Vec::new();
    append_field(&mut material, RESPONSE_KDF_DOMAIN);
    append_field(&mut material, shared);
    append_field(&mut material, request_id);
    append_field(&mut material, request_nonce);
    Sha256::digest(material).into()
}

fn append_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_times(created_ms: u64, expires_ms: u64, now_ms: u64) -> Result<(), RendezvousError> {
    if created_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
        return Err("rendezvous request creation time is too far in the future".into());
    }
    if expires_ms <= now_ms {
        return Err("rendezvous request expired".into());
    }
    if expires_ms.saturating_sub(created_ms) > VALIDITY_MS {
        return Err("rendezvous request lifetime is invalid".into());
    }
    Ok(())
}

fn reject_zero_shared(shared: &[u8; 32]) -> Result<(), RendezvousError> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err("rendezvous X25519 key is invalid".into());
    }
    Ok(())
}

fn encode_json<T: Serialize>(prefix: &str, value: &T) -> Result<String, RendezvousError> {
    let encoded = format!("{prefix}{}", encode(&serde_json::to_vec(value)?));
    if encoded.len() > MAX_ENCODED_LEN {
        return Err("rendezvous value is too large".into());
    }
    Ok(encoded)
}

fn decode_json<T: DeserializeOwned>(value: &str, prefix: &str) -> Result<T, RendezvousError> {
    let trimmed = value.trim();
    if trimmed.len() > MAX_ENCODED_LEN {
        return Err("rendezvous value is too large".into());
    }
    let encoded = trimmed
        .strip_prefix(prefix)
        .ok_or_else(|| RendezvousError::from("unrecognized rendezvous value"))?;
    let bytes = decode_bytes(encoded, "rendezvous value")?;
    serde_json::from_slice(&bytes).map_err(|_| RendezvousError::from("invalid rendezvous value"))
}

fn encode(value: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(value)
}

fn decode_bytes(value: &str, label: &str) -> Result<Vec<u8>, RendezvousError> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| RendezvousError(format!("invalid {label}")))
}

fn decode_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], RendezvousError> {
    decode_bytes(value, label)?
        .try_into()
        .map_err(|_| RendezvousError(format!("invalid {label} length")))
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct RendezvousError(String);

impl From<&str> for RendezvousError {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for RendezvousError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<serde_json::Error> for RendezvousError {
    fn from(_: serde_json::Error) -> Self {
        Self("rendezvous serialization failed".to_string())
    }
}
