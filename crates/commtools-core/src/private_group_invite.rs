use base64::{Engine as _, engine::general_purpose};
use crypto_secretbox::{
    Key, Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const PRIVATE_REQUEST_PREFIX: &str = "COMMTOOLS-I2P-GROUP-PRIVATE-REQUEST-v1:";
pub const PRIVATE_INVITE_PREFIX: &str = "COMMTOOLS-I2P-GROUP-PRIVATE-INVITE-v1:";
pub const VALIDITY_MS: u64 = 24 * 60 * 60 * 1_000;
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1_000;
pub const MAX_ENCODED_LEN: usize = 256 * 1_024;
pub const MAX_DECOMPRESSED_PAYLOAD: usize = 512 * 1_024;

const REQUEST_FORMAT: &str = "COMMTOOLS-I2P-GROUP-PRIVATE-REQUEST-v1";
const INVITE_FORMAT: &str = "COMMTOOLS-I2P-GROUP-PRIVATE-INVITE-v1";
const PAYLOAD_FORMAT: &str = "COMMTOOLS-I2P-GROUP-PRIVATE-PAYLOAD-v1";
const RESPONSE_KDF_DOMAIN: &[u8] = b"COMMTOOLS-I2P-GROUP-PRIVATE-INVITE-KDF-v1";
const JOIN_PROOF_DOMAIN: &str = "COMMTOOLS-I2P-GROUP-PRIVATE-JOIN-PROOF-v1";

#[derive(Clone, Serialize, Deserialize)]
pub struct PendingPrivateRequest {
    request_id: String,
    encryption_secret: String,
    signing_secret: String,
    request_nonce: String,
    expires_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateInviteBinding {
    request_id: String,
    verifying_key: String,
    expires_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PrivateJoinCredential {
    request_id: String,
    signing_secret: String,
    expires_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivateJoinProof {
    pub request_id: String,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    Public,
    Private,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RequestWire {
    format: String,
    request_id: String,
    encryption_public_key: String,
    verifying_key: String,
    created_ms: u64,
    expires_ms: u64,
    nonce: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateInviteWire {
    format: String,
    request_id: String,
    response_public_key: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrivateInvitePayload {
    format: String,
    request_id: String,
    expires_ms: u64,
    compressed_invite: String,
}

#[derive(Debug, Clone, Serialize)]
struct JoinProofPayload<'a> {
    domain: &'static str,
    request_id: &'a str,
    owner_b32: &'a str,
    token: &'a str,
    member_b32: &'a str,
    nonce: &'a str,
}

impl PendingPrivateRequest {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}

impl PrivateInviteBinding {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn verifying_key(&self) -> &str {
        &self.verifying_key
    }

    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}

impl PrivateJoinCredential {
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    pub fn expires_ms(&self) -> u64 {
        self.expires_ms
    }
}

impl std::fmt::Debug for PendingPrivateRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingPrivateRequest")
            .field("request_id", &self.request_id)
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for PrivateJoinCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrivateJoinCredential")
            .field("request_id", &self.request_id)
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

pub fn input_kind(value: &str, public_invite_prefix: &str) -> InputKind {
    let value = value.trim();
    if value.starts_with(public_invite_prefix) {
        InputKind::Public
    } else if value.starts_with(PRIVATE_INVITE_PREFIX) {
        InputKind::Private
    } else {
        InputKind::Unknown
    }
}

pub fn generate_request(
    now_ms: u64,
) -> Result<(PendingPrivateRequest, String), PrivateGroupInviteError> {
    let encryption_secret = StaticSecret::random_from_rng(OsRng);
    let encryption_public = PublicKey::from(&encryption_secret);
    let mut signing_secret = [0u8; 32];
    let mut request_id = [0u8; 16];
    let mut request_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut signing_secret);
    OsRng.fill_bytes(&mut request_id);
    OsRng.fill_bytes(&mut request_nonce);
    let signing_key = SigningKey::from_bytes(&signing_secret);
    let expires_ms = now_ms.saturating_add(VALIDITY_MS);

    let wire = RequestWire {
        format: REQUEST_FORMAT.into(),
        request_id: encode(&request_id),
        encryption_public_key: encode(encryption_public.as_bytes()),
        verifying_key: encode(signing_key.verifying_key().as_bytes()),
        created_ms: now_ms,
        expires_ms,
        nonce: encode(&request_nonce),
    };
    let encoded = encode_json(PRIVATE_REQUEST_PREFIX, &wire)?;
    Ok((
        PendingPrivateRequest {
            request_id: wire.request_id,
            encryption_secret: encode(&encryption_secret.to_bytes()),
            signing_secret: encode(&signing_secret),
            request_nonce: wire.nonce,
            expires_ms,
        },
        encoded,
    ))
}

pub fn seal_invite(
    encoded_request: &str,
    public_invite_payload: &[u8],
    now_ms: u64,
) -> Result<(PrivateInviteBinding, String), PrivateGroupInviteError> {
    let request: RequestWire = decode_json(encoded_request, PRIVATE_REQUEST_PREFIX)?;
    if request.format != REQUEST_FORMAT {
        return Err("unsupported private group request format".into());
    }
    validate_times(request.created_ms, request.expires_ms, now_ms)?;
    let request_id = decode_array::<16>(&request.request_id, "request id")?;
    let request_public =
        decode_array::<32>(&request.encryption_public_key, "request encryption key")?;
    let request_nonce = decode_array::<24>(&request.nonce, "request nonce")?;
    let request_verifying_key =
        decode_array::<32>(&request.verifying_key, "request verification key")?;
    VerifyingKey::from_bytes(&request_verifying_key)
        .map_err(|_| PrivateGroupInviteError::from("request verification key is invalid"))?;

    let response_secret = StaticSecret::random_from_rng(OsRng);
    let response_public = PublicKey::from(&response_secret);
    let shared = response_secret
        .diffie_hellman(&PublicKey::from(request_public))
        .to_bytes();
    reject_zero_shared(&shared, "request encryption key is invalid")?;
    let key = derive_response_key(&shared, &request_id, &request_nonce, &request_verifying_key);
    let compressed_invite = compress(public_invite_payload)?;
    let payload = PrivateInvitePayload {
        format: PAYLOAD_FORMAT.into(),
        request_id: request.request_id.clone(),
        expires_ms: request.expires_ms,
        compressed_invite: encode(&compressed_invite),
    };
    let plaintext = serde_json::to_vec(&payload)?;
    let mut response_nonce = [0u8; 24];
    OsRng.fill_bytes(&mut response_nonce);
    let ciphertext = XSalsa20Poly1305::new(Key::from_slice(&key))
        .encrypt(Nonce::from_slice(&response_nonce), plaintext.as_slice())
        .map_err(|_| PrivateGroupInviteError::from("private group invite encryption failed"))?;
    let wire = PrivateInviteWire {
        format: INVITE_FORMAT.into(),
        request_id: request.request_id.clone(),
        response_public_key: encode(response_public.as_bytes()),
        nonce: encode(&response_nonce),
        ciphertext: encode(&ciphertext),
    };

    Ok((
        PrivateInviteBinding {
            request_id: request.request_id,
            verifying_key: request.verifying_key,
            expires_ms: request.expires_ms,
        },
        encode_json(PRIVATE_INVITE_PREFIX, &wire)?,
    ))
}

pub fn response_request_id(encoded_invite: &str) -> Result<String, PrivateGroupInviteError> {
    let wire: PrivateInviteWire = decode_json(encoded_invite, PRIVATE_INVITE_PREFIX)?;
    if wire.format != INVITE_FORMAT {
        return Err("unsupported private group invite format".into());
    }
    let _ = decode_array::<16>(&wire.request_id, "request id")?;
    Ok(wire.request_id)
}

pub fn open_invite(
    encoded_invite: &str,
    pending: &PendingPrivateRequest,
    now_ms: u64,
) -> Result<(Vec<u8>, PrivateJoinCredential), PrivateGroupInviteError> {
    if now_ms > pending.expires_ms {
        return Err("private group request has expired".into());
    }
    let wire: PrivateInviteWire = decode_json(encoded_invite, PRIVATE_INVITE_PREFIX)?;
    if wire.format != INVITE_FORMAT || wire.request_id != pending.request_id {
        return Err("private group invite does not match this request".into());
    }
    let request_id = decode_array::<16>(&wire.request_id, "request id")?;
    let request_nonce = decode_array::<24>(&pending.request_nonce, "request nonce")?;
    let encryption_secret =
        decode_array::<32>(&pending.encryption_secret, "request encryption secret")?;
    let signing_secret = decode_array::<32>(&pending.signing_secret, "request signing secret")?;
    let request_verifying_key = SigningKey::from_bytes(&signing_secret)
        .verifying_key()
        .to_bytes();
    let response_public = decode_array::<32>(&wire.response_public_key, "response public key")?;
    let response_nonce = decode_array::<24>(&wire.nonce, "response nonce")?;
    let ciphertext = decode_limited(&wire.ciphertext, "private invite ciphertext")?;
    let shared = StaticSecret::from(encryption_secret)
        .diffie_hellman(&PublicKey::from(response_public))
        .to_bytes();
    reject_zero_shared(&shared, "private group invite response key is invalid")?;
    let key = derive_response_key(&shared, &request_id, &request_nonce, &request_verifying_key);
    let plaintext = XSalsa20Poly1305::new(Key::from_slice(&key))
        .decrypt(Nonce::from_slice(&response_nonce), ciphertext.as_slice())
        .map_err(|_| PrivateGroupInviteError::from("private group invite authentication failed"))?;
    let payload: PrivateInvitePayload = serde_json::from_slice(&plaintext)
        .map_err(|_| PrivateGroupInviteError::from("invalid private group invite payload"))?;
    if payload.format != PAYLOAD_FORMAT || payload.request_id != pending.request_id {
        return Err("private group invite payload does not match this request".into());
    }
    if payload.expires_ms != pending.expires_ms || now_ms > payload.expires_ms {
        return Err("private group invite has expired".into());
    }
    let compressed = decode_limited(&payload.compressed_invite, "private invite payload")?;
    let invite = decompress_limited(&compressed)?;
    Ok((
        invite,
        PrivateJoinCredential {
            request_id: pending.request_id.clone(),
            signing_secret: pending.signing_secret.clone(),
            expires_ms: pending.expires_ms,
        },
    ))
}

pub fn sign_join_proof(
    credential: &PrivateJoinCredential,
    owner_b32: &str,
    token: &str,
    member_b32: &str,
    now_ms: u64,
) -> Result<PrivateJoinProof, PrivateGroupInviteError> {
    if now_ms > credential.expires_ms {
        return Err("private group invite has expired".into());
    }
    let secret = decode_array::<32>(&credential.signing_secret, "join signing secret")?;
    let signing_key = SigningKey::from_bytes(&secret);
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let nonce = encode(&nonce);
    let payload = join_proof_payload(&credential.request_id, owner_b32, token, member_b32, &nonce)?;
    let signature = signing_key.sign(&payload);
    Ok(PrivateJoinProof {
        request_id: credential.request_id.clone(),
        nonce,
        signature: encode(&signature.to_bytes()),
    })
}

pub fn verify_join_proof(
    binding: &PrivateInviteBinding,
    owner_b32: &str,
    token: &str,
    member_b32: &str,
    proof: &PrivateJoinProof,
    now_ms: u64,
) -> Result<(), PrivateGroupInviteError> {
    if now_ms > binding.expires_ms {
        return Err("private group invite has expired".into());
    }
    if proof.request_id != binding.request_id {
        return Err("private group invite request id does not match".into());
    }
    let verifying_key = decode_array::<32>(&binding.verifying_key, "join verification key")?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key)
        .map_err(|_| PrivateGroupInviteError::from("join verification key is invalid"))?;
    let signature = Signature::from_bytes(&decode_array::<64>(
        &proof.signature,
        "join proof signature",
    )?);
    let _ = decode_array::<24>(&proof.nonce, "join proof nonce")?;
    let payload = join_proof_payload(
        &proof.request_id,
        owner_b32,
        token,
        member_b32,
        &proof.nonce,
    )?;
    verifying_key.verify(&payload, &signature).map_err(|_| {
        PrivateGroupInviteError::from("private group invite proof verification failed")
    })
}

fn join_proof_payload(
    request_id: &str,
    owner_b32: &str,
    token: &str,
    member_b32: &str,
    nonce: &str,
) -> Result<Vec<u8>, PrivateGroupInviteError> {
    let owner_b32 = owner_b32.to_ascii_lowercase();
    let member_b32 = member_b32.to_ascii_lowercase();
    Ok(serde_json::to_vec(&JoinProofPayload {
        domain: JOIN_PROOF_DOMAIN,
        request_id,
        owner_b32: &owner_b32,
        token,
        member_b32: &member_b32,
        nonce,
    })?)
}

fn validate_times(
    created_ms: u64,
    expires_ms: u64,
    now_ms: u64,
) -> Result<(), PrivateGroupInviteError> {
    if expires_ms <= created_ms || expires_ms.saturating_sub(created_ms) > VALIDITY_MS {
        return Err("private group request has invalid lifetime".into());
    }
    if created_ms > now_ms.saturating_add(MAX_CLOCK_SKEW_MS) {
        return Err("private group request was created too far in the future".into());
    }
    if now_ms > expires_ms {
        return Err("private group request has expired".into());
    }
    Ok(())
}

fn derive_response_key(
    shared: &[u8; 32],
    request_id: &[u8; 16],
    nonce: &[u8; 24],
    verifying_key: &[u8; 32],
) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(RESPONSE_KDF_DOMAIN);
    hash.update(shared);
    hash.update(request_id);
    hash.update(nonce);
    hash.update(verifying_key);
    hash.finalize().into()
}

fn reject_zero_shared(
    shared: &[u8; 32],
    message: &'static str,
) -> Result<(), PrivateGroupInviteError> {
    if shared.iter().all(|byte| *byte == 0) {
        return Err(message.into());
    }
    Ok(())
}

fn compress(value: &[u8]) -> Result<Vec<u8>, PrivateGroupInviteError> {
    if value.len() > MAX_DECOMPRESSED_PAYLOAD {
        return Err("private group invite payload is too large".into());
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(value)?;
    Ok(encoder.finish()?)
}

fn decompress_limited(value: &[u8]) -> Result<Vec<u8>, PrivateGroupInviteError> {
    let mut output = Vec::new();
    GzDecoder::new(value)
        .take((MAX_DECOMPRESSED_PAYLOAD + 1) as u64)
        .read_to_end(&mut output)?;
    if output.len() > MAX_DECOMPRESSED_PAYLOAD {
        return Err("private group invite payload is too large".into());
    }
    Ok(output)
}

fn encode_json<T: Serialize>(prefix: &str, value: &T) -> Result<String, PrivateGroupInviteError> {
    let encoded = format!(
        "{prefix}{}",
        general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(value)?)
    );
    if encoded.len() > MAX_ENCODED_LEN {
        return Err("private group invitation string is too large".into());
    }
    Ok(encoded)
}

fn decode_json<T: DeserializeOwned>(
    value: &str,
    prefix: &str,
) -> Result<T, PrivateGroupInviteError> {
    let value = value.trim();
    if value.len() > MAX_ENCODED_LEN {
        return Err("private group invitation string is too large".into());
    }
    let encoded = value.strip_prefix(prefix).ok_or_else(|| {
        PrivateGroupInviteError::from("private group invitation has wrong prefix")
    })?;
    let json = decode_limited(encoded, "private group invitation")?;
    serde_json::from_slice(&json)
        .map_err(|_| PrivateGroupInviteError::from("invalid private group invitation"))
}

fn decode_limited(value: &str, label: &str) -> Result<Vec<u8>, PrivateGroupInviteError> {
    if value.len() > MAX_ENCODED_LEN {
        return Err(format!("{label} is too large").into());
    }
    general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| PrivateGroupInviteError::from(format!("{label} is not valid base64")))
}

fn decode_array<const N: usize>(
    value: &str,
    label: &str,
) -> Result<[u8; N], PrivateGroupInviteError> {
    decode_limited(value, label)?
        .try_into()
        .map_err(|_| PrivateGroupInviteError::from(format!("{label} has invalid length")))
}

fn encode(value: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(value)
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct PrivateGroupInviteError(String);

impl From<&str> for PrivateGroupInviteError {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl From<String> for PrivateGroupInviteError {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<serde_json::Error> for PrivateGroupInviteError {
    fn from(_: serde_json::Error) -> Self {
        Self("private group invitation serialization failed".to_string())
    }
}

impl From<std::io::Error> for PrivateGroupInviteError {
    fn from(_: std::io::Error) -> Self {
        Self("private group invitation compression failed".to_string())
    }
}
