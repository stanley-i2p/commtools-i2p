use crypto_secretbox::{
    Key, Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x25519_dalek::{PublicKey, StaticSecret};

pub const SESSION_NONCE_SIZE: usize = 24;
pub const AUTH_TAG_SIZE: usize = 16;
pub const MIN_ENCRYPTED_PAYLOAD_SIZE: usize = SESSION_NONCE_SIZE + AUTH_TAG_SIZE;

const CLASSICAL_KDF_DOMAIN: &[u8] = b"COMMTOOLS-I2P-CLASSICAL-V1";
const OFFLINE_KDF_DOMAIN: &[u8] = b"OFFLINE_BLOB_V1";

/// Ephemeral X25519 agreement and authenticated live-session encryption.
///
/// This type intentionally exposes no plaintext fallback. A caller must finish
/// key agreement before sealing or opening application payloads.
#[derive(Clone)]
pub struct SessionCrypto {
    private_key: StaticSecret,
    public_key: PublicKey,
    session_key: Option<[u8; 32]>,
}

impl SessionCrypto {
    pub fn generate() -> Self {
        Self::from_private_key(StaticSecret::random_from_rng(OsRng).to_bytes())
    }

    /// Constructs a session from key material supplied by a secure owner.
    ///
    /// This is useful for deterministic compatibility tests and controlled key
    /// restoration. Frontends should normally use [`Self::generate`].
    pub fn from_private_key(private_key: [u8; 32]) -> Self {
        let private_key = StaticSecret::from(private_key);
        let public_key = PublicKey::from(&private_key);
        Self {
            private_key,
            public_key,
            session_key: None,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }

    pub fn is_ready(&self) -> bool {
        self.session_key.is_some()
    }

    pub fn receive_peer_key(&mut self, peer_key: &[u8]) -> Result<(), CryptoError> {
        let peer_key: [u8; 32] = peer_key
            .try_into()
            .map_err(|_| CryptoError::InvalidPeerKeyLength(peer_key.len()))?;
        let shared = self
            .private_key
            .diffie_hellman(&PublicKey::from(peer_key))
            .to_bytes();
        if shared.iter().all(|byte| *byte == 0) {
            return Err(CryptoError::InvalidPeerKey);
        }

        self.session_key = Some(derive_classical_session_key(&shared));
        Ok(())
    }

    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = [0u8; SESSION_NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce);
        self.seal_with_nonce(plaintext, nonce)
    }

    pub fn open(&self, payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let key = self.session_key.ok_or(CryptoError::SessionNotReady)?;
        open_with_key(&key, payload)
    }

    fn seal_with_nonce(
        &self,
        plaintext: &[u8],
        nonce: [u8; SESSION_NONCE_SIZE],
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self.session_key.ok_or(CryptoError::SessionNotReady)?;
        seal_with_key_and_nonce(&key, plaintext, nonce)
    }
}

impl Default for SessionCrypto {
    fn default() -> Self {
        Self::generate()
    }
}

pub fn derive_offline_blob_key(shared_secret: &[u8], my_b32: &str, peer_b32: &str) -> [u8; 32] {
    let mut identities = [normalize_b32(my_b32), normalize_b32(peer_b32)];
    identities.sort();

    let mut material = Vec::with_capacity(
        OFFLINE_KDF_DOMAIN.len()
            + shared_secret.len()
            + identities[0].len()
            + identities[1].len()
            + 3,
    );
    material.extend_from_slice(OFFLINE_KDF_DOMAIN);
    material.push(b'|');
    material.extend_from_slice(shared_secret);
    material.push(b'|');
    material.extend_from_slice(identities[0].as_bytes());
    material.push(b'|');
    material.extend_from_slice(identities[1].as_bytes());
    Sha256::digest(material).into()
}

pub fn seal_offline_blob(plaintext: &[u8], blob_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = require_key(blob_key)?;
    let mut nonce = [0u8; SESSION_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce);
    seal_with_key_and_nonce(&key, plaintext, nonce)
}

pub fn open_offline_blob(payload: &[u8], blob_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = require_key(blob_key)?;
    open_with_key(&key, payload)
}

fn derive_classical_session_key(shared: &[u8; 32]) -> [u8; 32] {
    let mut material = Vec::with_capacity(CLASSICAL_KDF_DOMAIN.len() + shared.len() + 1);
    material.extend_from_slice(CLASSICAL_KDF_DOMAIN);
    material.push(b'|');
    material.extend_from_slice(shared);
    Sha256::digest(material).into()
}

fn seal_with_key_and_nonce(
    key: &[u8; 32],
    plaintext: &[u8],
    nonce: [u8; SESSION_NONCE_SIZE],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = XSalsa20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| CryptoError::EncryptionFailed)?;
    let mut payload = Vec::with_capacity(nonce.len() + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);
    Ok(payload)
}

fn open_with_key(key: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if payload.len() < MIN_ENCRYPTED_PAYLOAD_SIZE {
        return Err(CryptoError::EncryptedPayloadTooShort(payload.len()));
    }
    let (nonce, ciphertext) = payload.split_at(SESSION_NONCE_SIZE);
    XSalsa20Poly1305::new(Key::from_slice(key))
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| CryptoError::AuthenticationFailed)
}

fn require_key(key: &[u8]) -> Result<[u8; 32], CryptoError> {
    key.try_into()
        .map_err(|_| CryptoError::InvalidKeyLength(key.len()))
}

fn normalize_b32(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    normalized
        .strip_suffix(".b32.i2p")
        .unwrap_or(&normalized)
        .to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    #[error("peer X25519 key must be 32 bytes, got {0}")]
    InvalidPeerKeyLength(usize),
    #[error("peer X25519 key produced an invalid all-zero shared secret")]
    InvalidPeerKey,
    #[error("secure session key is not ready")]
    SessionNotReady,
    #[error("symmetric key must be 32 bytes, got {0}")]
    InvalidKeyLength(usize),
    #[error("encrypted payload is too short: {0} bytes")]
    EncryptedPayloadTooShort(usize),
    #[error("payload encryption failed")]
    EncryptionFailed,
    #[error("payload authentication failed")]
    AuthenticationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_session_vector_matches_established_layout() {
        let mut alice = SessionCrypto::from_private_key([1; 32]);
        let mut bob = SessionCrypto::from_private_key([2; 32]);
        alice
            .receive_peer_key(&bob.public_key_bytes())
            .expect("alice agreement");
        bob.receive_peer_key(&alice.public_key_bytes())
            .expect("bob agreement");

        let sealed = alice
            .seal_with_nonce(b"compatibility", [3; SESSION_NONCE_SIZE])
            .expect("seal");
        assert_eq!(&sealed[..SESSION_NONCE_SIZE], &[3; SESSION_NONCE_SIZE]);
        assert_eq!(bob.open(&sealed).expect("open"), b"compatibility");
    }
}
