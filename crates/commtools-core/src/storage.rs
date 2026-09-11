use crate::config::SamEndpoint;
use crate::ids::{ContactId, GroupId};
use crate::offline::{
    OfflineMissingIndexSnapshot, OfflineSkippedIndexSnapshot, OfflineState, OfflineStateSnapshot,
};
use crate::private_group_invite::{
    PendingPrivateRequest, PrivateInviteBinding, PrivateJoinCredential,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;
use zeroize::Zeroize;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const STORAGE_FORMAT: &str = "COMMTOOLS-I2P-STORAGE";
pub const STORAGE_SCHEMA_VERSION: u32 = 1;
pub const MAX_STORAGE_BYTES: u64 = 16 * 1_024 * 1_024;
pub const MAX_CONTACTS: usize = 4_096;
pub const MAX_GROUPS: usize = 4_096;
pub const MAX_GROUP_MEMBERS: usize = 4_096;
pub const MAX_DEADDROP_SERVERS: usize = 64;
pub const MAX_PENDING_PRIVATE_REQUESTS: usize = 4_096;
pub const MIN_TUNNEL_LENGTH: u8 = 1;
pub const MAX_TUNNEL_LENGTH: u8 = 4;
pub const MIN_TUNNEL_QUANTITY: u8 = 1;
pub const MAX_TUNNEL_QUANTITY: u8 = 5;
pub const DEFAULT_TUNNEL_LENGTH: u8 = 2;
pub const DEFAULT_TUNNEL_QUANTITY: u8 = 3;
pub const DEFAULT_DEADDROP_SERVERS: [&str; 3] = [
    "62afc5yf2lcthx44okvavvmvgb55cee3weqeqhuapcclz6evwyrq.b32.i2p",
    "x75crc4lkcd3xcfrj5sox662mujngzrtmvmejaixutdozg35fgvq.b32.i2p",
    "xxbgj3dlw7fvwz3emqnvyzxrdj3vqd3fcdw6rutmvzoxidyhp7bq.b32.i2p",
];

const CONTACTS_DIR: &str = "profiles";
const GROUPS_DIR: &str = "groups";
const FILES_DIR: &str = "files";
const APP_CONFIG_FILE: &str = "app_config.json";
const PENDING_PRIVATE_REQUESTS_FILE: &str = "pending_private_group_invites.json";
const STORAGE_MANIFEST_FILE: &str = ".commtools-storage.json";
const DEADDROP_STATS_FILE: &str = "deaddrop_stats.json";
const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_DESTINATION_BYTES: usize = 16 * 1_024;
const MAX_SECRET_TEXT_BYTES: usize = 16 * 1_024;
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

#[derive(Clone, PartialEq, Eq)]
pub struct SecretBytes32([u8; 32]);

impl SecretBytes32 {
    pub fn new(value: [u8; 32]) -> Result<Self, StorageError> {
        if value.iter().all(|byte| *byte == 0) {
            return Err(StorageError::Validation(
                "32-byte secret must not be all zero".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes32 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretBytes32(<redacted>)")
    }
}

impl Drop for SecretBytes32 {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretBytes32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for SecretBytes32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(serde::de::Error::custom)?;
        let value: [u8; 32] = decoded
            .try_into()
            .map_err(|_| serde::de::Error::custom("secret must contain exactly 32 bytes"))?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretText(String);

impl SecretText {
    pub fn new(value: impl Into<String>) -> Result<Self, StorageError> {
        let value = value.into();
        validate_bounded_text("secret", &value, MAX_SECRET_TEXT_BYTES)?;
        Ok(Self(value))
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretText {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretText(<redacted>)")
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Serialize for SecretText {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretText {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GlobalSettings {
    pub sam_host: String,
    pub sam_port: u16,
    #[serde(default)]
    pub default_tunnels: TunnelSettings,
    #[serde(default)]
    pub sam_liveness_enabled: bool,
    #[serde(default)]
    pub sam_failure_action: SamFailureAction,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum SamFailureAction {
    GracefulShutdown,
    #[default]
    WarningOnly,
}

impl Default for GlobalSettings {
    fn default() -> Self {
        let endpoint = SamEndpoint::default();
        Self {
            sam_host: endpoint.host().to_string(),
            sam_port: endpoint.port(),
            default_tunnels: TunnelSettings::default(),
            sam_liveness_enabled: false,
            sam_failure_action: SamFailureAction::default(),
        }
    }
}

impl GlobalSettings {
    pub fn sam_endpoint(&self) -> Result<SamEndpoint, StorageError> {
        SamEndpoint::new(&self.sam_host, self.sam_port)
            .map_err(|error| StorageError::Validation(error.to_string()))
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        self.sam_endpoint()?;
        self.default_tunnels.validate()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersistentIdentity {
    pub destination_b64: SecretText,
    pub b32: String,
}

impl PersistentIdentity {
    pub fn new(
        destination_b64: impl Into<String>,
        b32: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let b32 = b32.into();
        let identity = Self {
            destination_b64: SecretText::new(destination_b64)?,
            b32: normalize_b32(&b32)?,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<(), StorageError> {
        validate_bounded_text(
            "I2P destination",
            self.destination_b64.expose_secret(),
            MAX_DESTINATION_BYTES,
        )?;
        require_normalized_b32("identity b32", &self.b32)
    }
}

impl fmt::Debug for PersistentIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistentIdentity")
            .field("destination_b64", &"<redacted>")
            .field("b32", &self.b32)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TofuPeerPin {
    pub b32: String,
    pub destination_b64: String,
}

impl fmt::Debug for TofuPeerPin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TofuPeerPin")
            .field("b32", &self.b32)
            .field("destination_b64", &"<redacted>")
            .finish()
    }
}

impl TofuPeerPin {
    pub fn new(
        b32: impl Into<String>,
        destination_b64: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let b32 = b32.into();
        let pin = Self {
            b32: normalize_b32(&b32)?,
            destination_b64: destination_b64.into(),
        };
        pin.validate()?;
        Ok(pin)
    }

    fn validate(&self) -> Result<(), StorageError> {
        require_normalized_b32("TOFU peer b32", &self.b32)?;
        validate_bounded_text(
            "TOFU peer destination",
            &self.destination_b64,
            MAX_DESTINATION_BYTES,
        )
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TunnelSettings {
    pub length: u8,
    pub quantity: u8,
}

impl Default for TunnelSettings {
    fn default() -> Self {
        Self {
            length: DEFAULT_TUNNEL_LENGTH,
            quantity: DEFAULT_TUNNEL_QUANTITY,
        }
    }
}

impl TunnelSettings {
    pub fn validate(self) -> Result<(), StorageError> {
        if !(MIN_TUNNEL_LENGTH..=MAX_TUNNEL_LENGTH).contains(&self.length) {
            return Err(StorageError::Validation(format!(
                "tunnel length must be {MIN_TUNNEL_LENGTH}..={MAX_TUNNEL_LENGTH}"
            )));
        }
        if !(MIN_TUNNEL_QUANTITY..=MAX_TUNNEL_QUANTITY).contains(&self.quantity) {
            return Err(StorageError::Validation(format!(
                "tunnel quantity must be {MIN_TUNNEL_QUANTITY}..={MAX_TUNNEL_QUANTITY}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeaddropServerStat {
    pub put_ok: u64,
    pub put_fail: u64,
    pub get_ok: u64,
    pub get_fail: u64,
    pub last_success_ms: u64,
    pub latency_ema_ms: f64,
    pub latency_samples: u64,
}

impl Default for DeaddropServerStat {
    fn default() -> Self {
        Self {
            put_ok: 0,
            put_fail: 0,
            get_ok: 0,
            get_fail: 0,
            last_success_ms: 0,
            latency_ema_ms: 0.0,
            latency_samples: 0,
        }
    }
}

impl DeaddropServerStat {
    fn validate(&self) -> Result<(), StorageError> {
        if !self.latency_ema_ms.is_finite() || self.latency_ema_ms < 0.0 {
            return Err(StorageError::Validation(
                "deaddrop latency must be finite and non-negative".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PersistedOfflineState {
    pub shared_secret: SecretBytes32,
    pub state: OfflineStateSnapshot,
}

impl PersistedOfflineState {
    pub fn new(shared_secret: [u8; 32], state: &OfflineState) -> Result<Self, StorageError> {
        Ok(Self {
            shared_secret: SecretBytes32::new(shared_secret)?,
            state: state.snapshot(),
        })
    }

    pub fn restore(&self) -> Result<OfflineState, StorageError> {
        OfflineState::from_snapshot(self.state.clone())
            .map_err(|error| StorageError::Validation(error.to_string()))
    }

    fn validate(&self) -> Result<(), StorageError> {
        self.restore().map(|_| ())
    }
}

impl fmt::Debug for PersistedOfflineState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PersistedOfflineState")
            .field("shared_secret", &"<redacted>")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ContactRecord {
    pub id: ContactId,
    pub display_name: String,
    pub identity: Option<PersistentIdentity>,
    pub tofu_peer: Option<TofuPeerPin>,
    pub pq_enabled: bool,
    pub history_enabled: bool,
    pub tunnels: TunnelSettings,
    pub deaddrop_servers: Vec<String>,
    pub deaddrop_stats: BTreeMap<String, DeaddropServerStat>,
    pub offline: Option<PersistedOfflineState>,
}

impl ContactRecord {
    pub fn new(id: ContactId, display_name: impl Into<String>) -> Result<Self, StorageError> {
        let record = Self {
            id,
            display_name: display_name.into(),
            identity: None,
            tofu_peer: None,
            pq_enabled: false,
            history_enabled: false,
            tunnels: TunnelSettings::default(),
            deaddrop_servers: DEFAULT_DEADDROP_SERVERS
                .iter()
                .map(|server| (*server).to_string())
                .collect(),
            deaddrop_stats: BTreeMap::new(),
            offline: None,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn set_display_name(
        &mut self,
        display_name: impl Into<String>,
    ) -> Result<(), StorageError> {
        let display_name = display_name.into();
        validate_contact_name(&display_name)?;
        self.display_name = display_name;
        Ok(())
    }

    fn validate(&self) -> Result<(), StorageError> {
        validate_contact_name(&self.display_name)?;
        self.tunnels.validate()?;
        if let Some(identity) = &self.identity {
            identity.validate()?;
        }
        if let Some(peer) = &self.tofu_peer {
            peer.validate()?;
        }
        validate_deaddrops(&self.deaddrop_servers, &self.deaddrop_stats)?;
        if let Some(offline) = &self.offline {
            if self.identity.is_none() || self.tofu_peer.is_none() {
                return Err(StorageError::Validation(
                    "offline state requires persistent local and pinned peer identities".into(),
                ));
            }
            offline.validate()?;
        }
        Ok(())
    }
}

impl fmt::Debug for ContactRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ContactRecord")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("identity", &self.identity)
            .field("tofu_peer", &self.tofu_peer)
            .field("pq_enabled", &self.pq_enabled)
            .field("history_enabled", &self.history_enabled)
            .field("tunnels", &self.tunnels)
            .field("deaddrop_servers", &self.deaddrop_servers)
            .field("deaddrop_stats", &self.deaddrop_stats)
            .field("offline", &self.offline)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupMemberRecord {
    pub name: String,
    pub b32: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupIssuedInviteRecord {
    pub token: SecretText,
    pub redeemed_b32: Option<String>,
    pub private_binding: Option<PrivateInviteBinding>,
}

impl fmt::Debug for GroupIssuedInviteRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupIssuedInviteRecord")
            .field("token", &"<redacted>")
            .field("redeemed_b32", &self.redeemed_b32)
            .field("private_binding", &self.private_binding)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupRecord {
    pub id: GroupId,
    pub display_name: String,
    pub identity: Option<PersistentIdentity>,
    pub local_member_name: String,
    pub history_enabled: bool,
    pub owner_b32: Option<String>,
    pub roster_version: u64,
    pub members: Vec<GroupMemberRecord>,
    pub join_token: Option<SecretText>,
    pub private_join_credential: Option<PrivateJoinCredential>,
    pub issued_invites: Vec<GroupIssuedInviteRecord>,
    pub roster_signing_public_key: Option<String>,
    pub roster_signing_secret: Option<SecretText>,
    pub roster_signature: Option<String>,
}

impl GroupRecord {
    pub fn new(id: GroupId, display_name: impl Into<String>) -> Result<Self, StorageError> {
        let record = Self {
            id,
            display_name: display_name.into(),
            identity: None,
            local_member_name: String::new(),
            history_enabled: false,
            owner_b32: None,
            roster_version: 1,
            members: Vec::new(),
            join_token: None,
            private_join_credential: None,
            issued_invites: Vec::new(),
            roster_signing_public_key: None,
            roster_signing_secret: None,
            roster_signature: None,
        };
        record.validate()?;
        Ok(record)
    }

    fn validate(&self) -> Result<(), StorageError> {
        validate_display_name("group name", &self.display_name, false)?;
        if !self.local_member_name.is_empty() {
            validate_display_name("group member name", &self.local_member_name, false)?;
        }
        if let Some(identity) = &self.identity {
            identity.validate()?;
        }
        if let Some(owner) = &self.owner_b32 {
            require_normalized_b32("group owner b32", owner)?;
        }
        if self.roster_version == 0 {
            return Err(StorageError::Validation(
                "group roster version must be nonzero".into(),
            ));
        }
        if self.members.len() > MAX_GROUP_MEMBERS || self.issued_invites.len() > MAX_GROUP_MEMBERS {
            return Err(StorageError::Validation(
                "group member or invite limit exceeded".into(),
            ));
        }
        let mut member_addresses = BTreeSet::new();
        for member in &self.members {
            validate_display_name("group member name", &member.name, false)?;
            require_normalized_b32("group member b32", &member.b32)?;
            if !member_addresses.insert(&member.b32) {
                return Err(StorageError::Validation(
                    "group contains duplicate member b32 addresses".into(),
                ));
            }
        }
        let mut invite_tokens = BTreeSet::new();
        for invite in &self.issued_invites {
            validate_bounded_text(
                "group invite token",
                invite.token.expose_secret(),
                MAX_SECRET_TEXT_BYTES,
            )?;
            if !invite_tokens.insert(invite.token.expose_secret()) {
                return Err(StorageError::Validation(
                    "group contains duplicate invite tokens".into(),
                ));
            }
            if let Some(redeemed) = &invite.redeemed_b32 {
                require_normalized_b32("redeemed group member b32", redeemed)?;
            }
        }
        validate_optional_text("roster signing public key", &self.roster_signing_public_key)?;
        validate_optional_text("roster signature", &self.roster_signature)?;
        if self.roster_signature.is_some() != self.roster_signing_public_key.is_some() {
            return Err(StorageError::Validation(
                "roster signature and public key must be stored together".into(),
            ));
        }
        if let Some(join_token) = &self.join_token {
            validate_bounded_text(
                "group join token",
                join_token.expose_secret(),
                MAX_SECRET_TEXT_BYTES,
            )?;
        }
        if let Some(secret) = &self.roster_signing_secret {
            validate_bounded_text(
                "roster signing secret",
                secret.expose_secret(),
                MAX_SECRET_TEXT_BYTES,
            )?;
        }
        Ok(())
    }
}

impl fmt::Debug for GroupRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GroupRecord")
            .field("id", &self.id)
            .field("display_name", &self.display_name)
            .field("identity", &self.identity)
            .field("local_member_name", &self.local_member_name)
            .field("history_enabled", &self.history_enabled)
            .field("owner_b32", &self.owner_b32)
            .field("roster_version", &self.roster_version)
            .field("members", &self.members)
            .field(
                "join_token",
                &self.join_token.as_ref().map(|_| "<redacted>"),
            )
            .field("private_join_credential", &self.private_join_credential)
            .field("issued_invites", &self.issued_invites)
            .field("roster_signing_public_key", &self.roster_signing_public_key)
            .field(
                "roster_signing_secret",
                &self.roster_signing_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("roster_signature", &self.roster_signature)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSnapshot {
    format: String,
    schema_version: u32,
    revision: u64,
    pub settings: GlobalSettings,
    pub contacts: BTreeMap<ContactId, ContactRecord>,
    pub groups: BTreeMap<GroupId, GroupRecord>,
    pub pending_private_group_requests: Vec<PendingPrivateRequest>,
}

impl StorageSnapshot {
    pub fn new() -> Self {
        Self {
            format: STORAGE_FORMAT.into(),
            schema_version: STORAGE_SCHEMA_VERSION,
            revision: 0,
            settings: GlobalSettings::default(),
            contacts: BTreeMap::new(),
            groups: BTreeMap::new(),
            pending_private_group_requests: Vec::new(),
        }
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn validate(&self) -> Result<(), StorageError> {
        if self.format != STORAGE_FORMAT {
            return Err(StorageError::UnsupportedFormat(self.format.clone()));
        }
        if self.schema_version != STORAGE_SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchema(self.schema_version));
        }
        self.settings.validate()?;
        if self.contacts.len() > MAX_CONTACTS
            || self.groups.len() > MAX_GROUPS
            || self.pending_private_group_requests.len() > MAX_PENDING_PRIVATE_REQUESTS
        {
            return Err(StorageError::Validation("record limit exceeded".into()));
        }
        let mut pending_request_ids = BTreeSet::new();
        for request in &self.pending_private_group_requests {
            validate_bounded_text("private group request id", request.request_id(), 256)?;
            if request.expires_ms() == 0 || !pending_request_ids.insert(request.request_id()) {
                return Err(StorageError::Validation(
                    "invalid or duplicate pending private group request".into(),
                ));
            }
        }

        let mut contact_names = BTreeSet::new();
        for (id, contact) in &self.contacts {
            if id != &contact.id {
                return Err(StorageError::Validation(
                    "contact map key does not match record id".into(),
                ));
            }
            contact.validate()?;
            if !contact_names.insert(contact.display_name.to_lowercase()) {
                return Err(StorageError::Validation(
                    "contact display names must be unique ignoring case".into(),
                ));
            }
        }
        for (id, group) in &self.groups {
            if id != &group.id {
                return Err(StorageError::Validation(
                    "group map key does not match record id".into(),
                ));
            }
            group.validate()?;
        }
        Ok(())
    }

    pub(crate) fn clone_with_revision(&self, revision: u64) -> Result<Self, StorageError> {
        let mut snapshot = self.clone();
        snapshot.revision = revision;
        snapshot.validate()?;
        Ok(snapshot)
    }
}

impl Default for StorageSnapshot {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for StorageSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StorageSnapshot")
            .field("format", &self.format)
            .field("schema_version", &self.schema_version)
            .field("revision", &self.revision)
            .field("settings", &self.settings)
            .field("contact_count", &self.contacts.len())
            .field("group_count", &self.groups.len())
            .field(
                "pending_private_group_request_count",
                &self.pending_private_group_requests.len(),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct StorageRepository {
    root: PathBuf,
}

impl StorageRepository {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let root = root.into();
        if root.as_os_str().is_empty() {
            return Err(StorageError::Validation(
                "storage root must not be empty".into(),
            ));
        }
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn load(&self) -> Result<Option<StorageSnapshot>, StorageError> {
        if !self.root.exists() {
            return Ok(None);
        }

        let manifest = self.load_manifest()?.unwrap_or_default();
        let settings = self.load_json_or_default::<GlobalSettings>(&self.app_config_path())?;
        let pending_private_group_requests =
            self.load_json_or_default::<Vec<PendingPrivateRequest>>(&self.pending_requests_path())?;
        let contacts = self.load_contacts(&manifest)?;
        let groups = self.load_groups(&manifest)?;

        let mut snapshot = StorageSnapshot::new();
        snapshot.settings = settings;
        snapshot.contacts = contacts;
        snapshot.groups = groups;
        snapshot.pending_private_group_requests = pending_private_group_requests;
        snapshot = snapshot.clone_with_revision(manifest.revision)?;
        Ok(Some(snapshot))
    }

    pub fn load_or_empty(&self) -> Result<StorageSnapshot, StorageError> {
        Ok(self.load()?.unwrap_or_default())
    }

    pub fn commit(&self, snapshot: &mut StorageSnapshot) -> Result<(), StorageError> {
        snapshot.validate()?;
        let disk_revision = self.load_manifest()?.unwrap_or_default().revision;
        if disk_revision != snapshot.revision {
            return Err(StorageError::RevisionConflict {
                expected: snapshot.revision,
                actual: disk_revision,
            });
        }
        let next_revision = snapshot
            .revision
            .checked_add(1)
            .ok_or(StorageError::RevisionExhausted)?;
        let committed = snapshot.clone_with_revision(next_revision)?;
        self.ensure_layout()?;
        self.write_json_atomic(&self.app_config_path(), &committed.settings)?;
        self.write_json_atomic(
            &self.pending_requests_path(),
            &committed.pending_private_group_requests,
        )?;

        let mut manifest = StorageManifest {
            format: STORAGE_FORMAT.into(),
            schema_version: STORAGE_SCHEMA_VERSION,
            revision: next_revision,
            contact_ids: BTreeMap::new(),
            group_ids: BTreeMap::new(),
        };
        self.write_contacts(&committed, &mut manifest)?;
        self.write_groups(&committed, &mut manifest)?;

        // The manifest is the commit marker and is intentionally published last.
        self.write_json_atomic(&self.manifest_path(), &manifest)?;
        sync_directory(self.root.clone())?;
        *snapshot = committed;
        Ok(())
    }

    pub fn files_dir(&self) -> PathBuf {
        self.root.join(FILES_DIR)
    }

    pub(crate) fn contact_directory(&self, display_name: &str) -> Result<PathBuf, StorageError> {
        validate_contact_directory_name(display_name)?;
        Ok(self.contacts_dir().join(display_name))
    }

    fn ensure_layout(&self) -> Result<(), StorageError> {
        create_secure_directory(&self.root)?;
        create_secure_directory(&self.contacts_dir())?;
        create_secure_directory(&self.groups_dir())?;
        create_secure_directory(&self.files_dir())
    }

    fn contacts_dir(&self) -> PathBuf {
        self.root.join(CONTACTS_DIR)
    }

    fn groups_dir(&self) -> PathBuf {
        self.root.join(GROUPS_DIR)
    }

    fn manifest_path(&self) -> PathBuf {
        self.root.join(STORAGE_MANIFEST_FILE)
    }

    fn app_config_path(&self) -> PathBuf {
        self.root.join(APP_CONFIG_FILE)
    }

    fn pending_requests_path(&self) -> PathBuf {
        self.root.join(PENDING_PRIVATE_REQUESTS_FILE)
    }

    fn load_manifest(&self) -> Result<Option<StorageManifest>, StorageError> {
        let path = self.manifest_path();
        if !path.exists() {
            return Ok(None);
        }
        let manifest: StorageManifest = self.load_json(&path)?;
        manifest.validate()?;
        Ok(Some(manifest))
    }

    fn load_contacts(
        &self,
        manifest: &StorageManifest,
    ) -> Result<BTreeMap<ContactId, ContactRecord>, StorageError> {
        let mut contacts = BTreeMap::new();
        let directory = self.contacts_dir();
        if !directory.exists() {
            return Ok(contacts);
        }
        for entry in fs::read_dir(&directory).map_err(|error| io_error(&directory, error))? {
            let entry = entry.map_err(|error| io_error(&directory, error))?;
            if !entry
                .file_type()
                .map_err(|error| io_error(&entry.path(), error))?
                .is_dir()
            {
                continue;
            }
            let Some(directory_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let metadata_path = entry.path().join(format!("{directory_name}.dat"));
            if !metadata_path.is_file() {
                continue;
            }
            let metadata: ContactMetadataFile = self.load_json(&metadata_path)?;
            let id_text = manifest
                .contact_ids
                .get(&directory_name)
                .map(String::as_str)
                .unwrap_or(&directory_name);
            let id = ContactId::new(id_text)
                .map_err(|error| StorageError::Validation(error.to_string()))?;
            let record = self.contact_from_files(id.clone(), &entry.path(), metadata)?;
            if contacts.insert(id, record).is_some() {
                return Err(StorageError::Validation(
                    "duplicate contact identifier".into(),
                ));
            }
        }
        Ok(contacts)
    }

    fn contact_from_files(
        &self,
        id: ContactId,
        directory: &Path,
        metadata: ContactMetadataFile,
    ) -> Result<ContactRecord, StorageError> {
        let identity = optional_identity(metadata.my_dest_b64, metadata.my_b32)?;
        let tofu_peer = optional_peer(metadata.locked_peer, metadata.locked_peer_dest_b64)?;
        let stats_path = directory.join(DEADDROP_STATS_FILE);
        let stats = self.load_json_or_default::<BTreeMap<String, ContactStatFile>>(&stats_path)?;
        let deaddrop_stats = stats
            .into_iter()
            .map(|(server, stat)| (server, stat.into_record()))
            .collect();
        let offline = match tofu_peer.as_ref() {
            Some(peer) => self.load_offline(directory, &peer.b32)?,
            None => None,
        };
        let record = ContactRecord {
            id,
            display_name: metadata.name,
            identity,
            tofu_peer,
            pq_enabled: metadata.pq_enabled,
            history_enabled: metadata.history_enabled,
            tunnels: TunnelSettings {
                length: metadata.tunnel_hops,
                quantity: metadata.tunnel_quantity,
            },
            deaddrop_servers: metadata.deaddrop_servers,
            deaddrop_stats,
            offline,
        };
        record.validate()?;
        Ok(record)
    }

    fn load_groups(
        &self,
        manifest: &StorageManifest,
    ) -> Result<BTreeMap<GroupId, GroupRecord>, StorageError> {
        let mut groups = BTreeMap::new();
        let directory = self.groups_dir();
        if !directory.exists() {
            return Ok(groups);
        }
        for entry in fs::read_dir(&directory).map_err(|error| io_error(&directory, error))? {
            let entry = entry.map_err(|error| io_error(&directory, error))?;
            if !entry
                .file_type()
                .map_err(|error| io_error(&entry.path(), error))?
                .is_dir()
            {
                continue;
            }
            let Some(directory_name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let path = entry.path().join("group.json");
            if !path.is_file() {
                continue;
            }
            let metadata: GroupMetadataFile = self.load_json(&path)?;
            let id_text = manifest
                .group_ids
                .get(&directory_name)
                .map(String::as_str)
                .unwrap_or_else(|| {
                    if metadata.id.is_empty() {
                        &directory_name
                    } else {
                        &metadata.id
                    }
                });
            let id = GroupId::new(id_text)
                .map_err(|error| StorageError::Validation(error.to_string()))?;
            let record = metadata.into_record(id.clone())?;
            if groups.insert(id, record).is_some() {
                return Err(StorageError::Validation(
                    "duplicate group identifier".into(),
                ));
            }
        }
        Ok(groups)
    }

    fn write_contacts(
        &self,
        snapshot: &StorageSnapshot,
        manifest: &mut StorageManifest,
    ) -> Result<(), StorageError> {
        let mut retained = BTreeSet::new();
        for contact in snapshot.contacts.values() {
            validate_contact_directory_name(&contact.display_name)?;
            let directory_name = contact.display_name.clone();
            retained.insert(directory_name.clone());
            manifest
                .contact_ids
                .insert(directory_name.clone(), contact.id.to_string());
            let directory = self.contacts_dir().join(&directory_name);
            create_secure_directory(&directory)?;
            let metadata = ContactMetadataFile::from_record(contact);
            self.write_json_atomic(&directory.join(format!("{directory_name}.dat")), &metadata)?;
            let stats = contact
                .deaddrop_stats
                .iter()
                .map(|(server, stat)| (server.clone(), ContactStatFile::from_record(stat)))
                .collect::<BTreeMap<_, _>>();
            self.write_json_atomic(&directory.join(DEADDROP_STATS_FILE), &stats)?;
            self.remove_offline_files_except(
                &directory,
                contact.tofu_peer.as_ref().map(|peer| &peer.b32),
            )?;
            if let (Some(peer), Some(offline)) = (&contact.tofu_peer, &contact.offline) {
                self.write_offline(&directory, &peer.b32, offline)?;
            }
        }
        self.remove_stale_directories(&self.contacts_dir(), &retained)
    }

    fn write_groups(
        &self,
        snapshot: &StorageSnapshot,
        manifest: &mut StorageManifest,
    ) -> Result<(), StorageError> {
        let mut retained = BTreeSet::new();
        for group in snapshot.groups.values() {
            let directory_name = group_storage_key(&group.id);
            retained.insert(directory_name.clone());
            manifest
                .group_ids
                .insert(directory_name.clone(), group.id.to_string());
            let directory = self.groups_dir().join(&directory_name);
            create_secure_directory(&directory)?;
            self.write_json_atomic(
                &directory.join("group.json"),
                &GroupMetadataFile::from_record(group),
            )?;
        }
        self.remove_stale_directories(&self.groups_dir(), &retained)
    }

    fn remove_stale_directories(
        &self,
        parent: &Path,
        retained: &BTreeSet<String>,
    ) -> Result<(), StorageError> {
        for entry in fs::read_dir(parent).map_err(|error| io_error(parent, error))? {
            let entry = entry.map_err(|error| io_error(parent, error))?;
            if !entry
                .file_type()
                .map_err(|error| io_error(&entry.path(), error))?
                .is_dir()
            {
                continue;
            }
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !retained.contains(&name) {
                fs::remove_dir_all(entry.path()).map_err(|error| io_error(&entry.path(), error))?;
            }
        }
        Ok(())
    }

    fn load_json<T: for<'de> Deserialize<'de>>(&self, path: &Path) -> Result<T, StorageError> {
        let bytes = read_bounded(path)?;
        serde_json::from_slice(&bytes).map_err(|error| StorageError::Decode(error.to_string()))
    }

    fn load_json_or_default<T>(&self, path: &Path) -> Result<T, StorageError>
    where
        T: for<'de> Deserialize<'de> + Default,
    {
        if path.exists() {
            self.load_json(path)
        } else {
            Ok(T::default())
        }
    }

    fn write_json_atomic<T: Serialize + ?Sized>(
        &self,
        path: &Path,
        value: &T,
    ) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec_pretty(value)
            .map_err(|error| StorageError::Encode(error.to_string()))?;
        write_atomic(path, &bytes)
    }

    fn load_offline(
        &self,
        directory: &Path,
        peer_b32: &str,
    ) -> Result<Option<PersistedOfflineState>, StorageError> {
        let path = directory.join(offline_state_filename(peer_b32));
        if !path.exists() {
            return Ok(None);
        }
        let text = String::from_utf8(read_bounded(&path)?)
            .map_err(|error| StorageError::Decode(error.to_string()))?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            if let Some((key, value)) = line.split_once('=') {
                values.insert(key.trim(), value.trim());
            }
        }
        let secret = decode_secret_hex(required_value(&values, "offline_shared_secret")?)?;
        let snapshot = OfflineStateSnapshot {
            send_index: parse_value(&values, "drop_send_index", 0)?,
            send_exhausted: parse_value(&values, "send_exhausted", false)?,
            receive_base: parse_value(&values, "drop_recv_base", 0)?,
            receive_exhausted: parse_value(&values, "receive_exhausted", false)?,
            window: parse_value(&values, "drop_window", 8)?,
            consumed: parse_csv(&values, "consumed_drop_recv")?,
            known_remote_next_send: parse_value(&values, "known_remote_next_send", 0)?,
            highest_authenticated_receive: parse_optional(
                &values,
                "highest_authenticated_recv_index",
            )?,
            missing: parse_missing(&values)?,
            skipped: parse_skipped(&values)?,
            forward_probe_index: parse_value(&values, "forward_probe_index", 0)?,
            stalled_sweeps: parse_value(&values, "stalled_sweeps", 0)?,
            last_recovery_probe_ms: parse_value(&values, "last_recovery_probe_ms", 0)?,
            seen_blob_hashes: parse_csv(&values, "seen_blob_hashes")?,
        };
        let offline = PersistedOfflineState {
            shared_secret: SecretBytes32::new(secret)?,
            state: snapshot,
        };
        offline.validate()?;
        Ok(Some(offline))
    }

    fn write_offline(
        &self,
        directory: &Path,
        peer_b32: &str,
        offline: &PersistedOfflineState,
    ) -> Result<(), StorageError> {
        offline.validate()?;
        let state = &offline.state;
        let mut text = String::new();
        text.push_str(&format!(
            "offline_shared_secret={}\n",
            hex::encode(offline.shared_secret.expose_secret())
        ));
        text.push_str(&format!("drop_send_index={}\n", state.send_index));
        text.push_str(&format!("drop_recv_base={}\n", state.receive_base));
        text.push_str(&format!("drop_window={}\n", state.window));
        text.push_str(&format!(
            "consumed_drop_recv={}\n",
            join_csv(&state.consumed)
        ));
        text.push_str(&format!(
            "known_remote_next_send={}\n",
            state.known_remote_next_send
        ));
        text.push_str("highest_authenticated_recv_index=");
        if let Some(index) = state.highest_authenticated_receive {
            text.push_str(&index.to_string());
        }
        text.push('\n');
        text.push_str(&format!(
            "missing_drop_recv={}\n",
            join_missing(&state.missing)
        ));
        text.push_str(&format!(
            "skipped_drop_recv={}\n",
            join_skipped(&state.skipped)
        ));
        text.push_str(&format!(
            "forward_probe_index={}\n",
            state.forward_probe_index
        ));
        text.push_str(&format!("send_exhausted={}\n", state.send_exhausted));
        text.push_str(&format!("receive_exhausted={}\n", state.receive_exhausted));
        text.push_str(&format!("stalled_sweeps={}\n", state.stalled_sweeps));
        text.push_str(&format!(
            "last_recovery_probe_ms={}\n",
            state.last_recovery_probe_ms
        ));
        text.push_str(&format!(
            "seen_blob_hashes={}\n",
            state.seen_blob_hashes.join(",")
        ));
        write_atomic(
            &directory.join(offline_state_filename(peer_b32)),
            text.as_bytes(),
        )
    }

    fn remove_offline_files_except(
        &self,
        directory: &Path,
        peer_b32: Option<&String>,
    ) -> Result<(), StorageError> {
        let retained = peer_b32.map(|peer| offline_state_filename(peer));
        for entry in fs::read_dir(directory).map_err(|error| io_error(directory, error))? {
            let entry = entry.map_err(|error| io_error(directory, error))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with("offline_")
                && name.ends_with(".state")
                && retained.as_deref() != Some(name.as_str())
            {
                fs::remove_file(entry.path()).map_err(|error| io_error(&entry.path(), error))?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageManifest {
    format: String,
    schema_version: u32,
    revision: u64,
    #[serde(default)]
    contact_ids: BTreeMap<String, String>,
    #[serde(default)]
    group_ids: BTreeMap<String, String>,
}

impl Default for StorageManifest {
    fn default() -> Self {
        Self {
            format: STORAGE_FORMAT.into(),
            schema_version: STORAGE_SCHEMA_VERSION,
            revision: 0,
            contact_ids: BTreeMap::new(),
            group_ids: BTreeMap::new(),
        }
    }
}

impl StorageManifest {
    fn validate(&self) -> Result<(), StorageError> {
        if self.format != STORAGE_FORMAT {
            return Err(StorageError::UnsupportedFormat(self.format.clone()));
        }
        if self.schema_version != STORAGE_SCHEMA_VERSION {
            return Err(StorageError::UnsupportedSchema(self.schema_version));
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ContactMetadataFile {
    name: String,
    my_dest_b64: Option<String>,
    #[serde(default)]
    my_b32: Option<String>,
    locked_peer: Option<String>,
    locked_peer_dest_b64: Option<String>,
    pq_enabled: bool,
    #[serde(default)]
    history_enabled: bool,
    #[serde(default)]
    deaddrop_servers: Vec<String>,
    #[serde(default = "default_tunnel_length")]
    tunnel_hops: u8,
    #[serde(default = "default_tunnel_quantity")]
    tunnel_quantity: u8,
}

impl ContactMetadataFile {
    fn from_record(record: &ContactRecord) -> Self {
        Self {
            name: record.display_name.clone(),
            my_dest_b64: record
                .identity
                .as_ref()
                .map(|identity| identity.destination_b64.expose_secret().to_owned()),
            my_b32: record
                .identity
                .as_ref()
                .map(|identity| identity.b32.clone()),
            locked_peer: record.tofu_peer.as_ref().map(|peer| peer.b32.clone()),
            locked_peer_dest_b64: record
                .tofu_peer
                .as_ref()
                .map(|peer| peer.destination_b64.clone()),
            pq_enabled: record.pq_enabled,
            history_enabled: record.history_enabled,
            deaddrop_servers: record.deaddrop_servers.clone(),
            tunnel_hops: record.tunnels.length,
            tunnel_quantity: record.tunnels.quantity,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ContactStatFile {
    put_ok: u64,
    put_fail: u64,
    get_ok: u64,
    get_fail: u64,
    last_success_ts: f64,
    latency_ema_ms: f64,
    latency_samples: u64,
}

impl ContactStatFile {
    fn from_record(record: &DeaddropServerStat) -> Self {
        Self {
            put_ok: record.put_ok,
            put_fail: record.put_fail,
            get_ok: record.get_ok,
            get_fail: record.get_fail,
            last_success_ts: record.last_success_ms as f64 / 1_000.0,
            latency_ema_ms: record.latency_ema_ms,
            latency_samples: record.latency_samples,
        }
    }

    fn into_record(self) -> DeaddropServerStat {
        DeaddropServerStat {
            put_ok: self.put_ok,
            put_fail: self.put_fail,
            get_ok: self.get_ok,
            get_fail: self.get_fail,
            last_success_ms: (self.last_success_ts.max(0.0) * 1_000.0) as u64,
            latency_ema_ms: self.latency_ema_ms,
            latency_samples: self.latency_samples,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupMetadataFile {
    #[serde(default)]
    id: String,
    name: String,
    my_dest_b64: Option<String>,
    #[serde(default)]
    my_b32: Option<String>,
    #[serde(default)]
    my_name: String,
    #[serde(default)]
    history_enabled: bool,
    #[serde(default)]
    owner_b32: Option<String>,
    #[serde(default)]
    roster_version: u64,
    #[serde(default)]
    members: Vec<GroupMemberFile>,
    #[serde(default)]
    join_token: Option<String>,
    #[serde(default)]
    private_join_credential: Option<PrivateJoinCredential>,
    #[serde(default)]
    issued_invites: Vec<GroupInviteFile>,
    #[serde(default)]
    roster_signing_pubkey: Option<String>,
    #[serde(default)]
    roster_signing_secret: Option<String>,
    #[serde(default)]
    roster_signature: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupMemberFile {
    name: String,
    b32: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupInviteFile {
    token: String,
    #[serde(default)]
    redeemed_b32: Option<String>,
    #[serde(default)]
    private_binding: Option<PrivateInviteBinding>,
}

impl GroupMetadataFile {
    fn from_record(record: &GroupRecord) -> Self {
        Self {
            id: record.id.to_string(),
            name: record.display_name.clone(),
            my_dest_b64: record
                .identity
                .as_ref()
                .map(|identity| identity.destination_b64.expose_secret().to_owned()),
            my_b32: record
                .identity
                .as_ref()
                .map(|identity| identity.b32.clone()),
            my_name: record.local_member_name.clone(),
            history_enabled: record.history_enabled,
            owner_b32: record.owner_b32.clone(),
            roster_version: record.roster_version,
            members: record
                .members
                .iter()
                .map(|member| GroupMemberFile {
                    name: member.name.clone(),
                    b32: member.b32.clone(),
                })
                .collect(),
            join_token: record
                .join_token
                .as_ref()
                .map(|token| token.expose_secret().to_owned()),
            private_join_credential: record.private_join_credential.clone(),
            issued_invites: record
                .issued_invites
                .iter()
                .map(|invite| GroupInviteFile {
                    token: invite.token.expose_secret().to_owned(),
                    redeemed_b32: invite.redeemed_b32.clone(),
                    private_binding: invite.private_binding.clone(),
                })
                .collect(),
            roster_signing_pubkey: record.roster_signing_public_key.clone(),
            roster_signing_secret: record
                .roster_signing_secret
                .as_ref()
                .map(|secret| secret.expose_secret().to_owned()),
            roster_signature: record.roster_signature.clone(),
        }
    }

    fn into_record(self, id: GroupId) -> Result<GroupRecord, StorageError> {
        let record = GroupRecord {
            id,
            display_name: self.name,
            identity: optional_identity(self.my_dest_b64, self.my_b32)?,
            local_member_name: self.my_name,
            history_enabled: self.history_enabled,
            owner_b32: self.owner_b32,
            roster_version: self.roster_version.max(1),
            members: self
                .members
                .into_iter()
                .map(|member| GroupMemberRecord {
                    name: member.name,
                    b32: member.b32,
                })
                .collect(),
            join_token: self.join_token.map(SecretText::new).transpose()?,
            private_join_credential: self.private_join_credential,
            issued_invites: self
                .issued_invites
                .into_iter()
                .map(|invite| {
                    Ok(GroupIssuedInviteRecord {
                        token: SecretText::new(invite.token)?,
                        redeemed_b32: invite.redeemed_b32,
                        private_binding: invite.private_binding,
                    })
                })
                .collect::<Result<Vec<_>, StorageError>>()?,
            roster_signing_public_key: self.roster_signing_pubkey,
            roster_signing_secret: self
                .roster_signing_secret
                .map(SecretText::new)
                .transpose()?,
            roster_signature: self.roster_signature,
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("storage serialization failed: {0}")]
    Encode(String),
    #[error("storage decoding failed: {0}")]
    Decode(String),
    #[error("unsupported storage format: {0}")]
    UnsupportedFormat(String),
    #[error("unsupported storage schema version: {0}")]
    UnsupportedSchema(u32),
    #[error("storage validation failed: {0}")]
    Validation(String),
    #[error("storage metadata file exceeds {MAX_STORAGE_BYTES} bytes: {0}")]
    TooLarge(u64),
    #[error("stale storage revision: expected {expected}, current revision is {actual}")]
    RevisionConflict { expected: u64, actual: u64 },
    #[error("storage revision counter is exhausted")]
    RevisionExhausted,
}

fn validate_contact_name(value: &str) -> Result<(), StorageError> {
    validate_display_name("contact name", value, true)?;
    validate_contact_directory_name(value)
}

fn validate_contact_directory_name(value: &str) -> Result<(), StorageError> {
    if value.starts_with('.') || value.contains('/') || value.contains('\\') {
        return Err(StorageError::Validation(
            "contact name is not safe for filesystem storage".into(),
        ));
    }
    Ok(())
}

fn validate_display_name(
    label: &str,
    value: &str,
    reject_reserved: bool,
) -> Result<(), StorageError> {
    validate_bounded_text(label, value, MAX_DISPLAY_NAME_BYTES)?;
    if value != value.trim() {
        return Err(StorageError::Validation(format!(
            "{label} must not have leading or trailing whitespace"
        )));
    }
    if reject_reserved
        && (value.eq_ignore_ascii_case("default")
            || value.eq_ignore_ascii_case("global")
            || value.eq_ignore_ascii_case("__app__")
            || value
                .get(.."group:".len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("group:")))
    {
        return Err(StorageError::Validation(format!(
            "{label} uses a reserved name"
        )));
    }
    Ok(())
}

fn validate_bounded_text(label: &str, value: &str, max: usize) -> Result<(), StorageError> {
    if value.is_empty() {
        return Err(StorageError::Validation(format!(
            "{label} must not be empty"
        )));
    }
    if value.len() > max {
        return Err(StorageError::Validation(format!(
            "{label} exceeds {max} bytes"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(StorageError::Validation(format!(
            "{label} contains a control character"
        )));
    }
    Ok(())
}

fn validate_optional_text(label: &str, value: &Option<String>) -> Result<(), StorageError> {
    if let Some(value) = value {
        validate_bounded_text(label, value, MAX_SECRET_TEXT_BYTES)?;
    }
    Ok(())
}

fn normalize_b32(value: &str) -> Result<String, StorageError> {
    let normalized = value.trim().to_ascii_lowercase();
    validate_b32(&normalized)?;
    Ok(normalized)
}

fn require_normalized_b32(label: &str, value: &str) -> Result<(), StorageError> {
    validate_b32(value)?;
    if value != value.to_ascii_lowercase() || value != value.trim() {
        return Err(StorageError::Validation(format!(
            "{label} must be normalized lowercase"
        )));
    }
    Ok(())
}

fn validate_b32(value: &str) -> Result<(), StorageError> {
    let Some(identity) = value.strip_suffix(".b32.i2p") else {
        return Err(StorageError::Validation("invalid I2P b32 address".into()));
    };
    if identity.len() != 52
        || !identity
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(StorageError::Validation("invalid I2P b32 address".into()));
    }
    Ok(())
}

fn validate_deaddrops(
    servers: &[String],
    stats: &BTreeMap<String, DeaddropServerStat>,
) -> Result<(), StorageError> {
    if servers.len() > MAX_DEADDROP_SERVERS || stats.len() > MAX_DEADDROP_SERVERS {
        return Err(StorageError::Validation(
            "deaddrop server limit exceeded".into(),
        ));
    }
    let mut unique = BTreeSet::new();
    for server in servers {
        require_normalized_b32("deaddrop server b32", server)?;
        if !unique.insert(server) {
            return Err(StorageError::Validation("duplicate deaddrop server".into()));
        }
    }
    for (server, stat) in stats {
        require_normalized_b32("deaddrop statistics b32", server)?;
        stat.validate()?;
    }
    Ok(())
}

fn default_tunnel_length() -> u8 {
    DEFAULT_TUNNEL_LENGTH
}

fn default_tunnel_quantity() -> u8 {
    DEFAULT_TUNNEL_QUANTITY
}

fn optional_identity(
    destination: Option<String>,
    b32: Option<String>,
) -> Result<Option<PersistentIdentity>, StorageError> {
    match (destination, b32) {
        (None, None) => Ok(None),
        (Some(destination), Some(b32)) => PersistentIdentity::new(destination, b32).map(Some),
        _ => Err(StorageError::Validation(
            "persistent identity destination and b32 must be stored together".into(),
        )),
    }
}

fn optional_peer(
    b32: Option<String>,
    destination: Option<String>,
) -> Result<Option<TofuPeerPin>, StorageError> {
    match (b32, destination) {
        (None, None) => Ok(None),
        (Some(b32), Some(destination)) => TofuPeerPin::new(b32, destination).map(Some),
        _ => Err(StorageError::Validation(
            "TOFU peer destination and b32 must be stored together".into(),
        )),
    }
}

pub fn group_storage_key(id: &GroupId) -> String {
    let value = id.as_str();
    if !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        value.to_owned()
    } else {
        format!("group_{}", URL_SAFE_NO_PAD.encode(value.as_bytes()))
    }
}

fn offline_state_filename(peer_b32: &str) -> String {
    let peer = peer_b32
        .strip_suffix(".b32.i2p")
        .unwrap_or(peer_b32)
        .to_ascii_lowercase();
    format!("offline_{peer}.state")
}

fn required_value<'a>(
    values: &'a BTreeMap<&str, &str>,
    key: &str,
) -> Result<&'a str, StorageError> {
    values
        .get(key)
        .copied()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| StorageError::Decode(format!("offline state is missing {key}")))
}

fn parse_value<T>(values: &BTreeMap<&str, &str>, key: &str, default: T) -> Result<T, StorageError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    match values.get(key).copied().filter(|value| !value.is_empty()) {
        Some(value) => value
            .parse()
            .map_err(|error| StorageError::Decode(format!("invalid {key}: {error}"))),
        None => Ok(default),
    }
}

fn parse_optional<T>(values: &BTreeMap<&str, &str>, key: &str) -> Result<Option<T>, StorageError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    values
        .get(key)
        .copied()
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|error| StorageError::Decode(format!("invalid {key}: {error}")))
        })
        .transpose()
}

fn parse_csv<T>(values: &BTreeMap<&str, &str>, key: &str) -> Result<Vec<T>, StorageError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let Some(value) = values.get(key).copied().filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(|item| {
            item.parse().map_err(|error| {
                StorageError::Decode(format!("invalid {key} item {item:?}: {error}"))
            })
        })
        .collect()
}

fn parse_missing(
    values: &BTreeMap<&str, &str>,
) -> Result<Vec<OfflineMissingIndexSnapshot>, StorageError> {
    let Some(value) = values
        .get("missing_drop_recv")
        .copied()
        .filter(|value| !value.is_empty())
    else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(|item| {
            let parts = item.split(':').collect::<Vec<_>>();
            if parts.len() != 4 {
                return Err(StorageError::Decode("invalid missing offline index".into()));
            }
            Ok(OfflineMissingIndexSnapshot {
                index: parse_component(parts[0], "missing index")?,
                confirmed_miss_rounds: parse_component(parts[1], "miss rounds")?,
                first_miss_ms: parse_component(parts[2], "first miss time")?,
                last_miss_ms: parse_component(parts[3], "last miss time")?,
            })
        })
        .collect()
}

fn parse_skipped(
    values: &BTreeMap<&str, &str>,
) -> Result<Vec<OfflineSkippedIndexSnapshot>, StorageError> {
    let Some(value) = values
        .get("skipped_drop_recv")
        .copied()
        .filter(|value| !value.is_empty())
    else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(|item| {
            let parts = item.split(':').collect::<Vec<_>>();
            if parts.len() != 3 {
                return Err(StorageError::Decode("invalid skipped offline index".into()));
            }
            Ok(OfflineSkippedIndexSnapshot {
                index: parse_component(parts[0], "skipped index")?,
                skipped_at_ms: parse_component(parts[1], "skipped time")?,
                last_recovery_probe_ms: parse_component(parts[2], "recovery probe time")?,
            })
        })
        .collect()
}

fn parse_component<T>(value: &str, label: &str) -> Result<T, StorageError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    value
        .parse()
        .map_err(|error| StorageError::Decode(format!("invalid {label}: {error}")))
}

fn decode_secret_hex(value: &str) -> Result<[u8; 32], StorageError> {
    let bytes = hex::decode(value)
        .map_err(|error| StorageError::Decode(format!("invalid offline secret: {error}")))?;
    bytes
        .try_into()
        .map_err(|_| StorageError::Decode("offline secret must contain 32 bytes".into()))
}

fn join_csv<T: ToString>(values: &[T]) -> String {
    values
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

fn join_missing(values: &[OfflineMissingIndexSnapshot]) -> String {
    values
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}:{}",
                entry.index, entry.confirmed_miss_rounds, entry.first_miss_ms, entry.last_miss_ms
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn join_skipped(values: &[OfflineSkippedIndexSnapshot]) -> String {
    values
        .iter()
        .map(|entry| {
            format!(
                "{}:{}:{}",
                entry.index, entry.skipped_at_ms, entry.last_recovery_probe_ms
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, StorageError> {
    let mut file = File::open(path).map_err(|error| io_error(path, error))?;
    let metadata = file.metadata().map_err(|error| io_error(path, error))?;
    if metadata.len() > MAX_STORAGE_BYTES {
        return Err(StorageError::TooLarge(metadata.len()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(MAX_STORAGE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    if bytes.len() as u64 > MAX_STORAGE_BYTES {
        return Err(StorageError::TooLarge(bytes.len() as u64));
    }
    Ok(bytes)
}

pub(crate) fn create_secure_directory(path: &Path) -> Result<(), StorageError> {
    fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|error| io_error(path, error))?;
    Ok(())
}

pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
    if bytes.len() as u64 > MAX_STORAGE_BYTES {
        return Err(StorageError::TooLarge(bytes.len() as u64));
    }
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::Validation("storage file has no parent".into()))?;
    create_secure_directory(parent)?;
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| io_error(&temporary, error))?;
        set_file_mode(&file, &temporary)?;
        file.write_all(bytes)
            .map_err(|error| io_error(&temporary, error))?;
        file.sync_all()
            .map_err(|error| io_error(&temporary, error))?;
        drop(file);
        replace_storage_file(&temporary, path)?;
        sync_directory(parent.to_path_buf())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn replace_storage_file(temporary: &Path, target: &Path) -> Result<(), StorageError> {
    fs::rename(temporary, target).map_err(|error| io_error(target, error))
}

#[cfg(not(unix))]
fn replace_storage_file(temporary: &Path, target: &Path) -> Result<(), StorageError> {
    let backup = target.with_extension("previous");
    if backup.exists() {
        fs::remove_file(&backup).map_err(|error| io_error(&backup, error))?;
    }
    if target.exists() {
        fs::rename(target, &backup).map_err(|error| io_error(target, error))?;
    }
    match fs::rename(temporary, target) {
        Ok(()) => {
            let _ = fs::remove_file(backup);
            Ok(())
        }
        Err(error) => {
            if backup.exists() {
                let _ = fs::rename(&backup, target);
            }
            Err(io_error(target, error))
        }
    }
}

pub(crate) fn set_file_mode(file: &File, path: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(FILE_MODE))
        .map_err(|error| io_error(path, error))?;
    #[cfg(not(unix))]
    let _ = (file, path);
    Ok(())
}

fn sync_directory(path: PathBuf) -> Result<(), StorageError> {
    #[cfg(unix)]
    File::open(&path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(&path, error))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> StorageError {
    StorageError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;

    #[test]
    fn legacy_global_settings_receive_safe_defaults() {
        let settings: GlobalSettings =
            serde_json::from_str(r#"{"sam_host":"127.0.0.1","sam_port":7656}"#)
                .expect("legacy settings");

        assert_eq!(settings.default_tunnels, TunnelSettings::default());
        assert!(!settings.sam_liveness_enabled);
        assert_eq!(settings.sam_failure_action, SamFailureAction::WarningOnly);
        settings.validate().expect("valid settings");
    }
}
