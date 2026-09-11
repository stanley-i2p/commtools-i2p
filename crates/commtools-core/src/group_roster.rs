use crate::ids::GroupId;
use crate::private_group_invite::{
    PrivateGroupInviteError, PrivateJoinCredential, PrivateJoinProof, seal_invite, sign_join_proof,
    verify_join_proof,
};
use crate::storage::{
    GroupIssuedInviteRecord, GroupMemberRecord, GroupRecord, SecretText, StorageError,
};
use base64::{Engine as _, engine::general_purpose};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use thiserror::Error;

pub const PUBLIC_INVITE_PREFIX: &str = "COMMTOOLS-I2P-GROUP-INVITE-v1:";
pub const INVITE_FORMAT: &str = "commtools-i2p-group-invite";
pub const ROSTER_FORMAT: &str = "commtools-i2p-group-roster";
pub const ROSTER_SIGNATURE_FORMAT: &str = "commtools-i2p-group-roster-signature";
pub const DISSOLUTION_FORMAT: &str = "commtools-i2p-group-dissolution";
pub const DISSOLUTION_SIGNATURE_FORMAT: &str = "commtools-i2p-group-dissolution-signature";
pub const GROUP_WIRE_VERSION: u32 = 1;
pub const JOIN_PROOF_CONTROL: &str = "join_proof";
pub const RENAME_REQUEST_CONTROL: &str = "rename_request";
pub const LEAVE_REQUEST_CONTROL: &str = "leave_request";
pub const MAX_PUBLIC_INVITE_BYTES: usize = 512 * 1_024;
pub const MAX_GROUP_DISPLAY_NAME_CHARS: usize = 32;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupInvite {
    pub format: String,
    pub version: u32,
    pub group_name: String,
    pub inviter_name: String,
    pub inviter_b32: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_b32: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
    pub roster_version: u64,
    #[serde(default)]
    pub members: Vec<GroupMemberRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_signing_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roster_signature: Option<String>,
}

impl std::fmt::Debug for GroupInvite {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GroupInvite")
            .field("format", &self.format)
            .field("version", &self.version)
            .field("group_name", &self.group_name)
            .field("inviter_name", &self.inviter_name)
            .field("inviter_b32", &self.inviter_b32)
            .field("owner_b32", &self.owner_b32)
            .field(
                "invite_token",
                &self.invite_token.as_ref().map(|_| "<redacted>"),
            )
            .field("roster_version", &self.roster_version)
            .field("members", &self.members)
            .field("roster_signing_pubkey", &self.roster_signing_pubkey)
            .field("roster_signature", &self.roster_signature)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupRosterSync {
    pub format: String,
    pub version: u32,
    pub group_name: String,
    pub owner_b32: String,
    pub roster_version: u64,
    pub members: Vec<GroupMemberRecord>,
    pub roster_signing_pubkey: String,
    pub roster_signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupDissolution {
    pub format: String,
    pub version: u32,
    pub group_name: String,
    pub owner_b32: String,
    pub roster_version: u64,
    pub roster_signing_pubkey: String,
    pub signature: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GroupControlMessage {
    pub kind: String,
    pub token: String,
    pub b32: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_proof_nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_proof_signature: Option<String>,
}

impl std::fmt::Debug for GroupControlMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GroupControlMessage")
            .field("kind", &self.kind)
            .field("token", &"<redacted>")
            .field("b32", &self.b32)
            .field("name", &self.name)
            .field("private_request_id", &self.private_request_id)
            .field(
                "private_proof_nonce",
                &self.private_proof_nonce.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "private_proof_signature",
                &self.private_proof_signature.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RosterApplyOutcome {
    Applied,
    Unchanged,
    LocalMemberRemoved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteRedemption {
    NewlyRedeemed,
    AlreadyRedeemedByMember,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteApplyOutcome {
    CreatedOrUpdated,
    MergedWithoutNewerRoster,
}

#[derive(Debug, Serialize)]
struct GroupRosterSignaturePayload<'a> {
    format: &'static str,
    version: u32,
    group_name: &'a str,
    owner_b32: &'a str,
    roster_version: u64,
    members: &'a [GroupMemberRecord],
}

#[derive(Debug, Serialize)]
struct GroupDissolutionSignaturePayload<'a> {
    format: &'static str,
    version: u32,
    group_name: &'a str,
    owner_b32: &'a str,
    roster_version: u64,
}

pub fn is_group_owner(group: &GroupRecord) -> bool {
    match (
        group
            .identity
            .as_ref()
            .map(|identity| identity.b32.as_str()),
        group.owner_b32.as_deref(),
    ) {
        (Some(local), Some(owner)) => local.eq_ignore_ascii_case(owner),
        _ => false,
    }
}

pub fn canonical_members(group: &GroupRecord) -> Result<Vec<GroupMemberRecord>, GroupRosterError> {
    let owner = group
        .owner_b32
        .as_deref()
        .ok_or(GroupRosterError::MissingOwner)?;
    let mut members = group.members.clone();
    if is_group_owner(group)
        && !members
            .iter()
            .any(|member| member.b32.eq_ignore_ascii_case(owner))
    {
        members.push(GroupMemberRecord {
            name: local_member_name(group, owner),
            b32: normalize_b32(owner)?,
        });
    }
    normalize_and_sort_members(members)
}

pub fn sign_owner_roster(group: &mut GroupRecord) -> Result<(), GroupRosterError> {
    ensure_owner(group)?;
    if group.roster_signing_secret.is_none() || group.roster_signing_public_key.is_none() {
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        let key = SigningKey::from_bytes(&secret);
        group.roster_signing_secret =
            Some(SecretText::new(general_purpose::STANDARD.encode(secret))?);
        group.roster_signing_public_key =
            Some(general_purpose::STANDARD.encode(key.verifying_key().to_bytes()));
    }

    let secret = group
        .roster_signing_secret
        .as_ref()
        .ok_or(GroupRosterError::MissingSigningSecret)?;
    let secret = decode_array::<32>(secret.expose_secret(), "roster signing secret")?;
    let signing_key = SigningKey::from_bytes(&secret);
    group.roster_signing_public_key =
        Some(general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes()));
    let payload = roster_signature_payload(group)?;
    group.roster_signature =
        Some(general_purpose::STANDARD.encode(signing_key.sign(&payload).to_bytes()));
    Ok(())
}

pub fn verify_roster_sync(sync: &GroupRosterSync) -> Result<(), GroupRosterError> {
    validate_wire_header(&sync.format, sync.version, ROSTER_FORMAT)?;
    validate_display_name(&sync.group_name)?;
    let owner = normalize_b32(&sync.owner_b32)?;
    if sync.roster_version == 0 {
        return Err(GroupRosterError::InvalidRosterVersion);
    }
    let members = normalize_and_sort_members(sync.members.clone())?;
    if !members
        .iter()
        .any(|member| member.b32.eq_ignore_ascii_case(&owner))
    {
        return Err(GroupRosterError::OwnerMissingFromRoster);
    }
    verify_signature(
        &sync.group_name,
        &owner,
        sync.roster_version,
        &members,
        &sync.roster_signing_pubkey,
        &sync.roster_signature,
    )
}

pub fn roster_sync(group: &GroupRecord) -> Result<GroupRosterSync, GroupRosterError> {
    let owner = group
        .owner_b32
        .as_deref()
        .ok_or(GroupRosterError::MissingOwner)?;
    let public_key = group
        .roster_signing_public_key
        .clone()
        .ok_or(GroupRosterError::MissingSigningPublicKey)?;
    let signature = group
        .roster_signature
        .clone()
        .ok_or(GroupRosterError::MissingRosterSignature)?;
    let sync = GroupRosterSync {
        format: ROSTER_FORMAT.into(),
        version: GROUP_WIRE_VERSION,
        group_name: group.display_name.clone(),
        owner_b32: normalize_b32(owner)?,
        roster_version: group.roster_version,
        members: canonical_members(group)?,
        roster_signing_pubkey: public_key,
        roster_signature: signature,
    };
    verify_roster_sync(&sync)?;
    Ok(sync)
}

pub fn issue_group_dissolution(
    group: &mut GroupRecord,
) -> Result<GroupDissolution, GroupRosterError> {
    ensure_owner(group)?;
    group.roster_version = group
        .roster_version
        .checked_add(1)
        .ok_or(GroupRosterError::InvalidRosterVersion)?;
    sign_owner_roster(group)?;
    let owner = normalize_b32(
        group
            .owner_b32
            .as_deref()
            .ok_or(GroupRosterError::MissingOwner)?,
    )?;
    let public_key = group
        .roster_signing_public_key
        .clone()
        .ok_or(GroupRosterError::MissingSigningPublicKey)?;
    let secret = group
        .roster_signing_secret
        .as_ref()
        .ok_or(GroupRosterError::MissingSigningSecret)?;
    let secret = decode_array::<32>(secret.expose_secret(), "roster signing secret")?;
    let signing_key = SigningKey::from_bytes(&secret);
    let mut dissolution = GroupDissolution {
        format: DISSOLUTION_FORMAT.into(),
        version: GROUP_WIRE_VERSION,
        group_name: group.display_name.clone(),
        owner_b32: owner,
        roster_version: group.roster_version,
        roster_signing_pubkey: public_key,
        signature: String::new(),
    };
    let payload = dissolution_signature_payload(&dissolution)?;
    dissolution.signature = general_purpose::STANDARD.encode(signing_key.sign(&payload).to_bytes());
    Ok(dissolution)
}

pub fn verify_group_dissolution(
    group: &GroupRecord,
    dissolution: &GroupDissolution,
) -> Result<(), GroupRosterError> {
    validate_wire_header(&dissolution.format, dissolution.version, DISSOLUTION_FORMAT)?;
    validate_display_name(&dissolution.group_name)?;
    let owner = normalize_b32(&dissolution.owner_b32)?;
    let stored_owner = group
        .owner_b32
        .as_deref()
        .ok_or(GroupRosterError::MissingOwner)?;
    if !stored_owner.eq_ignore_ascii_case(&owner) {
        return Err(GroupRosterError::OwnerMismatch);
    }
    if dissolution.group_name != group.display_name {
        return Err(GroupRosterError::GroupMismatch);
    }
    let pinned_key = group
        .roster_signing_public_key
        .as_deref()
        .ok_or(GroupRosterError::MissingSigningPublicKey)?;
    if pinned_key != dissolution.roster_signing_pubkey {
        return Err(GroupRosterError::SigningKeyMismatch);
    }
    if dissolution.roster_version <= group.roster_version {
        return Err(GroupRosterError::InvalidRosterVersion);
    }
    let payload = dissolution_signature_payload(dissolution)?;
    verify_raw_signature(
        &dissolution.roster_signing_pubkey,
        &dissolution.signature,
        &payload,
    )
}

pub fn apply_roster_sync(
    group: &mut GroupRecord,
    sync: GroupRosterSync,
) -> Result<RosterApplyOutcome, GroupRosterError> {
    verify_roster_sync(&sync)?;
    let stored_owner = group
        .owner_b32
        .as_deref()
        .ok_or(GroupRosterError::MissingOwner)?;
    if !stored_owner.eq_ignore_ascii_case(&sync.owner_b32) {
        return Err(GroupRosterError::OwnerMismatch);
    }
    if let Some(pinned_key) = group.roster_signing_public_key.as_deref() {
        if pinned_key != sync.roster_signing_pubkey {
            return Err(GroupRosterError::SigningKeyMismatch);
        }
    }
    if sync.roster_version <= group.roster_version {
        return Ok(RosterApplyOutcome::Unchanged);
    }

    let local_b32 = group.identity.as_ref().map(|identity| identity.b32.clone());
    let local_removed = local_b32.as_ref().is_some_and(|local| {
        !local.eq_ignore_ascii_case(&sync.owner_b32)
            && !sync
                .members
                .iter()
                .any(|member| member.b32.eq_ignore_ascii_case(local))
    });
    let local_is_admitted = local_b32.as_ref().is_some_and(|local| {
        local.eq_ignore_ascii_case(&sync.owner_b32)
            || sync
                .members
                .iter()
                .any(|member| member.b32.eq_ignore_ascii_case(local))
    });
    group.roster_version = sync.roster_version;
    group.roster_signing_public_key = Some(sync.roster_signing_pubkey);
    group.roster_signature = Some(sync.roster_signature);
    group.members = sync
        .members
        .into_iter()
        .filter(|member| {
            !local_b32
                .as_ref()
                .is_some_and(|local| local.eq_ignore_ascii_case(&member.b32))
        })
        .collect();

    if local_removed {
        group.members.clear();
        group.join_token = None;
        group.private_join_credential = None;
        return Ok(RosterApplyOutcome::LocalMemberRemoved);
    }
    if group.join_token.is_some() && local_is_admitted {
        group.join_token = None;
        group.private_join_credential = None;
    }
    Ok(RosterApplyOutcome::Applied)
}

pub fn issue_public_invite(group: &mut GroupRecord) -> Result<String, GroupRosterError> {
    ensure_owner(group)?;
    sign_owner_roster(group)?;
    let token = random_token();
    group.issued_invites.push(GroupIssuedInviteRecord {
        token: SecretText::new(token.clone())?,
        redeemed_b32: None,
        private_binding: None,
    });
    encode_public_invite(&invite_from_group(group, Some(token))?)
}

pub fn issue_private_invite(
    group: &mut GroupRecord,
    encoded_request: &str,
    now_ms: u64,
) -> Result<String, GroupRosterError> {
    ensure_owner(group)?;
    sign_owner_roster(group)?;
    group.issued_invites.retain(|invite| {
        invite
            .private_binding
            .as_ref()
            .is_none_or(|binding| binding.expires_ms() > now_ms)
    });
    let token = random_token();
    let invite = invite_from_group(group, Some(token.clone()))?;
    let invite_json = serde_json::to_vec(&invite)?;
    let (binding, encoded_invite) = seal_invite(encoded_request, &invite_json, now_ms)?;
    if group.issued_invites.iter().any(|invite| {
        invite
            .private_binding
            .as_ref()
            .is_some_and(|existing| existing.request_id() == binding.request_id())
    }) {
        return Err(GroupRosterError::PrivateRequestAlreadyAnswered);
    }
    group.issued_invites.push(GroupIssuedInviteRecord {
        token: SecretText::new(token)?,
        redeemed_b32: None,
        private_binding: Some(binding),
    });
    Ok(encoded_invite)
}

pub fn apply_invite(
    group: &mut GroupRecord,
    invite: GroupInvite,
    private_credential: Option<PrivateJoinCredential>,
) -> Result<InviteApplyOutcome, GroupRosterError> {
    validate_invite(&invite)?;
    if invite.roster_signing_pubkey.is_none() || invite.roster_signature.is_none() {
        return Err(GroupRosterError::UnsignedInvite);
    }
    let was_uninitialized = group.owner_b32.is_none();
    let owner = normalize_b32(invite.owner_b32.as_deref().unwrap_or(&invite.inviter_b32))?;
    if let Some(stored_owner) = group.owner_b32.as_deref()
        && !stored_owner.eq_ignore_ascii_case(&owner)
    {
        return Err(GroupRosterError::OwnerMismatch);
    }
    if let (Some(stored_key), Some(incoming_key)) = (
        group.roster_signing_public_key.as_deref(),
        invite.roster_signing_pubkey.as_deref(),
    ) && stored_key != incoming_key
    {
        return Err(GroupRosterError::SigningKeyMismatch);
    }
    if group.roster_signing_public_key.is_some() && invite.roster_signing_pubkey.is_none() {
        return Err(GroupRosterError::UnsignedInviteAfterKeyPin);
    }

    let mut incoming_members = invite.members.clone();
    if !incoming_members
        .iter()
        .any(|member| member.b32.eq_ignore_ascii_case(&invite.inviter_b32))
    {
        incoming_members.push(GroupMemberRecord {
            name: invite.inviter_name.clone(),
            b32: normalize_b32(&invite.inviter_b32)?,
        });
    }
    incoming_members = normalize_and_sort_members(incoming_members)?;
    let local_b32 = group.identity.as_ref().map(|identity| identity.b32.clone());
    let newer = invite.roster_version > group.roster_version;

    group.id = GroupId::new(&owner)?;
    group.display_name = invite.group_name;
    group.owner_b32 = Some(owner);
    if let Some(public_key) = invite.roster_signing_pubkey {
        group.roster_signing_public_key = Some(public_key);
    }
    if let Some(signature) = invite.roster_signature {
        group.roster_signature = Some(signature);
    }
    if newer {
        group.members = incoming_members
            .into_iter()
            .filter(|member| {
                !local_b32
                    .as_ref()
                    .is_some_and(|local| local.eq_ignore_ascii_case(&member.b32))
            })
            .collect();
        group.roster_version = invite.roster_version;
    } else {
        for member in incoming_members {
            if local_b32
                .as_ref()
                .is_some_and(|local| local.eq_ignore_ascii_case(&member.b32))
            {
                continue;
            }
            let _ = merge_member(&mut group.members, member);
        }
        group.roster_version = group.roster_version.max(invite.roster_version);
    }
    if let Some(token) = invite.invite_token {
        group.join_token = Some(SecretText::new(token)?);
        group.private_join_credential = private_credential;
    }
    Ok(if was_uninitialized || newer {
        InviteApplyOutcome::CreatedOrUpdated
    } else {
        InviteApplyOutcome::MergedWithoutNewerRoster
    })
}

pub fn invite_from_group(
    group: &GroupRecord,
    token: Option<String>,
) -> Result<GroupInvite, GroupRosterError> {
    let identity = group
        .identity
        .as_ref()
        .ok_or(GroupRosterError::MissingIdentity)?;
    Ok(GroupInvite {
        format: INVITE_FORMAT.into(),
        version: GROUP_WIRE_VERSION,
        group_name: group.display_name.clone(),
        inviter_name: local_member_name(group, &identity.b32),
        inviter_b32: identity.b32.clone(),
        owner_b32: group
            .owner_b32
            .clone()
            .or_else(|| Some(identity.b32.clone())),
        invite_token: token,
        roster_version: group.roster_version,
        members: group.members.clone(),
        roster_signing_pubkey: group.roster_signing_public_key.clone(),
        roster_signature: group.roster_signature.clone(),
    })
}

pub fn encode_public_invite(invite: &GroupInvite) -> Result<String, GroupRosterError> {
    validate_invite(invite)?;
    let json = serde_json::to_vec(invite)?;
    if json.len() > MAX_PUBLIC_INVITE_BYTES {
        return Err(GroupRosterError::InviteTooLarge);
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&json)?;
    let compressed = encoder.finish()?;
    let encoded = general_purpose::URL_SAFE_NO_PAD.encode(compressed);
    if encoded.len() > MAX_PUBLIC_INVITE_BYTES {
        return Err(GroupRosterError::InviteTooLarge);
    }
    Ok(format!("{PUBLIC_INVITE_PREFIX}{encoded}"))
}

pub fn decode_public_invite(value: &str) -> Result<GroupInvite, GroupRosterError> {
    let encoded = value
        .trim()
        .strip_prefix(PUBLIC_INVITE_PREFIX)
        .ok_or(GroupRosterError::WrongInvitePrefix)?;
    if encoded.len() > MAX_PUBLIC_INVITE_BYTES {
        return Err(GroupRosterError::InviteTooLarge);
    }
    let compressed = general_purpose::URL_SAFE_NO_PAD.decode(encoded.as_bytes())?;
    let mut decoder = GzDecoder::new(compressed.as_slice());
    let mut json = Vec::new();
    std::io::Read::by_ref(&mut decoder)
        .take((MAX_PUBLIC_INVITE_BYTES + 1) as u64)
        .read_to_end(&mut json)?;
    if json.len() > MAX_PUBLIC_INVITE_BYTES {
        return Err(GroupRosterError::InviteTooLarge);
    }
    let invite: GroupInvite = serde_json::from_slice(&json)?;
    validate_invite(&invite)?;
    Ok(invite)
}

pub fn validate_invite(invite: &GroupInvite) -> Result<(), GroupRosterError> {
    validate_wire_header(&invite.format, invite.version, INVITE_FORMAT)?;
    validate_display_name(&invite.group_name)?;
    validate_display_name(&invite.inviter_name)?;
    let owner = normalize_b32(invite.owner_b32.as_deref().unwrap_or(&invite.inviter_b32))?;
    let inviter = normalize_b32(&invite.inviter_b32)?;
    let mut members = invite.members.clone();
    if !members
        .iter()
        .any(|member| member.b32.eq_ignore_ascii_case(&inviter))
    {
        members.push(GroupMemberRecord {
            name: invite.inviter_name.clone(),
            b32: inviter,
        });
    }
    let members = normalize_and_sort_members(members)?;
    if let (Some(public_key), Some(signature)) = (
        invite.roster_signing_pubkey.as_deref(),
        invite.roster_signature.as_deref(),
    ) {
        if !members
            .iter()
            .any(|member| member.b32.eq_ignore_ascii_case(&owner))
        {
            return Err(GroupRosterError::OwnerMissingFromRoster);
        }
        verify_signature(
            &invite.group_name,
            &owner,
            invite.roster_version,
            &members,
            public_key,
            signature,
        )?;
    } else if invite.roster_signing_pubkey.is_some() || invite.roster_signature.is_some() {
        return Err(GroupRosterError::IncompleteRosterSignature);
    }
    Ok(())
}

pub fn join_control(
    group: &GroupRecord,
    now_ms: u64,
) -> Result<Option<GroupControlMessage>, GroupRosterError> {
    let Some(token) = group.join_token.as_ref() else {
        return Ok(None);
    };
    let identity = group
        .identity
        .as_ref()
        .ok_or(GroupRosterError::MissingIdentity)?;
    let owner = group
        .owner_b32
        .as_deref()
        .ok_or(GroupRosterError::MissingOwner)?;
    let proof = group
        .private_join_credential
        .as_ref()
        .map(|credential| {
            sign_join_proof(
                credential,
                owner,
                token.expose_secret(),
                &identity.b32,
                now_ms,
            )
        })
        .transpose()?;
    Ok(Some(GroupControlMessage {
        kind: JOIN_PROOF_CONTROL.into(),
        token: token.expose_secret().to_string(),
        b32: identity.b32.clone(),
        name: local_member_name(group, &identity.b32),
        private_request_id: proof.as_ref().map(|proof| proof.request_id.clone()),
        private_proof_nonce: proof.as_ref().map(|proof| proof.nonce.clone()),
        private_proof_signature: proof.map(|proof| proof.signature),
    }))
}

pub fn owner_control(
    group: &GroupRecord,
    now_ms: u64,
) -> Result<Option<GroupControlMessage>, GroupRosterError> {
    if let Some(control) = join_control(group, now_ms)? {
        return Ok(Some(control));
    }
    if is_group_owner(group) || group.local_member_name.trim().is_empty() {
        return Ok(None);
    }
    let identity = group
        .identity
        .as_ref()
        .ok_or(GroupRosterError::MissingIdentity)?;
    Ok(Some(GroupControlMessage {
        kind: RENAME_REQUEST_CONTROL.into(),
        token: String::new(),
        b32: identity.b32.clone(),
        name: local_member_name(group, &identity.b32),
        private_request_id: None,
        private_proof_nonce: None,
        private_proof_signature: None,
    }))
}

pub fn leave_control(group: &GroupRecord) -> Result<GroupControlMessage, GroupRosterError> {
    if is_group_owner(group) {
        return Err(GroupRosterError::OwnerCannotLeave);
    }
    let identity = group
        .identity
        .as_ref()
        .ok_or(GroupRosterError::MissingIdentity)?;
    Ok(GroupControlMessage {
        kind: LEAVE_REQUEST_CONTROL.into(),
        token: String::new(),
        b32: identity.b32.clone(),
        name: local_member_name(group, &identity.b32),
        private_request_id: None,
        private_proof_nonce: None,
        private_proof_signature: None,
    })
}

pub fn redeem_join_control(
    group: &mut GroupRecord,
    control: &GroupControlMessage,
    now_ms: u64,
) -> Result<InviteRedemption, GroupRosterError> {
    ensure_owner(group)?;
    if control.kind != JOIN_PROOF_CONTROL {
        return Err(GroupRosterError::UnsupportedControl(control.kind.clone()));
    }
    validate_display_name(&control.name)?;
    let member_b32 = normalize_b32(&control.b32)?;
    let invite_index = group
        .issued_invites
        .iter()
        .position(|invite| invite.token.expose_secret() == control.token)
        .ok_or(GroupRosterError::UnknownInviteToken)?;
    let private_binding = group.issued_invites[invite_index].private_binding.clone();

    let mut token_changed = false;
    let mut already_redeemed_by_member = false;
    if let Some(binding) = private_binding {
        let proof = PrivateJoinProof {
            request_id: control
                .private_request_id
                .clone()
                .ok_or(GroupRosterError::IncompletePrivateProof)?,
            nonce: control
                .private_proof_nonce
                .clone()
                .ok_or(GroupRosterError::IncompletePrivateProof)?,
            signature: control
                .private_proof_signature
                .clone()
                .ok_or(GroupRosterError::IncompletePrivateProof)?,
        };
        let owner = group
            .owner_b32
            .as_deref()
            .ok_or(GroupRosterError::MissingOwner)?;
        verify_join_proof(&binding, owner, &control.token, &member_b32, &proof, now_ms)?;
        group.issued_invites.remove(invite_index);
        token_changed = true;
    } else {
        match group.issued_invites[invite_index].redeemed_b32.as_deref() {
            Some(existing) if !existing.eq_ignore_ascii_case(&member_b32) => {
                return Err(GroupRosterError::InviteAlreadyRedeemed);
            }
            Some(_) => already_redeemed_by_member = true,
            None => {
                group.issued_invites[invite_index].redeemed_b32 = Some(member_b32.clone());
                token_changed = true;
            }
        }
    }

    let member_changed = merge_member(
        &mut group.members,
        GroupMemberRecord {
            name: control.name.clone(),
            b32: member_b32,
        },
    );
    if already_redeemed_by_member && !member_changed {
        return Ok(InviteRedemption::AlreadyRedeemedByMember);
    }
    debug_assert!(token_changed || member_changed);
    group.roster_version = group.roster_version.saturating_add(1);
    sign_owner_roster(group)?;
    Ok(InviteRedemption::NewlyRedeemed)
}

pub fn rename_member(
    group: &mut GroupRecord,
    member_b32: &str,
    new_name: &str,
) -> Result<bool, GroupRosterError> {
    ensure_owner(group)?;
    validate_display_name(new_name)?;
    let member_b32 = normalize_b32(member_b32)?;
    let member = group
        .members
        .iter_mut()
        .find(|member| member.b32 == member_b32)
        .ok_or(GroupRosterError::UnknownMember)?;
    if member.name == new_name {
        return Ok(false);
    }
    member.name = new_name.to_string();
    group.roster_version = group.roster_version.saturating_add(1);
    sign_owner_roster(group)?;
    Ok(true)
}

pub fn rename_local_member(
    group: &mut GroupRecord,
    new_name: &str,
) -> Result<bool, GroupRosterError> {
    let new_name = new_name.trim();
    validate_display_name(new_name)?;
    if group.local_member_name == new_name {
        return Ok(false);
    }
    group.local_member_name = new_name.to_string();
    if is_group_owner(group) {
        group.roster_version = group.roster_version.saturating_add(1);
        sign_owner_roster(group)?;
    }
    Ok(true)
}

pub fn remove_member(group: &mut GroupRecord, member_b32: &str) -> Result<bool, GroupRosterError> {
    ensure_owner(group)?;
    let member_b32 = normalize_b32(member_b32)?;
    if group
        .owner_b32
        .as_ref()
        .is_some_and(|owner| owner == &member_b32)
    {
        return Err(GroupRosterError::CannotRemoveOwner);
    }
    let old_len = group.members.len();
    group.members.retain(|member| member.b32 != member_b32);
    if old_len == group.members.len() {
        return Ok(false);
    }
    group.roster_version = group.roster_version.saturating_add(1);
    sign_owner_roster(group)?;
    Ok(true)
}

fn ensure_owner(group: &GroupRecord) -> Result<(), GroupRosterError> {
    if !is_group_owner(group) {
        return Err(GroupRosterError::OwnerOnly);
    }
    Ok(())
}

fn roster_signature_payload(group: &GroupRecord) -> Result<Vec<u8>, GroupRosterError> {
    let owner = group
        .owner_b32
        .as_deref()
        .ok_or(GroupRosterError::MissingOwner)?;
    let members = canonical_members(group)?;
    signature_payload(&group.display_name, owner, group.roster_version, &members)
}

fn signature_payload(
    group_name: &str,
    owner_b32: &str,
    roster_version: u64,
    members: &[GroupMemberRecord],
) -> Result<Vec<u8>, GroupRosterError> {
    Ok(serde_json::to_vec(&GroupRosterSignaturePayload {
        format: ROSTER_SIGNATURE_FORMAT,
        version: GROUP_WIRE_VERSION,
        group_name,
        owner_b32,
        roster_version,
        members,
    })?)
}

fn dissolution_signature_payload(
    dissolution: &GroupDissolution,
) -> Result<Vec<u8>, GroupRosterError> {
    Ok(serde_json::to_vec(&GroupDissolutionSignaturePayload {
        format: DISSOLUTION_SIGNATURE_FORMAT,
        version: GROUP_WIRE_VERSION,
        group_name: &dissolution.group_name,
        owner_b32: &dissolution.owner_b32,
        roster_version: dissolution.roster_version,
    })?)
}

fn verify_signature(
    group_name: &str,
    owner_b32: &str,
    roster_version: u64,
    members: &[GroupMemberRecord],
    public_key: &str,
    signature: &str,
) -> Result<(), GroupRosterError> {
    let payload = signature_payload(group_name, owner_b32, roster_version, members)?;
    verify_raw_signature(public_key, signature, &payload)
}

fn verify_raw_signature(
    public_key: &str,
    signature: &str,
    payload: &[u8],
) -> Result<(), GroupRosterError> {
    let public_key = decode_array::<32>(public_key, "roster signing public key")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|_| GroupRosterError::InvalidSigningPublicKey)?;
    let signature = Signature::from_bytes(&decode_array::<64>(signature, "roster signature")?);
    verifying_key
        .verify(payload, &signature)
        .map_err(|_| GroupRosterError::InvalidRosterSignature)
}

fn normalize_and_sort_members(
    members: Vec<GroupMemberRecord>,
) -> Result<Vec<GroupMemberRecord>, GroupRosterError> {
    let mut normalized = Vec::with_capacity(members.len());
    let mut addresses = BTreeSet::new();
    for member in members {
        validate_display_name(&member.name)?;
        let b32 = normalize_b32(&member.b32)?;
        if !addresses.insert(b32.clone()) {
            return Err(GroupRosterError::DuplicateMember(b32));
        }
        normalized.push(GroupMemberRecord {
            name: member.name,
            b32,
        });
    }
    normalized.sort_by(|left, right| {
        left.b32
            .cmp(&right.b32)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
    });
    Ok(normalized)
}

fn merge_member(members: &mut Vec<GroupMemberRecord>, incoming: GroupMemberRecord) -> bool {
    if let Some(member) = members
        .iter_mut()
        .find(|member| member.b32.eq_ignore_ascii_case(&incoming.b32))
    {
        if member.name == incoming.name {
            false
        } else {
            member.name = incoming.name;
            true
        }
    } else {
        members.push(incoming);
        true
    }
}

fn local_member_name(group: &GroupRecord, local_b32: &str) -> String {
    let name = group.local_member_name.trim();
    if !name.is_empty() {
        return name.to_string();
    }
    let short = local_b32.split('.').next().unwrap_or(local_b32);
    format!("member-{}", &short[..short.len().min(6)])
}

fn validate_display_name(value: &str) -> Result<(), GroupRosterError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_GROUP_DISPLAY_NAME_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(GroupRosterError::InvalidDisplayName);
    }
    Ok(())
}

fn validate_wire_header(
    actual_format: &str,
    actual_version: u32,
    expected_format: &'static str,
) -> Result<(), GroupRosterError> {
    if actual_format != expected_format || actual_version != GROUP_WIRE_VERSION {
        return Err(GroupRosterError::UnsupportedWireFormat);
    }
    Ok(())
}

fn normalize_b32(value: &str) -> Result<String, GroupRosterError> {
    let normalized = value.trim().to_ascii_lowercase();
    let label = normalized
        .strip_suffix(".b32.i2p")
        .ok_or(GroupRosterError::InvalidB32)?;
    if label.len() != 52
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    {
        return Err(GroupRosterError::InvalidB32);
    }
    Ok(format!("{label}.b32.i2p"))
}

fn random_token() -> String {
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    general_purpose::URL_SAFE_NO_PAD.encode(token)
}

fn decode_array<const N: usize>(
    encoded: &str,
    label: &'static str,
) -> Result<[u8; N], GroupRosterError> {
    general_purpose::STANDARD
        .decode(encoded.as_bytes())?
        .try_into()
        .map_err(|_| GroupRosterError::InvalidEncodedLength(label))
}

#[derive(Debug, Error)]
pub enum GroupRosterError {
    #[error("only the group owner may perform this operation")]
    OwnerOnly,
    #[error("group identity is missing")]
    MissingIdentity,
    #[error("group owner address is missing")]
    MissingOwner,
    #[error("group owner does not match the stored owner")]
    OwnerMismatch,
    #[error("group dissolution does not match the stored group")]
    GroupMismatch,
    #[error("group roster does not contain its owner")]
    OwnerMissingFromRoster,
    #[error("group roster version must be nonzero")]
    InvalidRosterVersion,
    #[error("group display name is invalid")]
    InvalidDisplayName,
    #[error("group b32 address is invalid")]
    InvalidB32,
    #[error("group roster contains duplicate member {0}")]
    DuplicateMember(String),
    #[error("group member is unknown")]
    UnknownMember,
    #[error("the group owner cannot be removed from its roster")]
    CannotRemoveOwner,
    #[error("the group owner cannot leave its own group")]
    OwnerCannotLeave,
    #[error("group roster signing secret is missing")]
    MissingSigningSecret,
    #[error("group roster signing public key is missing")]
    MissingSigningPublicKey,
    #[error("group roster signature is missing")]
    MissingRosterSignature,
    #[error("group roster signature fields are incomplete")]
    IncompleteRosterSignature,
    #[error("group roster signing key does not match the pinned key")]
    SigningKeyMismatch,
    #[error("group roster signing public key is invalid")]
    InvalidSigningPublicKey,
    #[error("group roster signature is invalid")]
    InvalidRosterSignature,
    #[error("unsupported group wire format")]
    UnsupportedWireFormat,
    #[error("unsupported group control: {0}")]
    UnsupportedControl(String),
    #[error("group invite has the wrong prefix")]
    WrongInvitePrefix,
    #[error("group invite is too large")]
    InviteTooLarge,
    #[error("group invite token is unknown")]
    UnknownInviteToken,
    #[error("group invite token was already redeemed")]
    InviteAlreadyRedeemed,
    #[error("private group invite proof is incomplete")]
    IncompletePrivateProof,
    #[error("private group request was already answered")]
    PrivateRequestAlreadyAnswered,
    #[error("unsigned group invite received after a roster key was pinned")]
    UnsignedInviteAfterKeyPin,
    #[error("group invite does not contain an owner roster signature")]
    UnsignedInvite,
    #[error("invalid encoded length for {0}")]
    InvalidEncodedLength(&'static str),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Identifier(#[from] crate::ids::IdentifierError),
    #[error(transparent)]
    PrivateInvite(#[from] PrivateGroupInviteError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
