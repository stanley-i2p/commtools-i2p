use crate::history::{
    HISTORY_FILENAME, HistoryError, HistoryRecord, HistoryRepository, HistoryScope,
};
use crate::ids::{ContactId, GroupId};
use crate::storage::{StorageError, StorageRepository, StorageSnapshot, group_storage_key};
use argon2::{Algorithm, Argon2, Params, Version};
use crypto_secretbox::{
    Key, Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tar::{Archive, Builder, EntryType};
use thiserror::Error;
use zeroize::Zeroizing;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub const VAULT_FORMAT_VERSION: u32 = 1;
// These are the Argon2 crate defaults used by the existing IcedComm vault format.
pub const DEFAULT_ARGON2_MEMORY_KIB: u32 = 19 * 1_024;
pub const DEFAULT_ARGON2_ITERATIONS: u32 = 2;
pub const DEFAULT_ARGON2_PARALLELISM: u32 = 1;
pub const MIN_ARGON2_MEMORY_KIB: u32 = 8 * 1_024;
pub const MAX_ARGON2_MEMORY_KIB: u32 = 256 * 1_024;
pub const MIN_ARGON2_ITERATIONS: u32 = 2;
pub const MAX_ARGON2_ITERATIONS: u32 = 10;
pub const MIN_ARGON2_PARALLELISM: u32 = 1;
pub const MAX_ARGON2_PARALLELISM: u32 = 4;

const VAULT_MAGIC: &[u8] = b"TERMCHAT-I2P-VAULT-V1\n";
const VAULT_FORMAT: &str = "termchat-i2p-encrypted-vault";
const BACKUP_MAGIC: &[u8] = b"COMMTOOLS-I2P-BACKUP-V1\n";
const BACKUP_FORMAT: &str = "commtools-i2p-encrypted-backup";
const BACKUP_MANIFEST_FILE: &str = ".commtools-backup.json";
const CONTACT_BACKUP_MAGIC: &[u8] = b"COMMTOOLS-I2P-CONTACT-BACKUP-V1\n";
const CONTACT_BACKUP_FORMAT: &str = "commtools-i2p-encrypted-contact-backup";
const CONTACT_BACKUP_PAYLOAD_FILE: &str = "contact.json";
const GROUP_BACKUP_MAGIC: &[u8] = b"COMMTOOLS-I2P-GROUP-BACKUP-V1\n";
const GROUP_BACKUP_FORMAT: &str = "commtools-i2p-encrypted-group-backup";
const GROUP_BACKUP_PAYLOAD_FILE: &str = "group.json";
const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 24;
const MAX_PASSPHRASE_BYTES: usize = 1_024;
const MAX_ENCRYPTED_VAULT_BYTES: u64 = 16 * 1_024 * 1_024 * 1_024;
const MAX_EXTRACTED_VAULT_BYTES: u64 = 16 * 1_024 * 1_024 * 1_024;
const MAX_CONTACT_BACKUP_PAYLOAD_BYTES: u64 = 32 * 1_024 * 1_024;
const MAX_GROUP_BACKUP_PAYLOAD_BYTES: u64 = 32 * 1_024 * 1_024;
#[cfg(unix)]
const DIRECTORY_MODE: u32 = 0o700;
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VaultKdfParams {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl VaultKdfParams {
    pub fn new(memory_kib: u32, iterations: u32, parallelism: u32) -> Result<Self, VaultError> {
        let params = Self {
            memory_kib,
            iterations,
            parallelism,
        };
        params.validate()?;
        Ok(params)
    }

    pub fn memory_kib(self) -> u32 {
        self.memory_kib
    }

    pub fn iterations(self) -> u32 {
        self.iterations
    }

    pub fn parallelism(self) -> u32 {
        self.parallelism
    }

    fn validate(self) -> Result<(), VaultError> {
        if !(MIN_ARGON2_MEMORY_KIB..=MAX_ARGON2_MEMORY_KIB).contains(&self.memory_kib)
            || !(MIN_ARGON2_ITERATIONS..=MAX_ARGON2_ITERATIONS).contains(&self.iterations)
            || !(MIN_ARGON2_PARALLELISM..=MAX_ARGON2_PARALLELISM).contains(&self.parallelism)
        {
            return Err(VaultError::InvalidKdfParameters);
        }
        Params::new(self.memory_kib, self.iterations, self.parallelism, Some(32))
            .map_err(|_| VaultError::InvalidKdfParameters)?;
        Ok(())
    }
}

impl Default for VaultKdfParams {
    fn default() -> Self {
        Self {
            memory_kib: DEFAULT_ARGON2_MEMORY_KIB,
            iterations: DEFAULT_ARGON2_ITERATIONS,
            parallelism: DEFAULT_ARGON2_PARALLELISM,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContactBackupInspection {
    pub contact_id: ContactId,
    pub display_name: String,
    pub includes_history: bool,
    pub replacement_contact_id: Option<ContactId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct GroupBackupInspection {
    pub group_id: GroupId,
    pub display_name: String,
    pub includes_history: bool,
    pub replacement_group_id: Option<GroupId>,
}

pub fn suggested_backup_export_path(vault_root: &Path) -> PathBuf {
    let timestamp = utc_artifact_timestamp(SystemTime::now());
    sibling_artifact_path(vault_root, &format!("-backup-{timestamp}.ctbak"))
}

pub fn suggested_backup_import_path(vault_root: &Path) -> PathBuf {
    sibling_artifact_path(vault_root, "-backup.ctbak")
}

pub fn suggested_contact_backup_export_path(
    vault_root: &Path,
    display_name: &str,
    contact_id: &ContactId,
) -> PathBuf {
    let label = artifact_display_label(display_name);
    let identifier = artifact_identifier(contact_id.as_str());
    sibling_artifact_path(
        vault_root,
        &format!("-contact-{label}-{identifier}.ctcontact"),
    )
}

pub fn suggested_contact_backup_import_path(vault_root: &Path) -> PathBuf {
    sibling_artifact_path(vault_root, "-contact.ctcontact")
}

pub fn suggested_group_backup_export_path(
    vault_root: &Path,
    display_name: &str,
    group_id: &GroupId,
) -> PathBuf {
    let label = artifact_display_label(display_name);
    let identifier = artifact_identifier(group_id.as_str());
    sibling_artifact_path(
        vault_root,
        &format!("-group-{label}-{identifier}.ctgroup"),
    )
}

pub fn suggested_group_backup_import_path(vault_root: &Path) -> PathBuf {
    sibling_artifact_path(vault_root, "-group.ctgroup")
}

#[derive(Debug, Clone)]
pub struct VaultRepository {
    root: PathBuf,
    creation_kdf: VaultKdfParams,
}

impl VaultRepository {
    pub fn new(root: impl Into<PathBuf>) -> Result<Self, VaultError> {
        Self::with_kdf(root, VaultKdfParams::default())
    }

    pub fn with_kdf(
        root: impl Into<PathBuf>,
        creation_kdf: VaultKdfParams,
    ) -> Result<Self, VaultError> {
        let root = root.into();
        if root.as_os_str().is_empty() || root.file_name().is_none() {
            return Err(VaultError::InvalidRoot);
        }
        creation_kdf.validate()?;
        Ok(Self { root, creation_kdf })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn vault_path(&self) -> PathBuf {
        sibling_with_suffix(&self.root, ".vault")
    }

    pub fn lock_path(&self) -> PathBuf {
        sibling_with_suffix(&self.root, ".app.lock")
    }

    fn restore_staging_path(&self) -> PathBuf {
        sibling_with_suffix(&self.root, ".restore-staging")
    }

    fn unlock_staging_path(&self) -> PathBuf {
        sibling_with_suffix(&self.root, ".unlock-staging")
    }

    pub fn wipe_all(&self) -> Result<(), VaultError> {
        remove_path_if_exists(&self.root)?;
        remove_path_if_exists(&self.unlock_staging_path())?;
        remove_path_if_exists(&self.restore_staging_path())?;
        remove_path_if_exists(&self.vault_path())?;
        remove_path_if_exists(&sibling_with_suffix(&self.vault_path(), ".previous"))?;
        sync_parent(&self.root)
    }

    pub fn exists(&self) -> Result<bool, VaultError> {
        Ok(self.vault_path().is_file())
    }

    pub fn try_acquire_lease(&self) -> Result<VaultLease, VaultError> {
        let path = self.lock_path();
        let parent = path.parent().ok_or(VaultError::InvalidRoot)?;
        ensure_parent_directory(parent)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|error| io_error(&path, error))?;
        set_file_mode(&file, &path)?;
        match FileExt::try_lock_exclusive(&file) {
            Ok(()) => Ok(VaultLease { file, path }),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                Err(VaultError::AlreadyInUse)
            }
            Err(error) => Err(io_error(&path, error)),
        }
    }

    pub fn create(&self, passphrase: &[u8]) -> Result<UnlockedVault, VaultError> {
        validate_passphrase(passphrase)?;
        if self.exists()? {
            return Err(VaultError::AlreadyExists);
        }
        remove_path_if_exists(&self.unlock_staging_path())?;
        remove_path_if_exists(&self.restore_staging_path())?;
        if directory_has_entries(&self.root)? {
            return Err(VaultError::PlaintextPresent);
        }
        let storage = StorageRepository::new(&self.root)?;
        let mut snapshot = StorageSnapshot::new();
        storage.commit(&mut snapshot)?;
        Ok(UnlockedVault {
            repository: self.clone(),
            storage,
            snapshot,
            passphrase: Zeroizing::new(passphrase.to_vec()),
            kdf: self.creation_kdf,
            dirty: false,
        })
    }

    pub fn unlock(&self, passphrase: &[u8]) -> Result<UnlockedVault, VaultError> {
        validate_passphrase(passphrase)?;
        let vault_path = self.vault_path();
        if !vault_path.is_file() {
            return Err(VaultError::NotFound);
        }
        remove_path_if_exists(&self.unlock_staging_path())?;
        remove_path_if_exists(&self.restore_staging_path())?;
        if directory_has_entries(&self.root)? {
            return Err(VaultError::PlaintextPresent);
        }

        let encrypted = read_vault(&vault_path)?;
        let (archive, kdf) = decrypt_payload(&encrypted, passphrase)?;
        let archive = Zeroizing::new(archive);
        let staging = self.unlock_staging_path();
        remove_path_if_exists(&staging)?;
        create_secure_directory(&staging)?;
        let extraction = extract_tar_gz(&archive, &staging);
        if let Err(error) = extraction {
            let _ = remove_path_if_exists(&staging);
            return Err(error);
        }
        if let Err(error) = validate_plaintext_tree(&staging) {
            let _ = remove_path_if_exists(&staging);
            return Err(error);
        }
        if self.root.exists() {
            remove_path_if_exists(&self.root)?;
        }
        if let Err(error) = fs::rename(&staging, &self.root) {
            let _ = remove_path_if_exists(&staging);
            return Err(io_error(&self.root, error));
        }
        sync_parent(&self.root)?;

        let storage = StorageRepository::new(&self.root)?;
        let snapshot = storage.load_or_empty()?;
        Ok(UnlockedVault {
            repository: self.clone(),
            storage,
            snapshot,
            passphrase: Zeroizing::new(passphrase.to_vec()),
            kdf,
            dirty: false,
        })
    }

    /// Reopens a plaintext working tree left by an interrupted process.
    ///
    /// The existing encrypted container is authenticated first so arbitrary
    /// plaintext cannot establish or change the vault passphrase.
    pub fn recover_existing_plaintext(
        &self,
        passphrase: &[u8],
    ) -> Result<UnlockedVault, VaultError> {
        validate_passphrase(passphrase)?;
        let vault_path = self.vault_path();
        if !vault_path.is_file() {
            return Err(VaultError::NotFound);
        }
        remove_path_if_exists(&self.unlock_staging_path())?;
        remove_path_if_exists(&self.restore_staging_path())?;
        if !directory_has_entries(&self.root)? {
            return self.unlock(passphrase);
        }

        let encrypted = read_vault(&vault_path)?;
        let (archive, kdf) = decrypt_payload(&encrypted, passphrase)?;
        let _archive = Zeroizing::new(archive);
        validate_plaintext_tree(&self.root)?;

        let storage = StorageRepository::new(&self.root)?;
        let snapshot = storage.load_or_empty()?;
        Ok(UnlockedVault {
            repository: self.clone(),
            storage,
            snapshot,
            passphrase: Zeroizing::new(passphrase.to_vec()),
            kdf,
            dirty: false,
        })
    }

    /// Adopts a valid plaintext working tree when the process was interrupted
    /// before the first encrypted generation could be created.
    pub fn adopt_initial_plaintext(
        &self,
        passphrase: &[u8],
    ) -> Result<UnlockedVault, VaultError> {
        validate_passphrase(passphrase)?;
        if self.exists()? {
            return Err(VaultError::AlreadyExists);
        }
        remove_path_if_exists(&self.unlock_staging_path())?;
        remove_path_if_exists(&self.restore_staging_path())?;
        validate_plaintext_tree(&self.root)?;

        let storage = StorageRepository::new(&self.root)?;
        let snapshot = storage.load_or_empty()?;
        Ok(UnlockedVault {
            repository: self.clone(),
            storage,
            snapshot,
            passphrase: Zeroizing::new(passphrase.to_vec()),
            kdf: self.creation_kdf,
            dirty: false,
        })
    }

    /// Discards an interrupted plaintext working tree and restores the last
    /// authenticated encrypted generation.
    pub fn discard_plaintext_and_unlock(
        &self,
        passphrase: &[u8],
    ) -> Result<UnlockedVault, VaultError> {
        validate_passphrase(passphrase)?;
        let vault_path = self.vault_path();
        if !vault_path.is_file() {
            return Err(VaultError::NotFound);
        }
        remove_path_if_exists(&self.unlock_staging_path())?;

        // Authenticate before performing the explicitly requested destructive step.
        let encrypted = read_vault(&vault_path)?;
        let (archive, kdf) = decrypt_payload(&encrypted, passphrase)?;
        let archive = Zeroizing::new(archive);
        let staging = self.restore_staging_path();
        remove_path_if_exists(&staging)?;
        create_secure_directory(&staging)?;
        let extraction = extract_tar_gz(&archive, &staging);
        if let Err(error) = extraction {
            let _ = remove_path_if_exists(&staging);
            return Err(error);
        }
        if let Err(error) = validate_plaintext_tree(&staging).and_then(|_| {
            StorageRepository::new(&staging)?
                .load_or_empty()
                .map(|_| ())
                .map_err(VaultError::from)
        }) {
            let _ = remove_path_if_exists(&staging);
            return Err(error);
        }

        // The encrypted generation is usable; the user-approved discard can now occur.
        if let Err(error) = remove_path_if_exists(&self.root) {
            let _ = remove_path_if_exists(&staging);
            return Err(error);
        }
        if let Err(error) = fs::rename(&staging, &self.root) {
            let _ = remove_path_if_exists(&staging);
            return Err(io_error(&self.root, error));
        }
        sync_parent(&self.root)?;

        let storage = StorageRepository::new(&self.root)?;
        let snapshot = storage.load_or_empty()?;
        Ok(UnlockedVault {
            repository: self.clone(),
            storage,
            snapshot,
            passphrase: Zeroizing::new(passphrase.to_vec()),
            kdf,
            dirty: false,
        })
    }

    /// Discards an interrupted pre-encryption working tree and creates a new,
    /// empty vault with the supplied passphrase.
    pub fn discard_plaintext_and_create(
        &self,
        passphrase: &[u8],
    ) -> Result<UnlockedVault, VaultError> {
        validate_passphrase(passphrase)?;
        if self.exists()? {
            return Err(VaultError::AlreadyExists);
        }
        remove_path_if_exists(&self.unlock_staging_path())?;
        remove_path_if_exists(&self.restore_staging_path())?;
        remove_path_if_exists(&self.root)?;
        sync_parent(&self.root)?;
        self.create(passphrase)
    }

    fn encrypt_plaintext(&self, passphrase: &[u8], kdf: VaultKdfParams) -> Result<(), VaultError> {
        validate_plaintext_tree(&self.root)?;
        let archive = Zeroizing::new(build_tar_gz(&self.root)?);
        let encrypted = encrypt_payload(&archive, passphrase, kdf)?;
        publish_vault(&self.vault_path(), &encrypted)?;
        remove_path_if_exists(&self.root)?;
        sync_parent(&self.root)
    }
}

pub struct VaultLease {
    file: File,
    path: PathBuf,
}

impl VaultLease {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for VaultLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VaultLease")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for VaultLease {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

pub struct UnlockedVault {
    repository: VaultRepository,
    storage: StorageRepository,
    snapshot: StorageSnapshot,
    passphrase: Zeroizing<Vec<u8>>,
    kdf: VaultKdfParams,
    dirty: bool,
}

impl UnlockedVault {
    pub fn snapshot(&self) -> &StorageSnapshot {
        &self.snapshot
    }

    pub fn snapshot_mut(&mut self) -> &mut StorageSnapshot {
        self.dirty = true;
        &mut self.snapshot
    }

    pub fn files_dir(&self) -> PathBuf {
        self.storage.files_dir()
    }

    pub fn history_repository(&self) -> Result<HistoryRepository, HistoryError> {
        HistoryRepository::new(self.storage.root())
    }

    pub fn passphrase_matches(&self, candidate: &[u8]) -> bool {
        constant_time_eq(self.passphrase.as_slice(), candidate)
    }

    pub fn export_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        include_files: bool,
    ) -> Result<(), VaultError> {
        validate_passphrase(passphrase)?;
        self.validate_external_backup_path(path)?;
        self.commit()?;
        validate_plaintext_tree(&self.repository.root)?;
        let archive = Zeroizing::new(build_backup_tar_gz(&self.repository.root, include_files)?);
        let encrypted = encrypt_container(
            &archive,
            passphrase,
            self.repository.creation_kdf,
            BACKUP_MAGIC,
            BACKUP_FORMAT,
        )?;
        publish_container(path, &encrypted)
    }

    fn validate_external_backup_path(&self, path: &Path) -> Result<(), VaultError> {
        let candidate = absolute_path(path)?;
        let root = absolute_path(&self.repository.root)?;
        if candidate.starts_with(&root)
            || candidate == absolute_path(&self.repository.vault_path())?
            || candidate == absolute_path(&self.repository.lock_path())?
        {
            return Err(VaultError::BackupPathConflictsWithVault);
        }
        Ok(())
    }

    pub fn restore_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        restore_files: bool,
    ) -> Result<(), VaultError> {
        validate_passphrase(passphrase)?;
        self.commit()?;
        let encrypted = read_container(path)?;
        let (archive, _) = decrypt_container(&encrypted, passphrase, BACKUP_MAGIC, BACKUP_FORMAT)?;
        let archive = Zeroizing::new(archive);
        let staging = sibling_with_suffix(
            &self.repository.root,
            &format!(".restore-{}", std::process::id()),
        );
        let rollback = sibling_with_suffix(
            &self.repository.root,
            &format!(".restore-rollback-{}", std::process::id()),
        );
        remove_path_if_exists(&staging)?;
        remove_path_if_exists(&rollback)?;
        create_secure_directory(&staging)?;
        let result = (|| {
            extract_tar_gz(&archive, &staging)?;
            let manifest_path = staging.join(BACKUP_MANIFEST_FILE);
            let manifest: BackupManifest = serde_json::from_slice(
                &fs::read(&manifest_path).map_err(|error| io_error(&manifest_path, error))?,
            )
            .map_err(|error| VaultError::Serialization(error.to_string()))?;
            manifest.validate()?;
            fs::remove_file(&manifest_path).map_err(|error| io_error(&manifest_path, error))?;
            validate_plaintext_tree(&staging)?;
            let staged_storage = StorageRepository::new(&staging)?;
            let staged_snapshot = staged_storage.load_or_empty()?;

            if !restore_files {
                remove_path_if_exists(&staging.join("files"))?;
                copy_directory_contents(&self.storage.files_dir(), &staging.join("files"))?;
            }

            fs::rename(&self.repository.root, &rollback)
                .map_err(|error| io_error(&self.repository.root, error))?;
            if let Err(error) = fs::rename(&staging, &self.repository.root) {
                let _ = fs::rename(&rollback, &self.repository.root);
                return Err(io_error(&self.repository.root, error));
            }
            let storage = StorageRepository::new(&self.repository.root)?;
            self.storage = storage;
            self.snapshot = staged_snapshot;
            self.dirty = false;
            remove_path_if_exists(&rollback)?;
            sync_parent(&self.repository.root)
        })();
        if result.is_err() {
            let _ = remove_path_if_exists(&staging);
            if rollback.exists() && !self.repository.root.exists() {
                let _ = fs::rename(&rollback, &self.repository.root);
            }
        }
        result
    }

    pub fn export_contact_backup(
        &mut self,
        contact_id: &ContactId,
        path: &Path,
        passphrase: &[u8],
        include_history: bool,
    ) -> Result<(), VaultError> {
        validate_passphrase(passphrase)?;
        self.validate_external_backup_path(path)?;
        self.commit()?;
        let contact = self
            .snapshot
            .contacts
            .get(contact_id)
            .cloned()
            .ok_or_else(|| StorageError::Validation(format!("contact not found: {contact_id}")))?;
        let history = if include_history {
            Some(
                self.history_repository()?
                    .load(&HistoryScope::Contact(contact.display_name.clone()))?,
            )
        } else {
            None
        };
        let payload = ContactBackupPayload::new(contact, history);
        payload.validate()?;
        let archive = Zeroizing::new(build_contact_backup_tar_gz(&payload)?);
        let encrypted = encrypt_container(
            &archive,
            passphrase,
            self.repository.creation_kdf,
            CONTACT_BACKUP_MAGIC,
            CONTACT_BACKUP_FORMAT,
        )?;
        publish_container(path, &encrypted)
    }

    pub fn inspect_contact_backup(
        &self,
        path: &Path,
        passphrase: &[u8],
    ) -> Result<ContactBackupInspection, VaultError> {
        validate_passphrase(passphrase)?;
        let payload = read_contact_backup(path, passphrase)?;
        let replacement_contact_id = self.contact_backup_replacement(&payload.contact)?;
        Ok(ContactBackupInspection {
            contact_id: payload.contact.id,
            display_name: payload.contact.display_name,
            includes_history: payload.history.is_some(),
            replacement_contact_id,
        })
    }

    pub fn import_contact_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        replace: bool,
    ) -> Result<ContactId, VaultError> {
        validate_passphrase(passphrase)?;
        self.commit()?;
        let payload = read_contact_backup(path, passphrase)?;
        let replacement = self.contact_backup_replacement(&payload.contact)?;
        if replacement.is_some() && !replace {
            return Err(VaultError::ContactImportRequiresReplacement);
        }

        let imported_id = payload.contact.id.clone();
        let imported_name = payload.contact.display_name.clone();
        let history_repository = self.history_repository()?;
        let previous_history = replacement
            .as_ref()
            .and_then(|replacement_id| self.snapshot.contacts.get(replacement_id))
            .map(|contact| {
                history_repository
                    .load(&HistoryScope::Contact(contact.display_name.clone()))
                    .map(|records| (contact.display_name.clone(), records))
            })
            .transpose()?;
        let mut candidate = self.snapshot.clone();
        if let Some(replacement_id) = &replacement {
            candidate.contacts.remove(replacement_id);
        }
        candidate
            .contacts
            .insert(imported_id.clone(), payload.contact);
        candidate.validate()?;

        let previous_snapshot = self.snapshot.clone();
        self.storage.commit(&mut candidate)?;
        self.snapshot = candidate;
        self.dirty = false;
        let history = payload.history.unwrap_or_default();
        if let Err(error) =
            history_repository.replace(&HistoryScope::Contact(imported_name), &history)
        {
            let mut rollback = previous_snapshot;
            rollback = rollback.clone_with_revision(self.snapshot.revision())?;
            if let Err(rollback_error) = self.storage.commit(&mut rollback) {
                return Err(VaultError::ContactImportRollback {
                    operation: error.to_string(),
                    rollback: rollback_error.to_string(),
                });
            }
            self.snapshot = rollback;
            self.dirty = false;
            if let Some((display_name, records)) = &previous_history
                && let Err(rollback_error) = history_repository
                    .replace(&HistoryScope::Contact(display_name.clone()), records)
            {
                return Err(VaultError::ContactImportRollback {
                    operation: error.to_string(),
                    rollback: rollback_error.to_string(),
                });
            }
            return Err(error.into());
        }
        Ok(imported_id)
    }

    fn contact_backup_replacement(
        &self,
        imported: &crate::storage::ContactRecord,
    ) -> Result<Option<ContactId>, VaultError> {
        let mut matches = self
            .snapshot
            .contacts
            .values()
            .filter(|existing| {
                existing.id == imported.id
                    || existing
                        .display_name
                        .eq_ignore_ascii_case(&imported.display_name)
            })
            .map(|contact| contact.id.clone())
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.pop()),
            _ => Err(VaultError::AmbiguousContactImportConflict),
        }
    }

    pub fn export_group_backup(
        &mut self,
        group_id: &GroupId,
        path: &Path,
        passphrase: &[u8],
        include_history: bool,
    ) -> Result<(), VaultError> {
        validate_passphrase(passphrase)?;
        self.validate_external_backup_path(path)?;
        self.commit()?;
        let group = self
            .snapshot
            .groups
            .get(group_id)
            .cloned()
            .ok_or_else(|| StorageError::Validation(format!("group not found: {group_id}")))?;
        let history = if include_history {
            Some(
                self.history_repository()?
                    .load(&HistoryScope::Group(group_storage_key(&group.id)))?,
            )
        } else {
            None
        };
        let payload = GroupBackupPayload::new(group, history);
        payload.validate()?;
        let archive = Zeroizing::new(build_group_backup_tar_gz(&payload)?);
        let encrypted = encrypt_container(
            &archive,
            passphrase,
            self.repository.creation_kdf,
            GROUP_BACKUP_MAGIC,
            GROUP_BACKUP_FORMAT,
        )?;
        publish_container(path, &encrypted)
    }

    pub fn inspect_group_backup(
        &self,
        path: &Path,
        passphrase: &[u8],
    ) -> Result<GroupBackupInspection, VaultError> {
        validate_passphrase(passphrase)?;
        let payload = read_group_backup(path, passphrase)?;
        let replacement_group_id = self.group_backup_replacement(&payload.group)?;
        Ok(GroupBackupInspection {
            group_id: payload.group.id,
            display_name: payload.group.display_name,
            includes_history: payload.history.is_some(),
            replacement_group_id,
        })
    }

    pub fn import_group_backup(
        &mut self,
        path: &Path,
        passphrase: &[u8],
        replace: bool,
    ) -> Result<GroupId, VaultError> {
        validate_passphrase(passphrase)?;
        self.commit()?;
        let payload = read_group_backup(path, passphrase)?;
        let replacement = self.group_backup_replacement(&payload.group)?;
        if replacement.is_some() && !replace {
            return Err(VaultError::GroupImportRequiresReplacement);
        }

        let imported_id = payload.group.id.clone();
        let imported_scope = HistoryScope::Group(group_storage_key(&imported_id));
        let history_repository = self.history_repository()?;
        let previous_history = replacement
            .as_ref()
            .map(|replacement_id| {
                let scope = HistoryScope::Group(group_storage_key(replacement_id));
                history_repository
                    .load(&scope)
                    .map(|records| (scope, records))
            })
            .transpose()?;
        let mut candidate = self.snapshot.clone();
        if let Some(replacement_id) = &replacement {
            candidate.groups.remove(replacement_id);
        }
        candidate.groups.insert(imported_id.clone(), payload.group);
        candidate.validate()?;

        let previous_snapshot = self.snapshot.clone();
        self.storage.commit(&mut candidate)?;
        self.snapshot = candidate;
        self.dirty = false;
        let history = payload.history.unwrap_or_default();
        if let Err(error) = history_repository.replace(&imported_scope, &history) {
            let mut rollback = previous_snapshot;
            rollback = rollback.clone_with_revision(self.snapshot.revision())?;
            if let Err(rollback_error) = self.storage.commit(&mut rollback) {
                return Err(VaultError::GroupImportRollback {
                    operation: error.to_string(),
                    rollback: rollback_error.to_string(),
                });
            }
            self.snapshot = rollback;
            self.dirty = false;
            if let Some((scope, records)) = &previous_history
                && let Err(rollback_error) = history_repository.replace(scope, records)
            {
                return Err(VaultError::GroupImportRollback {
                    operation: error.to_string(),
                    rollback: rollback_error.to_string(),
                });
            }
            return Err(error.into());
        }
        Ok(imported_id)
    }

    fn group_backup_replacement(
        &self,
        imported: &crate::storage::GroupRecord,
    ) -> Result<Option<GroupId>, VaultError> {
        let imported_b32 = imported.identity.as_ref().map(|identity| &identity.b32);
        let mut matches = self
            .snapshot
            .groups
            .values()
            .filter(|existing| {
                existing.id == imported.id
                    || imported_b32.is_some_and(|b32| {
                        existing
                            .identity
                            .as_ref()
                            .is_some_and(|identity| identity.b32.eq_ignore_ascii_case(b32))
                    })
            })
            .map(|group| group.id.clone())
            .collect::<Vec<_>>();
        matches.sort();
        matches.dedup();
        match matches.len() {
            0 => Ok(None),
            1 => Ok(matches.pop()),
            _ => Err(VaultError::AmbiguousGroupImportConflict),
        }
    }

    pub fn commit(&mut self) -> Result<(), VaultError> {
        if !self.dirty {
            return Ok(());
        }
        self.storage.commit(&mut self.snapshot)?;
        self.dirty = false;
        Ok(())
    }

    pub fn update<F>(&mut self, update: F) -> Result<(), VaultError>
    where
        F: FnOnce(&mut StorageSnapshot) -> Result<(), StorageError>,
    {
        let mut candidate = self.snapshot.clone();
        update(&mut candidate)?;
        self.storage.commit(&mut candidate)?;
        self.snapshot = candidate;
        self.dirty = false;
        Ok(())
    }

    pub fn rename_contact(
        &mut self,
        contact_id: &ContactId,
        display_name: &str,
    ) -> Result<String, VaultError> {
        let mut candidate = self.snapshot.clone();
        let contact = candidate
            .contacts
            .get_mut(contact_id)
            .ok_or_else(|| StorageError::Validation(format!("contact not found: {contact_id}")))?;
        let previous_name = contact.display_name.clone();
        contact.set_display_name(display_name.to_string())?;
        candidate.validate()?;

        if previous_name == display_name {
            return Ok(display_name.to_string());
        }

        let previous_directory = self.storage.contact_directory(&previous_name)?;
        let renamed_directory = self.storage.contact_directory(display_name)?;
        if !previous_directory.is_dir() {
            return Err(io_error(
                &previous_directory,
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "contact storage directory is missing",
                ),
            ));
        }

        let parent = previous_directory.parent().ok_or(VaultError::InvalidRoot)?;
        let temporary_directory = unique_contact_rename_path(parent)?;
        fs::rename(&previous_directory, &temporary_directory)
            .map_err(|error| io_error(&previous_directory, error))?;

        if renamed_directory.exists() {
            let rollback = fs::rename(&temporary_directory, &previous_directory);
            if let Err(error) = rollback {
                return Err(VaultError::ContactRenameRollback {
                    operation: format!(
                        "contact storage already exists at {}",
                        renamed_directory.display()
                    ),
                    rollback: error.to_string(),
                });
            }
            return Err(StorageError::Validation(format!(
                "contact storage already exists at {}",
                renamed_directory.display()
            ))
            .into());
        }

        if let Err(error) = fs::rename(&temporary_directory, &renamed_directory) {
            let rollback = fs::rename(&temporary_directory, &previous_directory);
            if let Err(rollback) = rollback {
                return Err(VaultError::ContactRenameRollback {
                    operation: error.to_string(),
                    rollback: rollback.to_string(),
                });
            }
            return Err(io_error(&renamed_directory, error));
        }

        if let Err(error) = self.storage.commit(&mut candidate) {
            let rollback = rollback_contact_directory_rename(
                &renamed_directory,
                &temporary_directory,
                &previous_directory,
            );
            if let Err(rollback) = rollback {
                return Err(VaultError::ContactRenameRollback {
                    operation: error.to_string(),
                    rollback: rollback.to_string(),
                });
            }
            return Err(error.into());
        }

        self.snapshot = candidate;
        self.dirty = false;
        Ok(display_name.to_string())
    }

    pub fn reset_contact(&mut self, contact_id: &ContactId) -> Result<(), VaultError> {
        let mut candidate = self.snapshot.clone();
        let contact = candidate
            .contacts
            .get_mut(contact_id)
            .ok_or_else(|| StorageError::Validation(format!("contact not found: {contact_id}")))?;
        let history_path = self
            .storage
            .contact_directory(&contact.display_name)?
            .join(HISTORY_FILENAME);
        let staged_history = history_path.with_extension(format!("reset-{}", std::process::id()));
        if staged_history.exists() {
            return Err(VaultError::TemporaryPathExists);
        }
        let history_staged = if history_path.exists() {
            fs::rename(&history_path, &staged_history)
                .map_err(|error| io_error(&history_path, error))?;
            true
        } else {
            false
        };

        contact.tofu_peer = None;
        contact.pq_enabled = false;
        contact.history_enabled = false;
        contact.deaddrop_stats.clear();
        contact.offline = None;
        if let Err(error) = self.storage.commit(&mut candidate) {
            if history_staged {
                let _ = fs::rename(&staged_history, &history_path);
            }
            return Err(error.into());
        }
        self.snapshot = candidate;
        self.dirty = false;
        if history_staged {
            fs::remove_file(&staged_history).map_err(|error| io_error(&staged_history, error))?;
        }
        Ok(())
    }

    pub fn rotate_passphrase(&mut self, new_passphrase: &[u8]) -> Result<(), VaultError> {
        validate_passphrase(new_passphrase)?;
        self.passphrase = Zeroizing::new(new_passphrase.to_vec());
        self.kdf = self.repository.creation_kdf;
        Ok(())
    }

    pub fn lock(&mut self) -> Result<(), VaultError> {
        self.commit()?;
        self.repository
            .encrypt_plaintext(self.passphrase.as_slice(), self.kdf)
    }
}

impl fmt::Debug for UnlockedVault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedVault")
            .field("root", &self.repository.root)
            .field("revision", &self.snapshot.revision())
            .field("contact_count", &self.snapshot.contacts.len())
            .field("group_count", &self.snapshot.groups.len())
            .field("passphrase", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct VaultEnvelope {
    format: String,
    version: u32,
    kdf: String,
    cipher: String,
    compression: String,
    salt_hex: String,
    nonce_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argon2_memory_kib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argon2_iterations: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argon2_parallelism: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    format: String,
    version: u32,
    includes_files: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContactBackupPayload {
    format: String,
    version: u32,
    contact: crate::storage::ContactRecord,
    history: Option<Vec<HistoryRecord>>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupBackupPayload {
    format: String,
    version: u32,
    group: crate::storage::GroupRecord,
    history: Option<Vec<HistoryRecord>>,
}

impl ContactBackupPayload {
    fn new(contact: crate::storage::ContactRecord, history: Option<Vec<HistoryRecord>>) -> Self {
        Self {
            format: "COMMTOOLS-I2P-CONTACT-BACKUP".into(),
            version: 1,
            contact,
            history,
        }
    }

    fn validate(&self) -> Result<(), VaultError> {
        if self.format != "COMMTOOLS-I2P-CONTACT-BACKUP" || self.version != 1 {
            return Err(VaultError::UnsupportedFormat);
        }
        let mut snapshot = StorageSnapshot::new();
        snapshot
            .contacts
            .insert(self.contact.id.clone(), self.contact.clone());
        snapshot.validate()?;
        if let Some(history) = &self.history {
            HistoryRepository::validate_records(history)?;
        }
        Ok(())
    }
}

impl GroupBackupPayload {
    fn new(group: crate::storage::GroupRecord, history: Option<Vec<HistoryRecord>>) -> Self {
        Self {
            format: "COMMTOOLS-I2P-GROUP-BACKUP".into(),
            version: 1,
            group,
            history,
        }
    }

    fn validate(&self) -> Result<(), VaultError> {
        if self.format != "COMMTOOLS-I2P-GROUP-BACKUP" || self.version != 1 {
            return Err(VaultError::UnsupportedFormat);
        }
        let mut snapshot = StorageSnapshot::new();
        snapshot
            .groups
            .insert(self.group.id.clone(), self.group.clone());
        snapshot.validate()?;
        if let Some(history) = &self.history {
            HistoryRepository::validate_records(history)?;
        }
        Ok(())
    }
}

impl BackupManifest {
    fn new(includes_files: bool) -> Self {
        Self {
            format: "COMMTOOLS-I2P-BACKUP".into(),
            version: 1,
            includes_files,
        }
    }

    fn validate(&self) -> Result<(), VaultError> {
        if self.format != "COMMTOOLS-I2P-BACKUP" || self.version != 1 {
            return Err(VaultError::UnsupportedFormat);
        }
        Ok(())
    }
}

impl VaultEnvelope {
    fn kdf_params(&self) -> Result<VaultKdfParams, VaultError> {
        match (
            self.argon2_memory_kib,
            self.argon2_iterations,
            self.argon2_parallelism,
        ) {
            (None, None, None) => Ok(VaultKdfParams::default()),
            (Some(memory), Some(iterations), Some(parallelism)) => {
                VaultKdfParams::new(memory, iterations, parallelism)
            }
            _ => Err(VaultError::MalformedContainer),
        }
    }
}

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault root must have a non-empty final path component")]
    InvalidRoot,
    #[error("backup path must have a non-empty final path component")]
    InvalidBackupPath,
    #[error("backup path must be outside the live vault and its control files")]
    BackupPathConflictsWithVault,
    #[error("vault passphrase must contain 1..={MAX_PASSPHRASE_BYTES} bytes")]
    InvalidPassphrase,
    #[error("vault Argon2id parameters are outside the accepted bounds")]
    InvalidKdfParameters,
    #[error("vault already exists")]
    AlreadyExists,
    #[error("vault is already open in another process")]
    AlreadyInUse,
    #[error("vault does not exist")]
    NotFound,
    #[error("plaintext storage is already present beside the encrypted vault")]
    PlaintextPresent,
    #[error("unsupported vault format or algorithm")]
    UnsupportedFormat,
    #[error("vault container is malformed")]
    MalformedContainer,
    #[error("vault authentication failed")]
    AuthenticationFailed,
    #[error("vault encryption failed")]
    EncryptionFailed,
    #[error("vault exceeds the supported size: {0} bytes")]
    TooLarge(u64),
    #[error("vault archive contains an unsafe entry")]
    UnsafeArchive,
    #[error("vault temporary path already exists")]
    TemporaryPathExists,
    #[error("contact rename failed ({operation}); storage rollback also failed ({rollback})")]
    ContactRenameRollback { operation: String, rollback: String },
    #[error("contact backup conflicts with an existing contact and requires replacement")]
    ContactImportRequiresReplacement,
    #[error("contact backup identifier and name conflict with different existing contacts")]
    AmbiguousContactImportConflict,
    #[error("contact import failed ({operation}); storage rollback also failed ({rollback})")]
    ContactImportRollback { operation: String, rollback: String },
    #[error("group backup conflicts with an existing group and requires replacement")]
    GroupImportRequiresReplacement,
    #[error("group backup identifier and local identity conflict with different existing groups")]
    AmbiguousGroupImportConflict,
    #[error("group import failed ({operation}); storage rollback also failed ({rollback})")]
    GroupImportRollback { operation: String, rollback: String },
    #[error("vault I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    History(#[from] HistoryError),
    #[error("vault serialization failed: {0}")]
    Serialization(String),
}

fn encrypt_payload(
    payload: &[u8],
    passphrase: &[u8],
    kdf: VaultKdfParams,
) -> Result<Vec<u8>, VaultError> {
    encrypt_container(payload, passphrase, kdf, VAULT_MAGIC, VAULT_FORMAT)
}

fn encrypt_container(
    payload: &[u8],
    passphrase: &[u8],
    kdf: VaultKdfParams,
    magic: &[u8],
    format: &str,
) -> Result<Vec<u8>, VaultError> {
    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt, kdf)?;
    let ciphertext = XSalsa20Poly1305::new(Key::from_slice(key.as_ref()))
        .encrypt(Nonce::from_slice(&nonce), payload)
        .map_err(|_| VaultError::EncryptionFailed)?;
    let defaults = kdf == VaultKdfParams::default();
    let envelope = VaultEnvelope {
        format: format.into(),
        version: VAULT_FORMAT_VERSION,
        kdf: "argon2id".into(),
        cipher: "xsalsa20poly1305".into(),
        compression: "tar.gz".into(),
        salt_hex: hex::encode(salt),
        nonce_hex: hex::encode(nonce),
        argon2_memory_kib: (!defaults).then_some(kdf.memory_kib),
        argon2_iterations: (!defaults).then_some(kdf.iterations),
        argon2_parallelism: (!defaults).then_some(kdf.parallelism),
    };
    let header = serde_json::to_vec(&envelope)
        .map_err(|error| VaultError::Serialization(error.to_string()))?;
    let header_len = u32::try_from(header.len()).map_err(|_| VaultError::MalformedContainer)?;
    let mut output = Vec::with_capacity(magic.len() + 4 + header.len() + ciphertext.len());
    output.extend_from_slice(magic);
    output.extend_from_slice(&header_len.to_be_bytes());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

fn decrypt_payload(
    bytes: &[u8],
    passphrase: &[u8],
) -> Result<(Vec<u8>, VaultKdfParams), VaultError> {
    decrypt_container(bytes, passphrase, VAULT_MAGIC, VAULT_FORMAT)
}

fn decrypt_container(
    bytes: &[u8],
    passphrase: &[u8],
    magic: &[u8],
    format: &str,
) -> Result<(Vec<u8>, VaultKdfParams), VaultError> {
    if !bytes.starts_with(magic) || bytes.len() < magic.len() + 4 {
        return Err(VaultError::UnsupportedFormat);
    }
    let length_offset = magic.len();
    let header_len = u32::from_be_bytes(
        bytes[length_offset..length_offset + 4]
            .try_into()
            .map_err(|_| VaultError::MalformedContainer)?,
    ) as usize;
    let header_start = length_offset + 4;
    let header_end = header_start
        .checked_add(header_len)
        .filter(|end| *end <= bytes.len())
        .ok_or(VaultError::MalformedContainer)?;
    let envelope: VaultEnvelope = serde_json::from_slice(&bytes[header_start..header_end])
        .map_err(|_| VaultError::MalformedContainer)?;
    if envelope.format != format
        || envelope.version != VAULT_FORMAT_VERSION
        || envelope.kdf != "argon2id"
        || envelope.cipher != "xsalsa20poly1305"
        || envelope.compression != "tar.gz"
    {
        return Err(VaultError::UnsupportedFormat);
    }
    let salt = hex::decode(&envelope.salt_hex).map_err(|_| VaultError::MalformedContainer)?;
    let nonce = hex::decode(&envelope.nonce_hex).map_err(|_| VaultError::MalformedContainer)?;
    if salt.len() != SALT_SIZE || nonce.len() != NONCE_SIZE {
        return Err(VaultError::MalformedContainer);
    }
    let kdf = envelope.kdf_params()?;
    let key = derive_key(passphrase, &salt, kdf)?;
    let plaintext = XSalsa20Poly1305::new(Key::from_slice(key.as_ref()))
        .decrypt(Nonce::from_slice(&nonce), &bytes[header_end..])
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok((plaintext, kdf))
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    params: VaultKdfParams,
) -> Result<Zeroizing<[u8; 32]>, VaultError> {
    params.validate()?;
    let argon_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|_| VaultError::InvalidKdfParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon2
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| VaultError::AuthenticationFailed)?;
    Ok(key)
}

fn build_tar_gz(root: &Path) -> Result<Vec<u8>, VaultError> {
    let name = root.file_name().ok_or(VaultError::InvalidRoot)?;
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut gzip);
        archive
            .append_dir_all(name, root)
            .map_err(|error| io_error(root, error))?;
        archive.finish().map_err(|error| io_error(root, error))?;
    }
    gzip.finish().map_err(|error| io_error(root, error))
}

fn build_backup_tar_gz(root: &Path, include_files: bool) -> Result<Vec<u8>, VaultError> {
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut gzip);
        let archive_root = Path::new("commtools-backup-v1");
        archive
            .append_dir(archive_root, root)
            .map_err(|error| io_error(root, error))?;
        append_backup_directory(&mut archive, root, archive_root, include_files, true)?;
        let manifest = serde_json::to_vec_pretty(&BackupManifest::new(include_files))
            .map_err(|error| VaultError::Serialization(error.to_string()))?;
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                archive_root.join(BACKUP_MANIFEST_FILE),
                manifest.as_slice(),
            )
            .map_err(|error| io_error(root, error))?;
        archive.finish().map_err(|error| io_error(root, error))?;
    }
    gzip.finish().map_err(|error| io_error(root, error))
}

fn build_contact_backup_tar_gz(payload: &ContactBackupPayload) -> Result<Vec<u8>, VaultError> {
    let serialized = Zeroizing::new(
        serde_json::to_vec(payload)
            .map_err(|error| VaultError::Serialization(error.to_string()))?,
    );
    if serialized.len() as u64 > MAX_CONTACT_BACKUP_PAYLOAD_BYTES {
        return Err(VaultError::TooLarge(serialized.len() as u64));
    }
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut gzip);
        let mut header = tar::Header::new_gnu();
        header.set_size(serialized.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                Path::new("commtools-contact-backup-v1").join(CONTACT_BACKUP_PAYLOAD_FILE),
                serialized.as_slice(),
            )
            .map_err(|error| io_error(Path::new(CONTACT_BACKUP_PAYLOAD_FILE), error))?;
        archive
            .finish()
            .map_err(|error| io_error(Path::new(CONTACT_BACKUP_PAYLOAD_FILE), error))?;
    }
    gzip.finish()
        .map_err(|error| io_error(Path::new(CONTACT_BACKUP_PAYLOAD_FILE), error))
}

fn read_contact_backup(path: &Path, passphrase: &[u8]) -> Result<ContactBackupPayload, VaultError> {
    let encrypted = read_container(path)?;
    let (archive, _) = decrypt_container(
        &encrypted,
        passphrase,
        CONTACT_BACKUP_MAGIC,
        CONTACT_BACKUP_FORMAT,
    )?;
    let archive = Zeroizing::new(archive);
    let decoder = GzDecoder::new(Cursor::new(archive.as_slice()));
    let mut tar = Archive::new(decoder);
    let mut payload_bytes: Option<Zeroizing<Vec<u8>>> = None;
    for entry in tar.entries().map_err(|_| VaultError::MalformedContainer)? {
        let mut entry = entry.map_err(|_| VaultError::MalformedContainer)?;
        let entry_path = entry
            .path()
            .map_err(|_| VaultError::UnsafeArchive)?
            .into_owned();
        let expected = Path::new("commtools-contact-backup-v1").join(CONTACT_BACKUP_PAYLOAD_FILE);
        if entry_path != expected
            || entry.header().entry_type() != EntryType::Regular
            || payload_bytes.is_some()
        {
            return Err(VaultError::UnsafeArchive);
        }
        let size = entry
            .header()
            .size()
            .map_err(|_| VaultError::MalformedContainer)?;
        if size > MAX_CONTACT_BACKUP_PAYLOAD_BYTES || size > usize::MAX as u64 {
            return Err(VaultError::TooLarge(size));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(size as usize));
        std::io::Read::by_ref(&mut entry)
            .take(MAX_CONTACT_BACKUP_PAYLOAD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(path, error))?;
        if bytes.len() as u64 != size {
            return Err(VaultError::MalformedContainer);
        }
        payload_bytes = Some(bytes);
    }
    let payload_bytes = payload_bytes.ok_or(VaultError::MalformedContainer)?;
    let payload: ContactBackupPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| VaultError::MalformedContainer)?;
    payload.validate()?;
    Ok(payload)
}

fn build_group_backup_tar_gz(payload: &GroupBackupPayload) -> Result<Vec<u8>, VaultError> {
    let serialized = Zeroizing::new(
        serde_json::to_vec(payload)
            .map_err(|error| VaultError::Serialization(error.to_string()))?,
    );
    if serialized.len() as u64 > MAX_GROUP_BACKUP_PAYLOAD_BYTES {
        return Err(VaultError::TooLarge(serialized.len() as u64));
    }
    let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut archive = Builder::new(&mut gzip);
        let mut header = tar::Header::new_gnu();
        header.set_size(serialized.len() as u64);
        header.set_mode(0o600);
        header.set_cksum();
        archive
            .append_data(
                &mut header,
                Path::new("commtools-group-backup-v1").join(GROUP_BACKUP_PAYLOAD_FILE),
                serialized.as_slice(),
            )
            .map_err(|error| io_error(Path::new(GROUP_BACKUP_PAYLOAD_FILE), error))?;
        archive
            .finish()
            .map_err(|error| io_error(Path::new(GROUP_BACKUP_PAYLOAD_FILE), error))?;
    }
    gzip
        .finish()
        .map_err(|error| io_error(Path::new(GROUP_BACKUP_PAYLOAD_FILE), error))
}

fn read_group_backup(path: &Path, passphrase: &[u8]) -> Result<GroupBackupPayload, VaultError> {
    let encrypted = read_container(path)?;
    let (archive, _) = decrypt_container(
        &encrypted,
        passphrase,
        GROUP_BACKUP_MAGIC,
        GROUP_BACKUP_FORMAT,
    )?;
    let archive = Zeroizing::new(archive);
    let decoder = GzDecoder::new(Cursor::new(archive.as_slice()));
    let mut tar = Archive::new(decoder);
    let mut payload_bytes: Option<Zeroizing<Vec<u8>>> = None;
    for entry in tar.entries().map_err(|_| VaultError::MalformedContainer)? {
        let mut entry = entry.map_err(|_| VaultError::MalformedContainer)?;
        let entry_path = entry
            .path()
            .map_err(|_| VaultError::UnsafeArchive)?
            .into_owned();
        let expected = Path::new("commtools-group-backup-v1").join(GROUP_BACKUP_PAYLOAD_FILE);
        if entry_path != expected
            || entry.header().entry_type() != EntryType::Regular
            || payload_bytes.is_some()
        {
            return Err(VaultError::UnsafeArchive);
        }
        let size = entry
            .header()
            .size()
            .map_err(|_| VaultError::MalformedContainer)?;
        if size > MAX_GROUP_BACKUP_PAYLOAD_BYTES || size > usize::MAX as u64 {
            return Err(VaultError::TooLarge(size));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(size as usize));
        std::io::Read::by_ref(&mut entry)
            .take(MAX_GROUP_BACKUP_PAYLOAD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| io_error(path, error))?;
        if bytes.len() as u64 != size {
            return Err(VaultError::MalformedContainer);
        }
        payload_bytes = Some(bytes);
    }
    let payload_bytes = payload_bytes.ok_or(VaultError::MalformedContainer)?;
    let payload: GroupBackupPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| VaultError::MalformedContainer)?;
    payload.validate()?;
    Ok(payload)
}

fn append_backup_directory(
    archive: &mut Builder<&mut GzEncoder<Vec<u8>>>,
    source: &Path,
    archive_path: &Path,
    include_files: bool,
    root: bool,
) -> Result<(), VaultError> {
    let mut entries = fs::read_dir(source)
        .map_err(|error| io_error(source, error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io_error(source, error))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let name = entry.file_name();
        if root && !include_files && name.to_str() == Some("files") {
            let empty_files = archive_path.join("files");
            archive
                .append_dir(&empty_files, entry.path())
                .map_err(|error| io_error(&entry.path(), error))?;
            continue;
        }
        let source_path = entry.path();
        let destination = archive_path.join(&name);
        let file_type = entry
            .file_type()
            .map_err(|error| io_error(&source_path, error))?;
        if file_type.is_dir() {
            archive
                .append_dir(&destination, &source_path)
                .map_err(|error| io_error(&source_path, error))?;
            append_backup_directory(archive, &source_path, &destination, include_files, false)?;
        } else if file_type.is_file() {
            archive
                .append_path_with_name(&source_path, &destination)
                .map_err(|error| io_error(&source_path, error))?;
        } else {
            return Err(VaultError::UnsafeArchive);
        }
    }
    Ok(())
}

fn extract_tar_gz(data: &[u8], target: &Path) -> Result<(), VaultError> {
    let decoder = GzDecoder::new(Cursor::new(data));
    let mut archive = Archive::new(decoder);
    let mut extracted = 0u64;
    let mut archive_root: Option<OsString> = None;
    for entry in archive
        .entries()
        .map_err(|_| VaultError::MalformedContainer)?
    {
        let mut entry = entry.map_err(|_| VaultError::MalformedContainer)?;
        let path = entry
            .path()
            .map_err(|_| VaultError::UnsafeArchive)?
            .into_owned();
        let mut components = path.components();
        let Some(Component::Normal(component)) = components.next() else {
            return Err(VaultError::UnsafeArchive);
        };
        match &archive_root {
            Some(expected) if expected != component => return Err(VaultError::UnsafeArchive),
            None => archive_root = Some(component.to_owned()),
            _ => {}
        }
        let relative = components.as_path();
        if !safe_relative_path(relative) {
            return Err(VaultError::UnsafeArchive);
        }
        let entry_type = entry.header().entry_type();
        if !matches!(entry_type, EntryType::Regular | EntryType::Directory) {
            return Err(VaultError::UnsafeArchive);
        }
        extracted = extracted
            .checked_add(
                entry
                    .header()
                    .size()
                    .map_err(|_| VaultError::MalformedContainer)?,
            )
            .filter(|size| *size <= MAX_EXTRACTED_VAULT_BYTES)
            .ok_or(VaultError::TooLarge(MAX_EXTRACTED_VAULT_BYTES + 1))?;
        if relative.as_os_str().is_empty() {
            continue;
        }
        let destination = target.join(relative);
        if entry_type == EntryType::Directory {
            create_secure_directory(&destination)?;
        } else {
            if let Some(parent) = destination.parent() {
                create_secure_directory(parent)?;
            }
            entry
                .unpack(&destination)
                .map_err(|error| io_error(&destination, error))?;
            set_path_file_mode(&destination)?;
        }
    }
    if archive_root.is_none() {
        return Err(VaultError::MalformedContainer);
    }
    Ok(())
}

fn validate_plaintext_tree(root: &Path) -> Result<(), VaultError> {
    if !root.join("profiles").is_dir()
        || !root.join("groups").is_dir()
        || !root.join("files").is_dir()
    {
        return Err(VaultError::MalformedContainer);
    }
    Ok(())
}

fn publish_vault(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if bytes.len() as u64 > MAX_ENCRYPTED_VAULT_BYTES {
        return Err(VaultError::TooLarge(bytes.len() as u64));
    }
    let parent = path.parent().ok_or(VaultError::InvalidRoot)?;
    ensure_parent_directory(parent)?;
    let temporary = sibling_with_suffix(path, &format!(".tmp-{}", std::process::id()));
    if temporary.exists() {
        return Err(VaultError::TemporaryPathExists);
    }
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| io_error(&temporary, error))?;
        set_file_mode(&file, &temporary)?;
        file.write_all(bytes)
            .map_err(|error| io_error(&temporary, error))?;
        file.sync_all()
            .map_err(|error| io_error(&temporary, error))?;
        drop(file);
        replace_vault_file(&temporary, path)?;
        sync_parent(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn publish_container(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(VaultError::InvalidBackupPath);
    }
    if bytes.len() as u64 > MAX_ENCRYPTED_VAULT_BYTES {
        return Err(VaultError::TooLarge(bytes.len() as u64));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        ensure_parent_directory(parent)?;
    }
    let temporary = sibling_with_suffix(path, &format!(".tmp-{}", std::process::id()));
    if temporary.exists() {
        return Err(VaultError::TemporaryPathExists);
    }
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|error| io_error(&temporary, error))?;
        set_file_mode(&file, &temporary)?;
        file.write_all(bytes)
            .map_err(|error| io_error(&temporary, error))?;
        file.sync_all()
            .map_err(|error| io_error(&temporary, error))?;
        drop(file);
        replace_vault_file(&temporary, path)?;
        if let Some(parent) = parent {
            sync_directory(parent)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn replace_vault_file(temporary: &Path, target: &Path) -> Result<(), VaultError> {
    fs::rename(temporary, target).map_err(|error| io_error(target, error))
}

#[cfg(not(unix))]
fn replace_vault_file(temporary: &Path, target: &Path) -> Result<(), VaultError> {
    let backup = sibling_with_suffix(target, ".previous");
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

fn read_vault(path: &Path) -> Result<Vec<u8>, VaultError> {
    read_container(path)
}

fn read_container(path: &Path) -> Result<Vec<u8>, VaultError> {
    let mut file = File::open(path).map_err(|error| io_error(path, error))?;
    let size = file
        .metadata()
        .map_err(|error| io_error(path, error))?
        .len();
    if size > MAX_ENCRYPTED_VAULT_BYTES || size > usize::MAX as u64 {
        return Err(VaultError::TooLarge(size));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .map_err(|error| io_error(path, error))?;
    Ok(bytes)
}

fn copy_directory_contents(source: &Path, target: &Path) -> Result<(), VaultError> {
    create_secure_directory(target)?;
    if !source.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(source).map_err(|error| io_error(source, error))? {
        let entry = entry.map_err(|error| io_error(source, error))?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let file_type = entry
            .file_type()
            .map_err(|error| io_error(&source_path, error))?;
        if file_type.is_dir() {
            copy_directory_contents(&source_path, &target_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &target_path).map_err(|error| io_error(&target_path, error))?;
            set_path_file_mode(&target_path)?;
        } else {
            return Err(VaultError::UnsafeArchive);
        }
    }
    Ok(())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    let mut difference = left.len() ^ right.len();
    let maximum = left.len().max(right.len());
    for index in 0..maximum {
        let left = left.get(index).copied().unwrap_or(0);
        let right = right.get(index).copied().unwrap_or(0);
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

fn sibling_artifact_path(vault_root: &Path, suffix: &str) -> PathBuf {
    let prefix = vault_root
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new(".termcomm-i2p"))
        .to_string_lossy();
    let prefix = prefix.trim_start_matches('.');
    let filename = format!("{prefix}{suffix}");
    vault_root
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(filename)
}

fn utc_artifact_timestamp(time: SystemTime) -> String {
    let seconds = time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (seconds / 86_400) as i64;
    let day_seconds = seconds % 86_400;
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    let shifted_days = days + 719_468;
    let era = shifted_days / 146_097;
    let day_of_era = shifted_days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096)
            / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year =
        day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    format!("{year:04}{month:02}{day:02}-{hour:02}{minute:02}{second:02}")
}

fn artifact_display_label(display_name: &str) -> String {
    let mut label = String::new();
    let mut separator = false;
    for character in display_name.trim().chars() {
        if character.is_alphanumeric() || matches!(character, '-' | '_') {
            if separator && !label.is_empty() {
                label.push('-');
            }
            separator = false;
            label.push(character);
        } else {
            separator = true;
        }
        if label.chars().count() >= 64 {
            break;
        }
    }
    let label = label.chars().take(48).collect::<String>();
    let label = label.trim_matches('-');
    if label.is_empty() {
        "unnamed".into()
    } else {
        label.into()
    }
}

fn artifact_identifier(identifier: &str) -> String {
    let digest = Sha256::digest(identifier.as_bytes());
    hex::encode(&digest[..3])
}

fn absolute_path(path: &Path) -> Result<PathBuf, VaultError> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    std::env::current_dir()
        .map(|directory| directory.join(path))
        .map_err(|error| io_error(path, error))
}

fn validate_passphrase(passphrase: &[u8]) -> Result<(), VaultError> {
    if passphrase.is_empty() || passphrase.len() > MAX_PASSPHRASE_BYTES {
        return Err(VaultError::InvalidPassphrase);
    }
    Ok(())
}

fn sibling_with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut value: OsString = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn directory_has_entries(path: &Path) -> Result<bool, VaultError> {
    if !path.exists() {
        return Ok(false);
    }
    if !path.is_dir() {
        return Err(VaultError::PlaintextPresent);
    }
    Ok(fs::read_dir(path)
        .map_err(|error| io_error(path, error))?
        .next()
        .transpose()
        .map_err(|error| io_error(path, error))?
        .is_some())
}

fn remove_path_if_exists(path: &Path) -> Result<(), VaultError> {
    if !path.exists() {
        return Ok(());
    }
    if path.is_dir() {
        fs::remove_dir_all(path).map_err(|error| io_error(path, error))
    } else {
        fs::remove_file(path).map_err(|error| io_error(path, error))
    }
}

fn safe_relative_path(path: &Path) -> bool {
    !path.is_absolute()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
}

fn create_secure_directory(path: &Path) -> Result<(), VaultError> {
    fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|error| io_error(path, error))?;
    Ok(())
}

fn ensure_parent_directory(path: &Path) -> Result<(), VaultError> {
    if path.exists() {
        if !path.is_dir() {
            return Err(VaultError::InvalidRoot);
        }
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|error| io_error(path, error))?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|error| io_error(path, error))?;
    Ok(())
}

fn set_file_mode(file: &File, path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(FILE_MODE))
        .map_err(|error| io_error(path, error))?;
    #[cfg(not(unix))]
    let _ = (file, path);
    Ok(())
}

fn set_path_file_mode(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
        .map_err(|error| io_error(path, error))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_parent(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        let parent = path.parent().ok_or(VaultError::InvalidRoot)?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_error(parent, error))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error(path, error))?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn io_error(path: &Path, source: std::io::Error) -> VaultError {
    VaultError::Io {
        path: path.to_path_buf(),
        source,
    }
}

fn unique_contact_rename_path(parent: &Path) -> Result<PathBuf, VaultError> {
    for _ in 0..16 {
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        let candidate = parent.join(format!(".contact-rename-{}", hex::encode(suffix)));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(VaultError::TemporaryPathExists)
}

fn rollback_contact_directory_rename(
    renamed_directory: &Path,
    temporary_directory: &Path,
    previous_directory: &Path,
) -> std::io::Result<()> {
    fs::rename(renamed_directory, temporary_directory)?;
    fs::rename(temporary_directory, previous_directory)
}
