use commtools_core::ids::{ContactId, GroupId};
use commtools_core::storage::{
    ContactRecord, DeaddropServerStat, GroupRecord, PersistentIdentity, TofuPeerPin,
};
use commtools_core::vault::{
    MIN_ARGON2_ITERATIONS, MIN_ARGON2_MEMORY_KIB, VaultError, VaultKdfParams, VaultRepository,
};
use commtools_core::{HistoryRecord, HistoryScope};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[test]
fn vault_round_trip_exposes_plaintext_only_while_unlocked() {
    let temp = TestDirectory::new("round-trip");
    let repository = test_repository(temp.path());
    let mut vault = repository.create(b"correct passphrase").expect("create");
    let contact_id = ContactId::new("alice-contact").expect("contact id");
    let contact = ContactRecord::new(contact_id.clone(), "Unique Alice Marker").expect("contact");
    vault.snapshot_mut().contacts.insert(contact_id, contact);
    vault.commit().expect("commit contact");
    vault
        .history_repository()
        .expect("history repository")
        .append_message(
            &HistoryScope::Contact("Unique Alice Marker".into()),
            &HistoryRecord {
                created_ms: 1,
                timestamp_utc: "12:00:00 UTC".into(),
                author: "Alice".into(),
                sender_b32: None,
                text: "vault-protected history marker".into(),
                mine: false,
                offline: false,
                msg_id: Some(7),
                delivered: false,
                group_expected_acks: Vec::new(),
                group_received_acks: Vec::new(),
            },
        )
        .expect("append history");
    assert_eq!(vault.snapshot().revision(), 2);
    fs::write(
        vault.files_dir().join("received-map.bin"),
        b"received file bytes",
    )
    .expect("received file fixture");
    assert!(
        temp.path()
            .join("profiles/Unique Alice Marker/Unique Alice Marker.dat")
            .is_file()
    );
    vault.lock().expect("lock vault");

    assert!(!temp.path().exists());
    let bytes = fs::read(vault_path(temp.path())).expect("encrypted vault");
    assert!(!contains(&bytes, b"Unique Alice Marker"));
    assert!(!contains(&bytes, b"alice-contact"));
    assert!(!contains(&bytes, b"vault-protected history marker"));

    let unlocked = repository.unlock(b"correct passphrase").expect("unlock");
    assert_eq!(unlocked.snapshot().revision(), 2);
    assert_eq!(
        fs::read(unlocked.files_dir().join("received-map.bin")).expect("restored file"),
        b"received file bytes"
    );
    assert_eq!(
        unlocked
            .snapshot()
            .contacts
            .values()
            .next()
            .expect("contact")
            .display_name,
        "Unique Alice Marker"
    );
    let history = unlocked
        .history_repository()
        .expect("history repository")
        .load(&HistoryScope::Contact("Unique Alice Marker".into()))
        .expect("restored history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].text, "vault-protected history marker");
}

#[test]
fn wrong_passphrases_and_ciphertext_tampering_fail_authentication() {
    let temp = TestDirectory::new("authentication");
    let repository = test_repository(temp.path());
    repository
        .create(b"right passphrase")
        .expect("create")
        .lock()
        .expect("lock vault");

    assert!(matches!(
        repository.unlock(b"wrong passphrase"),
        Err(VaultError::AuthenticationFailed)
    ));

    let latest = vault_path(temp.path());
    let mut bytes = fs::read(&latest).expect("read generation");
    *bytes.last_mut().expect("ciphertext byte") ^= 1;
    fs::write(&latest, bytes).expect("tamper generation");
    assert!(matches!(
        repository.unlock(b"right passphrase"),
        Err(VaultError::AuthenticationFailed)
    ));
}

#[test]
fn passphrase_rotation_protects_the_newest_generation_with_the_new_key() {
    let temp = TestDirectory::new("rotation");
    let repository = test_repository(temp.path());
    let mut vault = repository.create(b"old passphrase").expect("create");
    vault
        .rotate_passphrase(b"new passphrase")
        .expect("rotate passphrase");
    assert_eq!(vault.snapshot().revision(), 1);
    vault.lock().expect("lock rotated vault");

    assert!(matches!(
        repository.unlock(b"old passphrase"),
        Err(VaultError::AuthenticationFailed)
    ));
    assert!(repository.unlock(b"new passphrase").is_ok());
}

#[test]
fn plaintext_recovery_state_is_not_overwritten_by_unlock() {
    let temp = TestDirectory::new("plaintext-recovery");
    let repository = test_repository(temp.path());
    repository
        .create(b"passphrase")
        .expect("create")
        .lock()
        .expect("lock");
    fs::create_dir_all(temp.path()).expect("recovery plaintext");
    fs::write(temp.path().join("recovery-marker"), b"keep me").expect("recovery marker");
    assert!(matches!(
        repository.unlock(b"passphrase"),
        Err(VaultError::PlaintextPresent)
    ));
    assert!(temp.path().join("recovery-marker").is_file());
}

#[test]
fn vault_lease_excludes_a_second_process_owner() {
    let temp = TestDirectory::new("exclusive-lease");
    let repository = test_repository(temp.path());
    let lease = repository.try_acquire_lease().expect("first lease");

    assert_eq!(lease.path(), lock_path(temp.path()));
    assert!(matches!(
        repository.try_acquire_lease(),
        Err(VaultError::AlreadyInUse)
    ));

    drop(lease);
    assert!(repository.try_acquire_lease().is_ok());
}

#[test]
fn incomplete_sibling_temporary_file_does_not_replace_the_vault() {
    let temp = TestDirectory::new("temporary-file");
    let repository = test_repository(temp.path());
    let mut vault = repository.create(b"passphrase").expect("create");
    vault.commit().expect("revision two");
    vault.commit().expect("revision three");
    vault.lock().expect("lock");
    let temporary = PathBuf::from(format!("{}.vault.tmp-crashed", temp.path().display()));
    fs::write(&temporary, b"partial").expect("temporary file");

    assert_eq!(
        repository
            .unlock(b"passphrase")
            .expect("unlock")
            .snapshot()
            .revision(),
        1
    );
    let _ = fs::remove_file(temporary);
}

#[test]
fn failed_transaction_does_not_mutate_the_unlocked_snapshot() {
    let temp = TestDirectory::new("transaction-rollback");
    let repository = test_repository(temp.path());
    let mut vault = repository.create(b"passphrase").expect("create");
    let first_id = ContactId::new("first-contact").expect("first id");
    let second_id = ContactId::new("second-contact").expect("second id");

    let result = vault.update(|snapshot| {
        snapshot.contacts.insert(
            first_id.clone(),
            ContactRecord::new(first_id, "Duplicate").expect("first contact"),
        );
        snapshot.contacts.insert(
            second_id.clone(),
            ContactRecord::new(second_id, "duplicate").expect("second contact"),
        );
        Ok(())
    });

    assert!(matches!(result, Err(VaultError::Storage(_))));
    assert!(vault.snapshot().contacts.is_empty());
    assert_eq!(vault.snapshot().revision(), 1);
}

#[test]
fn encrypted_backup_restores_validated_state_and_optional_files() {
    let temp = TestDirectory::new("backup-round-trip");
    let repository = test_repository(temp.path());
    let backup = temp.path().with_extension("ctbak");
    let mut vault = repository.create(b"vault passphrase").expect("create");
    let contact_id = ContactId::new("backup-contact").expect("contact id");
    let group_id = GroupId::new("backup-group").expect("group id");
    vault
        .update(|snapshot| {
            snapshot.contacts.insert(
                contact_id.clone(),
                ContactRecord::new(contact_id.clone(), "Backup Alice")?,
            );
            snapshot.groups.insert(
                group_id.clone(),
                GroupRecord::new(group_id.clone(), "Backup group")?,
            );
            Ok(())
        })
        .expect("store contact");
    fs::write(vault.files_dir().join("received.bin"), b"original file").expect("file fixture");
    vault
        .export_backup(&backup, b"backup passphrase", true)
        .expect("export backup");
    assert!(matches!(
        vault.restore_backup(&backup, b"wrong passphrase", true),
        Err(VaultError::AuthenticationFailed)
    ));

    vault
        .update(|snapshot| {
            snapshot.contacts.clear();
            snapshot.groups.clear();
            Ok(())
        })
        .expect("mutate vault");
    fs::write(vault.files_dir().join("received.bin"), b"changed file").expect("change file");
    vault
        .restore_backup(&backup, b"backup passphrase", true)
        .expect("restore backup");

    assert!(vault.snapshot().contacts.contains_key(&contact_id));
    assert!(vault.snapshot().groups.contains_key(&group_id));
    assert_eq!(
        fs::read(vault.files_dir().join("received.bin")).expect("restored file"),
        b"original file"
    );
    vault
        .update(|snapshot| {
            snapshot.contacts.clear();
            snapshot.groups.clear();
            Ok(())
        })
        .expect("mutate vault again");
    fs::write(
        vault.files_dir().join("received.bin"),
        b"locally retained file",
    )
    .expect("replace local file");
    vault
        .restore_backup(&backup, b"backup passphrase", false)
        .expect("restore without files");
    assert!(vault.snapshot().contacts.contains_key(&contact_id));
    assert!(vault.snapshot().groups.contains_key(&group_id));
    assert_eq!(
        fs::read(vault.files_dir().join("received.bin")).expect("retained file"),
        b"locally retained file"
    );
    let encrypted = fs::read(&backup).expect("read backup");
    assert!(!contains(&encrypted, b"Backup Alice"));
    let _ = fs::remove_file(backup);
}

#[test]
fn repository_wipe_removes_plaintext_and_encrypted_generations() {
    let temp = TestDirectory::new("wipe-all");
    let repository = test_repository(temp.path());
    repository
        .create(b"vault passphrase")
        .expect("create")
        .lock()
        .expect("lock");
    assert!(repository.vault_path().is_file());

    repository.wipe_all().expect("wipe");

    assert!(!temp.path().exists());
    assert!(!repository.vault_path().exists());
}

#[test]
fn backup_cannot_be_written_inside_the_live_vault() {
    let temp = TestDirectory::new("backup-path-guard");
    let repository = test_repository(temp.path());
    let mut vault = repository.create(b"vault passphrase").expect("create");
    let path = temp.path().join("unsafe.ctbak");

    assert!(matches!(
        vault.export_backup(&path, b"backup passphrase", true),
        Err(VaultError::BackupPathConflictsWithVault)
    ));
}

#[test]
fn contact_reset_preserves_identity_and_transport_configuration() {
    let temp = TestDirectory::new("contact-reset");
    let repository = test_repository(temp.path());
    let mut vault = repository.create(b"vault passphrase").expect("create");
    let contact_id = ContactId::new("reset-contact").expect("contact id");
    let b32 = commtools_core::sam::destination_to_b32("YWJj").expect("b32");
    let mut contact = ContactRecord::new(contact_id.clone(), "Reset Alice").expect("contact");
    contact.identity = Some(PersistentIdentity::new("YWJj", &b32).expect("identity"));
    contact.tofu_peer = Some(TofuPeerPin::new(&b32, "YWJj").expect("peer pin"));
    contact.history_enabled = true;
    contact.deaddrop_stats.insert(
        contact.deaddrop_servers[0].clone(),
        DeaddropServerStat {
            put_ok: 1,
            ..DeaddropServerStat::default()
        },
    );
    let expected_identity = contact.identity.clone();
    let expected_tunnels = contact.tunnels;
    let expected_servers = contact.deaddrop_servers.clone();
    vault
        .update(|snapshot| {
            snapshot.contacts.insert(contact_id.clone(), contact);
            Ok(())
        })
        .expect("store contact");
    vault
        .history_repository()
        .expect("history repository")
        .append_message(
            &HistoryScope::Contact("Reset Alice".into()),
            &HistoryRecord {
                created_ms: 1,
                timestamp_utc: "00:00:01 UTC".into(),
                author: "Alice".into(),
                sender_b32: None,
                text: "remove this".into(),
                mine: false,
                offline: false,
                msg_id: Some(1),
                delivered: false,
                group_expected_acks: Vec::new(),
                group_received_acks: Vec::new(),
            },
        )
        .expect("history fixture");

    vault.reset_contact(&contact_id).expect("reset contact");

    let reset = &vault.snapshot().contacts[&contact_id];
    assert_eq!(reset.identity, expected_identity);
    assert_eq!(reset.tunnels, expected_tunnels);
    assert_eq!(reset.deaddrop_servers, expected_servers);
    assert!(reset.tofu_peer.is_none());
    assert!(reset.offline.is_none());
    assert!(!reset.history_enabled);
    assert!(reset.deaddrop_stats.is_empty());
    assert!(
        vault
            .history_repository()
            .expect("history repository")
            .load(&HistoryScope::Contact("Reset Alice".into()))
            .expect("load history")
            .is_empty()
    );
}

#[test]
fn encrypted_contact_backup_requires_confirmed_replacement_and_restores_history() {
    let source_temp = TestDirectory::new("contact-backup-source");
    let source_repository = test_repository(source_temp.path());
    let backup = source_temp.path().with_extension("ctcontact");
    let mut source = source_repository
        .create(b"source vault passphrase")
        .expect("create source");
    let imported_id = ContactId::new("portable-contact").expect("contact id");
    let mut imported = ContactRecord::new(imported_id.clone(), "Portable Alice").expect("contact");
    let local_b32 = commtools_core::sam::destination_to_b32("YWJj").expect("local b32");
    imported.identity =
        Some(PersistentIdentity::new("YWJj", &local_b32).expect("persistent identity"));
    let expected_identity = imported.identity.clone();
    source
        .update(|snapshot| {
            snapshot.contacts.insert(imported_id.clone(), imported);
            Ok(())
        })
        .expect("store source contact");
    source
        .history_repository()
        .expect("history repository")
        .append_message(
            &HistoryScope::Contact("Portable Alice".into()),
            &HistoryRecord {
                created_ms: 7,
                timestamp_utc: "00:00:07 UTC".into(),
                author: "Alice".into(),
                sender_b32: None,
                text: "portable history".into(),
                mine: false,
                offline: false,
                msg_id: Some(7),
                delivered: false,
                group_expected_acks: Vec::new(),
                group_received_acks: Vec::new(),
            },
        )
        .expect("history fixture");
    source
        .export_contact_backup(&imported_id, &backup, b"contact passphrase", true)
        .expect("export contact");

    let target_temp = TestDirectory::new("contact-backup-target");
    let target_repository = test_repository(target_temp.path());
    let mut target = target_repository
        .create(b"target vault passphrase")
        .expect("create target");
    let replaced_id = ContactId::new("existing-contact").expect("existing id");
    target
        .update(|snapshot| {
            snapshot.contacts.insert(
                replaced_id.clone(),
                ContactRecord::new(replaced_id.clone(), "portable alice")?,
            );
            Ok(())
        })
        .expect("store conflicting contact");

    let inspection = target
        .inspect_contact_backup(&backup, b"contact passphrase")
        .expect("inspect contact");
    assert_eq!(inspection.contact_id, imported_id);
    assert_eq!(inspection.display_name, "Portable Alice");
    assert!(inspection.includes_history);
    assert_eq!(inspection.replacement_contact_id, Some(replaced_id.clone()));
    assert!(matches!(
        target.import_contact_backup(&backup, b"contact passphrase", false),
        Err(VaultError::ContactImportRequiresReplacement)
    ));

    let restored_id = target
        .import_contact_backup(&backup, b"contact passphrase", true)
        .expect("replace contact");
    assert_eq!(restored_id, imported_id);
    assert!(!target.snapshot().contacts.contains_key(&replaced_id));
    assert_eq!(
        target.snapshot().contacts[&imported_id].identity,
        expected_identity
    );
    let history = target
        .history_repository()
        .expect("history repository")
        .load(&HistoryScope::Contact("Portable Alice".into()))
        .expect("load imported history");
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].text, "portable history");
    let encrypted = fs::read(&backup).expect("read contact backup");
    assert!(!contains(&encrypted, b"Portable Alice"));
    assert!(!contains(&encrypted, b"portable history"));
    let _ = fs::remove_file(backup);
}

fn test_repository(root: &Path) -> VaultRepository {
    let params = VaultKdfParams::new(MIN_ARGON2_MEMORY_KIB, MIN_ARGON2_ITERATIONS, 1)
        .expect("test KDF parameters");
    VaultRepository::with_kdf(root, params).expect("repository")
}

fn vault_path(root: &Path) -> PathBuf {
    PathBuf::from(format!("{}.vault", root.display()))
}

fn lock_path(root: &Path) -> PathBuf {
    PathBuf::from(format!("{}.app.lock", root.display()))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "commtools-core-vault-{label}-{}-{sequence}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
        let _ = fs::remove_file(vault_path(&self.path));
        let _ = fs::remove_file(lock_path(&self.path));
    }
}
