use commtools_core::ids::{ContactId, GroupId};
use commtools_core::offline::{OfflineIndexSync, OfflineState};
use commtools_core::storage::{
    ContactRecord, GroupRecord, PersistedOfflineState, PersistentIdentity, SecretBytes32,
    SecretText, StorageError, StorageRepository, StorageSnapshot, TofuPeerPin, TunnelSettings,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p";
const BOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.b32.i2p";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[test]
fn records_round_trip_through_icedcomm_compatible_directories() {
    let temp = TestDirectory::new("round-trip");
    let repository = StorageRepository::new(temp.path()).expect("repository");
    let mut snapshot = populated_snapshot();

    repository.commit(&mut snapshot).expect("first commit");
    assert_eq!(snapshot.revision(), 1);
    let loaded = repository.load().expect("load").expect("stored snapshot");
    assert_eq!(loaded.revision(), 1);
    assert_eq!(loaded.contacts.len(), 1);
    assert_eq!(loaded.groups.len(), 1);

    let contact = loaded.contacts.values().next().expect("contact");
    let offline = contact.offline.as_ref().expect("offline state");
    assert_eq!(offline.shared_secret.expose_secret(), &[7; 32]);
    let restored = offline.restore().expect("restore offline state");
    assert_eq!(restored.send_index(), 4);
    assert_eq!(restored.known_remote_next_send(), 11);
    assert_eq!(restored.snapshot(), offline.state);

    assert!(temp.path().join("app_config.json").is_file());
    assert!(temp.path().join("profiles/Alice/Alice.dat").is_file());
    assert!(
        temp.path()
            .join(format!("groups/{ALICE}/group.json"))
            .is_file()
    );
    assert!(temp.path().join("files").is_dir());
    assert!(temp.path().join(".commtools-storage.json").is_file());

    let history = temp.path().join("profiles/Alice/history.jsonl");
    fs::write(&history, b"preserve existing history").expect("history fixture");
    repository.commit(&mut snapshot).expect("second commit");
    assert_eq!(
        fs::read(&history).expect("preserved history"),
        b"preserve existing history"
    );
}

#[test]
fn stale_writers_cannot_overwrite_a_newer_revision() {
    let temp = TestDirectory::new("stale-writer");
    let repository = StorageRepository::new(temp.path()).expect("repository");
    let mut first = StorageSnapshot::new();
    let mut stale = first.clone();

    repository.commit(&mut first).expect("first commit");
    let error = repository
        .commit(&mut stale)
        .expect_err("stale commit must fail");
    assert!(matches!(
        error,
        StorageError::RevisionConflict {
            expected: 0,
            actual: 1
        }
    ));
    assert_eq!(stale.revision(), 0);
    assert_eq!(
        repository
            .load()
            .expect("load committed storage")
            .expect("committed snapshot")
            .revision(),
        1
    );
}

#[test]
fn malformed_manifest_is_reported_instead_of_silently_resetting_storage() {
    let temp = TestDirectory::new("corrupt-latest");
    let repository = StorageRepository::new(temp.path()).expect("repository");
    let mut snapshot = StorageSnapshot::new();
    repository.commit(&mut snapshot).expect("revision one");
    let manifest = temp.path().join(".commtools-storage.json");
    fs::write(&manifest, b"not json").expect("corrupt manifest");
    assert!(matches!(repository.load(), Err(StorageError::Decode(_))));
}

#[test]
fn unrelated_temporary_files_do_not_change_the_committed_revision() {
    let temp = TestDirectory::new("abandoned-temporary");
    let repository = StorageRepository::new(temp.path()).expect("repository");
    let mut snapshot = StorageSnapshot::new();
    repository.commit(&mut snapshot).expect("revision one");
    fs::write(
        temp.path().join(".commtools-storage.tmp-crashed"),
        b"partial",
    )
    .expect("write abandoned temporary file");

    let loaded = repository.load().expect("load").expect("snapshot");
    assert_eq!(loaded.revision(), 1);
}

#[test]
fn validation_rejects_unsafe_or_inconsistent_records() {
    assert!(ContactRecord::new(ContactId::new("default").unwrap(), "default").is_err());
    assert!(
        TunnelSettings {
            length: 0,
            quantity: 3,
        }
        .validate()
        .is_err()
    );

    let mut snapshot = StorageSnapshot::new();
    let contact = ContactRecord::new(ContactId::new("alice-id").unwrap(), "Alice").unwrap();
    snapshot
        .contacts
        .insert(ContactId::new("different-id").unwrap(), contact);
    assert!(snapshot.validate().is_err());
}

#[test]
fn new_contacts_receive_the_predefined_deaddrop_servers() {
    let contact = ContactRecord::new(ContactId::new("alice-id").unwrap(), "Alice").unwrap();

    assert_eq!(
        contact.deaddrop_servers,
        commtools_core::DEFAULT_DEADDROP_SERVERS
            .iter()
            .map(|server| (*server).to_string())
            .collect::<Vec<_>>()
    );
}

#[test]
fn deaddrop_server_input_is_normalized_before_storage() {
    let expected = commtools_core::DEFAULT_DEADDROP_SERVERS[0];
    let input = format!("  {}  ", expected.to_ascii_uppercase());

    assert_eq!(
        commtools_core::normalize_deaddrop_server(&input).unwrap(),
        expected
    );
}

#[test]
fn secret_debug_output_is_redacted() {
    let bytes = SecretBytes32::new([9; 32]).expect("secret bytes");
    let text = SecretText::new("do-not-print-this").expect("secret text");
    let identity = PersistentIdentity::new("private-destination", ALICE).expect("identity");

    assert!(!format!("{bytes:?}").contains('9'));
    assert!(!format!("{text:?}").contains("do-not-print-this"));
    assert!(!format!("{identity:?}").contains("private-destination"));
}

#[test]
fn identifier_deserialization_still_enforces_identifier_rules() {
    assert!(serde_json::from_str::<ContactId>(r#""valid-contact""#).is_ok());
    assert!(serde_json::from_str::<ContactId>(r#""""#).is_err());
    assert!(serde_json::from_str::<GroupId>(r#""bad\ngroup""#).is_err());
}

fn populated_snapshot() -> StorageSnapshot {
    let mut offline_state = OfflineState::default();
    offline_state.apply_remote_index_sync(OfflineIndexSync {
        next_send: 11,
        receive_base: 4,
    });

    let contact_id = ContactId::new("alice-contact").expect("contact id");
    let mut contact = ContactRecord::new(contact_id.clone(), "Alice").expect("contact");
    contact.identity = Some(PersistentIdentity::new("alice-private-destination", ALICE).unwrap());
    contact.tofu_peer = Some(TofuPeerPin::new(BOB, "bob-public-destination").unwrap());
    contact.offline = Some(PersistedOfflineState::new([7; 32], &offline_state).unwrap());

    let group_id = GroupId::new(ALICE).expect("group id");
    let group = GroupRecord::new(group_id.clone(), "Core Test Group").expect("group");

    let mut snapshot = StorageSnapshot::new();
    snapshot.contacts.insert(contact_id, contact);
    snapshot.groups.insert(group_id, group);
    snapshot
}

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new(label: &str) -> Self {
        let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "commtools-core-storage-{label}-{}-{sequence}",
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
    }
}
