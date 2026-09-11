use commtools_core::deaddrop::{GetReplicaResult, GetReplicaStatus, GetResult};
use commtools_core::offline::{
    OFFLINE_RECOVERY_PROBE_INTERVAL_MS, OfflineContext, OfflineDirection, OfflineIndexSync,
    OfflinePollKind, OfflinePollObservation, OfflinePollOutcome, OfflinePollTarget, OfflineState,
};
use commtools_core::protocol::{Frame, MessageType};

const ALICE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.b32.i2p";
const BOB: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.b32.i2p";

#[test]
fn directional_keys_match_the_established_cross_peer_contract() {
    let alice = context(ALICE, BOB);
    let bob = context(BOB, ALICE);

    assert_eq!(
        alice.directional_key(OfflineDirection::Send, 5),
        "370dfe5c5691de56b93e1e2e8991b9cc659b03b1b9f376bbbf956266c8ce4205"
    );
    assert_eq!(
        alice.directional_key(OfflineDirection::Receive, 5),
        "dd2434ac43da6e91fa294309f74fb1173c01594d22a7ef661d2645b41a1c3d41"
    );
    assert_eq!(
        alice.directional_key(OfflineDirection::Send, 5),
        bob.directional_key(OfflineDirection::Receive, 5)
    );
    assert_eq!(
        alice.directional_key(OfflineDirection::Receive, 5),
        bob.directional_key(OfflineDirection::Send, 5)
    );
    assert!(format!("{alice:?}").contains("<redacted>"));
}

#[test]
fn offline_blobs_round_trip_and_reject_tampering() {
    let alice = context(ALICE, BOB);
    let bob = context(BOB, ALICE);
    let frame = Frame::new(MessageType::U, 42, b"offline text".to_vec());
    let blob = alice.seal_frame(&frame).expect("seal frame");
    assert_eq!(bob.open_frame(&blob).expect("open frame"), frame);

    let mut tampered = blob;
    let last = tampered.last_mut().expect("ciphertext byte");
    *last ^= 1;
    assert!(bob.open_frame(&tampered).is_err());
    assert!(OfflineContext::new([0; 32], ALICE, BOB).is_err());
    assert!(OfflineContext::new([7; 32], ALICE, ALICE).is_err());
}

#[test]
fn index_sync_uses_the_compatible_seventeen_byte_layout() {
    let sync = OfflineIndexSync {
        next_send: 0x0102_0304_0506_0708,
        receive_base: 0x1112_1314_1516_1718,
    };
    let encoded = sync.encode();
    assert_eq!(encoded.len(), 17);
    assert_eq!(encoded[0], 1);
    assert_eq!(OfflineIndexSync::decode(&encoded).expect("decode"), sync);
    assert!(OfflineIndexSync::decode(&encoded[..16]).is_err());

    let mut state = OfflineState::default();
    state.apply_remote_index_sync(OfflineIndexSync {
        next_send: 10,
        receive_base: 4,
    });
    assert_eq!(state.send_index(), 4);
    assert_eq!(state.known_remote_next_send(), 10);
}

#[test]
fn send_index_advances_only_after_matching_confirmation() {
    let context = context(ALICE, BOB);
    let frame = Frame::new(MessageType::U, 7, b"pending".to_vec());
    let mut state = OfflineState::default();
    let pending = state.prepare_send(&context, &frame).expect("prepare");
    assert_eq!(pending.index, 0);
    assert_eq!(state.send_index(), 0);
    assert!(state.confirm_send(1).is_err());
    assert_eq!(state.send_index(), 0);
    state.confirm_send(pending.index).expect("confirm");
    assert_eq!(state.send_index(), 1);
}

#[test]
fn authenticated_replica_hits_are_deduplicated_and_advance_the_window() {
    let alice = context(ALICE, BOB);
    let bob = context(BOB, ALICE);
    let frame = Frame::new(MessageType::U, 99, b"message".to_vec());
    let blob = alice.seal_frame(&frame).expect("blob");
    let target = OfflinePollTarget {
        index: 0,
        key: bob.directional_key(OfflineDirection::Receive, 0),
        kind: OfflinePollKind::Window,
    };
    let replicas = GetResult {
        replicas: vec![
            get_replica("drop-a", GetReplicaStatus::Hit, Some(blob.clone())),
            get_replica("drop-b", GetReplicaStatus::Hit, Some(blob)),
            get_replica("drop-c", GetReplicaStatus::Miss, None),
        ],
    };

    let mut state = OfflineState::default();
    let decoded = state.classify_get_result(&bob, &target, &replicas);
    assert_eq!(
        decoded.observation.outcome,
        OfflinePollOutcome::Authenticated
    );
    assert_eq!(decoded.frames.len(), 1);
    assert_eq!(decoded.frames[0].frame, frame);
    state.finalize_poll_sweep(1_000, &[decoded.observation]);
    assert_eq!(state.receive_base(), 1);
    assert_eq!(state.known_remote_next_send(), 1);

    let replay = state.classify_get_result(&bob, &target, &replicas);
    assert_eq!(
        replay.observation.outcome,
        OfflinePollOutcome::Indeterminate
    );
    assert!(replay.frames.is_empty());
}

#[test]
fn gaps_require_three_confirmed_rounds_and_authenticated_forward_evidence() {
    let mut state = OfflineState::default();
    let miss = OfflinePollObservation {
        index: 0,
        kind: OfflinePollKind::Window,
        outcome: OfflinePollOutcome::ConfirmedMiss,
    };

    for round in 1..=3 {
        state.finalize_poll_sweep(round * 1_000, &[miss.clone()]);
    }
    assert_eq!(state.receive_base(), 0);
    assert_eq!(state.skipped().count(), 0);

    state.apply_remote_index_sync(OfflineIndexSync {
        next_send: 3,
        receive_base: 0,
    });
    state.finalize_poll_sweep(4_000, &[miss.clone()]);
    assert_eq!(state.receive_base(), 1);
    assert_eq!(
        state.skipped().map(|entry| entry.index).collect::<Vec<_>>(),
        vec![0]
    );

    state.record_authenticated(2);
    assert_eq!(state.receive_base(), 1);
    state.record_authenticated(1);
    assert_eq!(state.receive_base(), 3);

    let targets = state.poll_targets(
        &context(BOB, ALICE),
        4_000 + OFFLINE_RECOVERY_PROBE_INTERVAL_MS,
    );
    assert!(
        targets
            .iter()
            .any(|target| { target.index == 0 && target.kind == OfflinePollKind::RecoveryProbe })
    );

    state.finalize_poll_sweep(
        5_000 + OFFLINE_RECOVERY_PROBE_INTERVAL_MS,
        &[OfflinePollObservation {
            index: 0,
            kind: OfflinePollKind::RecoveryProbe,
            outcome: OfflinePollOutcome::Authenticated,
        }],
    );
    assert_eq!(state.receive_base(), 3);
    assert_eq!(state.skipped().count(), 0);
}

#[test]
fn stalled_windows_add_a_forward_probe_without_replacing_normal_targets() {
    let mut state = OfflineState::default();
    let observations = [OfflinePollObservation {
        index: 0,
        kind: OfflinePollKind::Window,
        outcome: OfflinePollOutcome::ConfirmedMiss,
    }];
    for round in 1..=3 {
        state.finalize_poll_sweep(round * 1_000, &observations);
    }
    assert_eq!(state.stalled_sweeps(), 3);

    let targets = state.poll_targets(&context(BOB, ALICE), 10_000);
    assert_eq!(
        targets
            .iter()
            .filter(|target| target.kind == OfflinePollKind::Window)
            .count(),
        8
    );
    assert!(
        targets
            .iter()
            .any(|target| { target.index == 8 && target.kind == OfflinePollKind::ForwardProbe })
    );
}

#[test]
fn invalid_hits_are_indeterminate_and_do_not_create_gap_evidence() {
    let context = context(BOB, ALICE);
    let target = OfflinePollTarget {
        index: 0,
        key: context.directional_key(OfflineDirection::Receive, 0),
        kind: OfflinePollKind::Window,
    };
    let result = GetResult {
        replicas: vec![
            get_replica("drop-a", GetReplicaStatus::Hit, Some(vec![1, 2, 3])),
            get_replica("drop-b", GetReplicaStatus::Miss, None),
        ],
    };
    let mut state = OfflineState::default();
    let classified = state.classify_get_result(&context, &target, &result);
    assert_eq!(
        classified.observation.outcome,
        OfflinePollOutcome::Indeterminate
    );
    assert_eq!(classified.rejected_blobs.len(), 1);
    state.finalize_poll_sweep(1_000, &[classified.observation]);
    assert_eq!(state.missing().count(), 0);
}

fn context(my_b32: &str, peer_b32: &str) -> OfflineContext {
    OfflineContext::new([7; 32], my_b32, peer_b32).expect("offline context")
}

fn get_replica(server: &str, status: GetReplicaStatus, blob: Option<Vec<u8>>) -> GetReplicaResult {
    GetReplicaResult {
        server: server.to_string(),
        status,
        blob,
        latency_ms: 1,
        detail: match status {
            GetReplicaStatus::Hit => "OK",
            GetReplicaStatus::Miss => "MISS",
            GetReplicaStatus::Rejected => "ERR",
            GetReplicaStatus::Failed => "failed",
        }
        .to_string(),
    }
}
