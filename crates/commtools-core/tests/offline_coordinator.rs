use commtools_core::deaddrop::{
    GetReplicaResult, GetReplicaStatus, GetResult, PutResult, PutStatus,
};
use commtools_core::offline::{OfflineContext, OfflineState};
use commtools_core::offline_coordinator::{
    OFFLINE_POLL_INTERVAL_MS, OfflineCoordinator, OfflineCoordinatorAction,
    OfflineCoordinatorEvent, OfflineCoordinatorMode, OfflineOperationId,
};
use commtools_core::one_to_one::{
    ConnectionId, OneToOneAction, OneToOneConfig, OneToOneOutput, OneToOneSession, PinnedPeer,
};
use commtools_core::protocol::{Frame, MessageType};
use commtools_core::sam::destination_to_b32;
use commtools_core::storage::PersistedOfflineState;

const ALICE_DESTINATION: &str = "YWJj";
const BOB_DESTINATION: &str = "ZGVm";
const SHARED_SECRET: [u8; 32] = [7; 32];

#[test]
fn put_confirmation_advances_and_persists_exactly_once() {
    let (alice_b32, bob_b32) = peer_b32s();
    let mut coordinator = coordinator(&alice_b32, &bob_b32);
    coordinator.enter_offline().expect("enter offline");

    let started = coordinator
        .begin_send(Frame::new(MessageType::U, 41, b"queued message"))
        .expect("begin offline send");
    let (operation_id, index) = put_action(&started);
    assert_eq!(index, 0);
    assert_eq!(coordinator.state().send_index(), 0);

    let completed = coordinator
        .put_completed(operation_id, stored_result(), 1_000)
        .expect("complete put");
    assert_eq!(coordinator.state().send_index(), 1);
    assert!(completed.events.iter().any(|event| matches!(
        event,
        OfflineCoordinatorEvent::SendConfirmed {
            message_id: 41,
            index: 0,
            status: PutStatus::Stored,
            ..
        }
    )));
    let persisted = persisted_action(&completed);
    assert_eq!(persisted.restore().expect("restore").send_index(), 1);

    let restarted = OfflineCoordinator::from_persisted(&alice_b32, &bob_b32, &persisted)
        .expect("restart coordinator");
    assert_eq!(restarted.state().send_index(), 1);
}

#[test]
fn failed_put_does_not_advance_or_persist_the_send_index() {
    let (alice_b32, bob_b32) = peer_b32s();
    let mut coordinator = coordinator(&alice_b32, &bob_b32);
    coordinator.enter_offline().expect("enter offline");
    let started = coordinator
        .begin_send(Frame::new(MessageType::U, 42, b"retry me"))
        .expect("begin offline send");
    let (operation_id, _) = put_action(&started);

    let failed = coordinator
        .put_completed(
            operation_id,
            PutResult {
                status: PutStatus::Failed,
                successful_servers: Vec::new(),
                replicas: Vec::new(),
            },
            1_000,
        )
        .expect("complete failed put");
    assert_eq!(coordinator.state().send_index(), 0);
    assert!(failed.events.iter().any(|event| matches!(
        event,
        OfflineCoordinatorEvent::SendFailed {
            message_id: 42,
            index: 0,
            ..
        }
    )));
    assert!(
        failed
            .actions
            .iter()
            .all(|action| !matches!(action, OfflineCoordinatorAction::PersistState { .. }))
    );
}

#[test]
fn poll_sweeps_are_sequential_persist_received_frames_and_respect_cadence() {
    let (alice_b32, bob_b32) = peer_b32s();
    let sender_context =
        OfflineContext::new(SHARED_SECRET, &alice_b32, &bob_b32).expect("sender context");
    let frame = Frame::new(MessageType::U, 77, b"offline hello");
    let sender_target = OfflineState::default()
        .prepare_send(&sender_context, &frame)
        .expect("sender target");

    let mut receiver = coordinator(&bob_b32, &alice_b32);
    receiver.enter_offline().expect("enter offline");
    let started_at = 10_000;
    let first = receiver.tick(started_at).expect("start poll");
    assert!(first.events.iter().any(|event| matches!(
        event,
        OfflineCoordinatorEvent::PollSweepStarted { started_ms }
            if *started_ms == started_at
    )));
    let (mut operation_id, mut target) = get_action(&first);
    assert_eq!(target.index, 0);
    assert_eq!(target.key, sender_target.key);

    let mut received = false;
    let mut final_output = None;
    for step in 0..receiver.state().window() {
        let result = if target.index == 0 {
            GetResult {
                replicas: vec![get_replica(
                    "drop-a",
                    GetReplicaStatus::Hit,
                    Some(sender_target.blob.clone()),
                )],
            }
        } else {
            GetResult {
                replicas: vec![get_replica("drop-a", GetReplicaStatus::Miss, None)],
            }
        };
        let output = receiver
            .get_completed(operation_id, result, started_at + u64::from(step) + 1)
            .expect("complete get");
        received |= output.events.iter().any(|event| {
            matches!(
                event,
                OfflineCoordinatorEvent::FrameReceived {
                    index: 0,
                    frame: received_frame,
                    ..
                } if received_frame == &frame
            )
        });
        if let Some(next) = output.actions.iter().find_map(as_get_action) {
            (operation_id, target) = next;
        } else {
            final_output = Some(output);
            break;
        }
    }

    let final_output = final_output.expect("completed sweep");
    assert!(received);
    assert_eq!(receiver.state().receive_base(), 1);
    assert!(final_output.events.iter().any(|event| matches!(
        event,
        OfflineCoordinatorEvent::PollSweepCompleted { observations, .. }
            if observations.len() == 8
    )));
    let persisted = persisted_action(&final_output);
    assert_eq!(persisted.restore().expect("restore").receive_base(), 1);

    let completed_at = started_at + u64::from(receiver.state().window());
    assert!(
        receiver
            .tick(completed_at + OFFLINE_POLL_INTERVAL_MS - 1)
            .expect("early tick")
            .actions
            .is_empty()
    );
    assert!(matches!(
        receiver
            .tick(completed_at + OFFLINE_POLL_INTERVAL_MS)
            .expect("due tick")
            .actions
            .first(),
        Some(OfflineCoordinatorAction::Get { .. })
    ));
}

#[test]
fn authenticated_receive_is_persisted_before_the_poll_sweep_finishes() {
    let (alice_b32, bob_b32) = peer_b32s();
    let sender_context =
        OfflineContext::new(SHARED_SECRET, &alice_b32, &bob_b32).expect("sender context");
    let sender_target = OfflineState::default()
        .prepare_send(
            &sender_context,
            &Frame::new(MessageType::U, 78, b"persist before close"),
        )
        .expect("sender target");

    let mut receiver = coordinator(&bob_b32, &alice_b32);
    receiver.enter_offline().expect("enter offline");
    let poll = receiver.tick(10_000).expect("start poll");
    let (operation_id, target) = get_action(&poll);
    assert_eq!(target.index, 0);

    let received = receiver
        .get_completed(
            operation_id,
            GetResult {
                replicas: vec![get_replica(
                    "drop-a",
                    GetReplicaStatus::Hit,
                    Some(sender_target.blob),
                )],
            },
            10_001,
        )
        .expect("complete authenticated get");

    assert!(received.actions.iter().any(|action| matches!(
        action,
        OfflineCoordinatorAction::Get { target, .. } if target.index == 1
    )));
    let persisted = persisted_action(&received);
    assert_eq!(persisted.restore().expect("restore").receive_base(), 1);

    receiver.begin_shutdown();
    let restarted = OfflineCoordinator::from_persisted(&bob_b32, &alice_b32, &persisted)
        .expect("restart from persisted state");
    assert_eq!(restarted.state().receive_base(), 1);
}

#[test]
fn put_temporarily_pauses_a_poll_between_keys() {
    let (alice_b32, bob_b32) = peer_b32s();
    let mut coordinator = coordinator(&alice_b32, &bob_b32);
    coordinator.enter_offline().expect("enter offline");
    let poll = coordinator.tick(1_000).expect("start poll");
    let (get_id, _) = get_action(&poll);

    let send = coordinator
        .begin_send(Frame::new(MessageType::U, 99, b"outgoing"))
        .expect("begin send during poll");
    let (put_id, _) = put_action(&send);
    let paused = coordinator
        .get_completed(
            get_id,
            GetResult {
                replicas: vec![get_replica("drop-a", GetReplicaStatus::Miss, None)],
            },
            1_001,
        )
        .expect("complete current get");
    assert!(
        paused
            .actions
            .iter()
            .all(|action| !matches!(action, OfflineCoordinatorAction::Get { .. }))
    );

    let resumed = coordinator
        .put_completed(put_id, stored_result(), 1_002)
        .expect("complete put");
    assert!(matches!(
        resumed
            .actions
            .iter()
            .find(|action| matches!(action, OfflineCoordinatorAction::Get { .. })),
        Some(OfflineCoordinatorAction::Get { .. })
    ));
}

#[test]
fn leaving_offline_finishes_the_current_get_without_scheduling_another() {
    let (alice_b32, bob_b32) = peer_b32s();
    let mut coordinator = coordinator(&alice_b32, &bob_b32);
    coordinator.enter_offline().expect("enter offline");
    let poll = coordinator.tick(1_000).expect("start poll");
    let (get_id, _) = get_action(&poll);

    let leaving = coordinator.leave_offline().expect("leave offline");
    assert_eq!(coordinator.mode(), OfflineCoordinatorMode::Standby);
    assert!(leaving.actions.is_empty());

    let completed = coordinator
        .get_completed(
            get_id,
            GetResult {
                replicas: vec![get_replica("drop-a", GetReplicaStatus::Miss, None)],
            },
            1_001,
        )
        .expect("complete in-flight get after leaving offline");
    assert!(
        completed
            .actions
            .iter()
            .all(|action| !matches!(action, OfflineCoordinatorAction::Get { .. }))
    );
    assert!(completed.events.iter().any(|event| matches!(
        event,
        OfflineCoordinatorEvent::PollSweepCompleted { observations, .. }
            if observations.len() == 1
    )));
    let _ = persisted_action(&completed);
}

#[test]
fn index_sync_is_strictly_encrypted_bound_to_the_pinned_session_and_persisted() {
    let (alice_session, bob_session, alice_connection, _bob_connection) = ready_pinned_pair();
    let alice_b32 = alice_session.config().local_b32().to_string();
    let bob_b32 = bob_session.config().local_b32().to_string();
    let mut alice = coordinator(&alice_b32, &bob_b32);
    alice.enter_offline().expect("enter offline");
    let send = alice
        .begin_send(Frame::new(MessageType::U, 1, b"advance index"))
        .expect("begin send");
    let (put_id, _) = put_action(&send);
    alice
        .put_completed(put_id, stored_result(), 1_000)
        .expect("confirm send");
    alice.leave_offline().expect("leave offline");

    let prepared = alice
        .prepare_index_sync(&alice_session, 500)
        .expect("prepare sync");
    let encrypted = prepared
        .actions
        .iter()
        .find_map(|action| match action {
            OfflineCoordinatorAction::SendIndexSync {
                connection_id,
                frame,
            } if *connection_id == alice_connection => Some(frame.clone()),
            _ => None,
        })
        .expect("encrypted index sync");
    assert_eq!(encrypted.message_type, MessageType::I);
    assert_ne!(encrypted.payload, alice.state().index_sync().encode());
    alice
        .index_sync_sent(alice_connection)
        .expect("mark sync sent");
    assert!(
        alice
            .prepare_index_sync(&alice_session, 501)
            .expect("deduplicate sync")
            .actions
            .is_empty()
    );

    let mut bob = coordinator(&bob_b32, &alice_b32);
    let applied = bob
        .receive_index_sync(&bob_session, &encrypted)
        .expect("apply sync");
    assert_eq!(bob.state().known_remote_next_send(), 1);
    assert!(applied.events.iter().any(|event| matches!(
        event,
        OfflineCoordinatorEvent::IndexSyncApplied {
            remote_next_send: 1,
            known_remote_next_send: 1,
            ..
        }
    )));
    persisted_action(&applied);

    alice.live_connection_closed(alice_connection);
    assert!(matches!(
        alice
            .prepare_index_sync(&alice_session, 502)
            .expect("resync after reconnect notification")
            .actions
            .first(),
        Some(OfflineCoordinatorAction::SendIndexSync { .. })
    ));
}

fn coordinator(my_b32: &str, peer_b32: &str) -> OfflineCoordinator {
    OfflineCoordinator::new(SHARED_SECRET, my_b32, peer_b32, OfflineState::default())
        .expect("offline coordinator")
}

fn peer_b32s() -> (String, String) {
    (
        destination_to_b32(ALICE_DESTINATION).expect("alice b32"),
        destination_to_b32(BOB_DESTINATION).expect("bob b32"),
    )
}

fn put_action(output: &commtools_core::OfflineCoordinatorOutput) -> (OfflineOperationId, u64) {
    output
        .actions
        .iter()
        .find_map(|action| match action {
            OfflineCoordinatorAction::Put {
                operation_id,
                target,
            } => Some((*operation_id, target.index)),
            _ => None,
        })
        .expect("put action")
}

fn get_action(
    output: &commtools_core::OfflineCoordinatorOutput,
) -> (
    OfflineOperationId,
    commtools_core::offline::OfflinePollTarget,
) {
    output
        .actions
        .iter()
        .find_map(as_get_action)
        .expect("get action")
}

fn as_get_action(
    action: &OfflineCoordinatorAction,
) -> Option<(
    OfflineOperationId,
    commtools_core::offline::OfflinePollTarget,
)> {
    match action {
        OfflineCoordinatorAction::Get {
            operation_id,
            target,
        } => Some((*operation_id, target.clone())),
        _ => None,
    }
}

fn persisted_action(output: &commtools_core::OfflineCoordinatorOutput) -> PersistedOfflineState {
    output
        .actions
        .iter()
        .find_map(|action| match action {
            OfflineCoordinatorAction::PersistState { state, .. } => Some(state.clone()),
            _ => None,
        })
        .expect("persist action")
}

fn stored_result() -> PutResult {
    PutResult {
        status: PutStatus::Stored,
        successful_servers: vec!["drop-a".into()],
        replicas: Vec::new(),
    }
}

fn get_replica(server: &str, status: GetReplicaStatus, blob: Option<Vec<u8>>) -> GetReplicaResult {
    GetReplicaResult {
        server: server.into(),
        status,
        blob,
        latency_ms: 1,
        detail: match status {
            GetReplicaStatus::Hit => "OK",
            GetReplicaStatus::Miss => "MISS",
            GetReplicaStatus::Rejected => "ERR",
            GetReplicaStatus::Failed => "failed",
        }
        .into(),
    }
}

fn ready_pinned_pair() -> (OneToOneSession, OneToOneSession, ConnectionId, ConnectionId) {
    let alice_pin = PinnedPeer::new(BOB_DESTINATION).expect("bob pin");
    let bob_pin = PinnedPeer::new(ALICE_DESTINATION).expect("alice pin");
    let mut alice = OneToOneSession::new(
        OneToOneConfig::new(ALICE_DESTINATION, Some(alice_pin)).expect("alice config"),
    );
    let mut bob = OneToOneSession::new(
        OneToOneConfig::new(BOB_DESTINATION, Some(bob_pin)).expect("bob config"),
    );
    let alice_b32 = alice.config().local_b32().to_string();
    let bob_b32 = bob.config().local_b32().to_string();
    let alice_connection = ConnectionId::new(11);
    let bob_connection = ConnectionId::new(12);

    let attempt = alice
        .begin_connect(&bob_b32)
        .expect("begin connect")
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("connect attempt");
    let alice_connected = alice.outbound_connected(attempt, alice_connection, &bob_b32, 1_000);
    let alice_handshake = handshake_frames(&alice_connected);

    bob.incoming_connected(bob_connection, &alice_b32, ALICE_DESTINATION, 1_000);
    for frame in alice_handshake {
        bob.receive_frame(bob_connection, frame, 1_001);
    }
    let bob_accepted = bob.accept_incoming(1_002).expect("accept incoming");
    for frame in handshake_frames(&bob_accepted) {
        alice.receive_frame(alice_connection, frame, 1_002);
    }
    assert!(alice.is_ready());
    assert!(bob.is_ready());
    (alice, bob, alice_connection, bob_connection)
}

fn handshake_frames(output: &OneToOneOutput) -> Vec<Frame> {
    output
        .actions
        .iter()
        .find_map(|action| match action {
            OneToOneAction::SendHandshake { frames, .. } => Some(frames.clone()),
            _ => None,
        })
        .expect("handshake frames")
}
