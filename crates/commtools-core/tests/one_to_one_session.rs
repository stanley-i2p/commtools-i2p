use commtools_core::one_to_one::{
    CollisionWinner, ConnectionDirection, ConnectionId, DisconnectReason, GRACEFUL_CLOSE_DELAY_MS,
    HEARTBEAT_PING_INTERVAL_MS, HEARTBEAT_PONG_PREFIX, HEARTBEAT_TIMEOUT_MS,
    ONE_TO_ONE_CONNECT_RETRY_MS, ONE_TO_ONE_CONNECT_TIMEOUT_MS, ONE_TO_ONE_HANDSHAKE_TIMEOUT_MS,
    OneToOneAction, OneToOneConfig, OneToOneEvent, OneToOneOutput, OneToOnePhase, OneToOneSession,
    PinnedPeer, QUIT_SIGNAL,
};
use commtools_core::protocol::{Frame, MessageType};
use commtools_core::sam::destination_to_b32;

const ALICE_DESTINATION: &str = "YWJj";
const BOB_DESTINATION: &str = "ZGVm";
const CAROL_DESTINATION: &str = "Z2hp";

#[test]
fn outbound_and_inbound_peers_complete_the_same_secure_session() {
    let (alice, mut bob, alice_connection, bob_connection, ready_at) = ready_pair();

    assert_eq!(alice.phase(), OneToOnePhase::Ready);
    assert_eq!(bob.phase(), OneToOnePhase::Ready);
    assert_eq!(
        alice.connection_direction(),
        Some(ConnectionDirection::Outbound)
    );
    assert_eq!(
        bob.connection_direction(),
        Some(ConnectionDirection::Inbound)
    );

    let encrypted = alice
        .seal_application_frame(MessageType::U, 91, b"confidential message")
        .expect("seal application frame");
    assert_ne!(encrypted.payload, b"confidential message");
    let receive = bob.receive_frame(bob_connection, encrypted.clone(), ready_at + 1);
    assert!(receive.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::ApplicationFrame { connection_id, frame }
            if *connection_id == bob_connection && frame == &encrypted
    )));
    let opened = bob
        .open_application_frame(&encrypted)
        .expect("open application frame");
    assert_eq!(opened.payload, b"confidential message");

    let reverse = bob
        .seal_application_frame(MessageType::I, 92, b"index sync")
        .expect("seal reverse frame");
    assert_eq!(
        alice
            .open_application_frame(&reverse)
            .expect("open reverse frame")
            .payload,
        b"index sync"
    );
    assert_eq!(alice.active_connection_id(), Some(alice_connection));
}

#[test]
fn delivery_acknowledgements_are_plaintext_and_strictly_sized() {
    let (alice, bob, _alice_connection, _bob_connection, _ready_at) = ready_pair();
    let delivered_message_id = 91_u64;
    let payload = delivered_message_id.to_be_bytes();

    let acknowledgement = alice
        .seal_application_frame(MessageType::D, 93, &payload)
        .expect("seal delivery acknowledgement");
    assert_eq!(acknowledgement.payload, payload);
    assert_eq!(
        bob.open_application_frame(&acknowledgement)
            .expect("open delivery acknowledgement")
            .payload,
        payload
    );

    assert!(matches!(
        alice.seal_application_frame(MessageType::D, 94, &[0; 7]),
        Err(commtools_core::one_to_one::OneToOneError::InvalidDeliveryAcknowledgementLength(7))
    ));
    assert!(matches!(
        bob.open_application_frame(&Frame::new(MessageType::D, 95, [0; 9])),
        Err(commtools_core::one_to_one::OneToOneError::InvalidDeliveryAcknowledgementLength(9))
    ));
}

#[test]
fn inline_image_terminators_are_plaintext_empty_frames() {
    let (alice, bob, _alice_connection, _bob_connection, _ready_at) = ready_pair();
    let terminator = alice
        .seal_application_frame(MessageType::Z, 96, &[])
        .expect("seal image terminator");

    assert!(terminator.payload.is_empty());
    assert_eq!(
        bob.open_application_frame(&terminator)
            .expect("open image terminator"),
        terminator
    );
    assert!(matches!(
        alice.seal_application_frame(MessageType::Z, 97, b"unexpected"),
        Err(commtools_core::one_to_one::OneToOneError::InvalidImageTerminator)
    ));
}

#[test]
fn file_frames_match_the_live_transfer_wire_contract() {
    let (alice, bob, _alice_connection, _bob_connection, _ready_at) = ready_pair();
    let header = b"notes.txt|42";
    let sealed = alice
        .file_frame_sealer()
        .expect("file sealer")
        .seal(MessageType::F, header)
        .expect("seal file header");

    assert_eq!(sealed.message_id, 0);
    assert_ne!(sealed.payload, header);
    assert_eq!(
        bob.open_application_frame(&sealed)
            .expect("open file header")
            .payload,
        header
    );

    let terminator = alice
        .seal_application_frame(MessageType::E, 0, &[])
        .expect("seal file terminator");
    assert!(terminator.payload.is_empty());
    assert_eq!(
        bob.open_application_frame(&terminator)
            .expect("open file terminator"),
        terminator
    );
    assert!(matches!(
        alice.seal_application_frame(MessageType::E, 0, b"unexpected"),
        Err(commtools_core::one_to_one::OneToOneError::InvalidFileTerminator)
    ));
}

#[test]
fn inline_image_headers_remain_aead_protected() {
    let (alice, bob, _alice_connection, _bob_connection, _ready_at) = ready_pair();
    let plaintext = b"preview.png|image/png|128";
    let sealed = alice
        .seal_application_frame(MessageType::J, 98, plaintext)
        .expect("seal image header");

    assert_ne!(sealed.payload, plaintext);
    assert_eq!(
        bob.open_application_frame(&sealed)
            .expect("open image header")
            .payload,
        plaintext
    );
}

#[test]
fn simultaneous_connect_collision_has_one_deterministic_winner() {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");

    let alice_output = collision_input(ALICE_DESTINATION, &bob_b32, BOB_DESTINATION, 11);
    let bob_output = collision_input(BOB_DESTINATION, &alice_b32, ALICE_DESTINATION, 22);

    let (lower_output, higher_output) = if alice_b32 < bob_b32 {
        (alice_output, bob_output)
    } else {
        (bob_output, alice_output)
    };

    assert!(lower_output.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::CloseConnection { connection_id }
            if *connection_id == ConnectionId::new(11)
                || *connection_id == ConnectionId::new(22)
    )));
    assert!(lower_output.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::CollisionResolved {
            winner: CollisionWinner::Outbound,
            kept_connection: None,
            closed_connection: Some(_),
        }
    )));
    assert!(
        higher_output
            .actions
            .iter()
            .any(|action| matches!(action, OneToOneAction::CancelConnect { .. }))
    );
    assert!(higher_output.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::CollisionResolved {
            winner: CollisionWinner::Inbound,
            kept_connection: Some(_),
            closed_connection: None,
        }
    )));
}

#[test]
fn a_stale_outbound_result_is_closed_after_inbound_wins() {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let (higher_destination, lower_destination, lower_b32) = if alice_b32 > bob_b32 {
        (ALICE_DESTINATION, BOB_DESTINATION, bob_b32)
    } else {
        (BOB_DESTINATION, ALICE_DESTINATION, alice_b32)
    };
    let mut session = session(higher_destination, None);
    let attempt = connect_attempt(&mut session, &lower_b32);
    let incoming = ConnectionId::new(7);
    let accepted = session.incoming_connected(incoming, &lower_b32, lower_destination, 1_000);
    assert!(accepted.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::CancelConnect { attempt_id } if *attempt_id == attempt
    )));

    let stale = ConnectionId::new(8);
    let result = session.outbound_connected(attempt, stale, &lower_b32, 1_001);
    assert_eq!(
        result.actions,
        vec![OneToOneAction::CloseConnection {
            connection_id: stale
        }]
    );
    assert_eq!(session.pending_connection_id(), Some(incoming));
}

#[test]
fn collision_rule_is_preserved_when_outbound_stream_finishes_first() {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let (higher_destination, lower_destination, lower_b32) = if alice_b32 > bob_b32 {
        (ALICE_DESTINATION, BOB_DESTINATION, bob_b32)
    } else {
        (BOB_DESTINATION, ALICE_DESTINATION, alice_b32)
    };
    let mut higher = session(higher_destination, None);
    let attempt = connect_attempt(&mut higher, &lower_b32);
    let outbound = ConnectionId::new(31);
    higher.outbound_connected(attempt, outbound, &lower_b32, 1_000);
    assert_eq!(higher.phase(), OneToOnePhase::Handshaking);

    let inbound = ConnectionId::new(32);
    let collision = higher.incoming_connected(inbound, &lower_b32, lower_destination, 1_001);
    assert_eq!(higher.phase(), OneToOnePhase::IncomingPending);
    assert_eq!(higher.pending_connection_id(), Some(inbound));
    assert!(collision.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::CloseConnection { connection_id } if *connection_id == outbound
    )));
    assert!(collision.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::CollisionResolved {
            winner: CollisionWinner::Inbound,
            kept_connection: Some(kept),
            closed_connection: Some(closed),
        } if *kept == inbound && *closed == outbound
    )));
}

#[test]
fn pinned_contacts_reject_wrong_stream_and_framed_identities() {
    let bob_pin = PinnedPeer::new(BOB_DESTINATION).expect("bob pin");
    let mut alice = session(ALICE_DESTINATION, Some(bob_pin.clone()));
    let carol_b32 = destination_to_b32(CAROL_DESTINATION).expect("carol b32");
    let rejected =
        alice.incoming_connected(ConnectionId::new(4), &carol_b32, CAROL_DESTINATION, 1_000);
    assert!(rejected.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::ConnectionRejected {
            reason: DisconnectReason::IdentityMismatch,
            ..
        }
    )));

    let attempt = connect_attempt(&mut alice, bob_pin.b32());
    let connection = ConnectionId::new(5);
    alice.outbound_connected(attempt, connection, bob_pin.b32(), 2_000);
    let mismatch = alice.receive_frame(
        connection,
        Frame::new(MessageType::S, 1, CAROL_DESTINATION),
        2_001,
    );
    assert!(mismatch.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::Disconnected {
            reason: DisconnectReason::IdentityMismatch,
            ..
        }
    )));
    assert_eq!(alice.phase(), OneToOnePhase::Closing);
}

#[test]
fn application_frames_are_rejected_until_identity_and_key_are_complete() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let attempt = connect_attempt(&mut alice, &bob_b32);
    let connection = ConnectionId::new(10);
    alice.outbound_connected(attempt, connection, &bob_b32, 1_000);

    let output = alice.receive_frame(
        connection,
        Frame::new(MessageType::U, 4, b"not ready"),
        1_001,
    );
    assert!(output.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::FrameRejected { connection_id, .. }
            if *connection_id == connection
    )));
    assert!(
        alice
            .seal_application_frame(MessageType::U, 5, b"not ready")
            .is_err()
    );
}

#[test]
fn rendezvous_control_proofs_precede_identity_and_key_frames() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let proof = "__SIGNAL__:RENDEZVOUS:one-time-proof".to_string();
    let begin = alice
        .begin_connect_with_control_signals(&bob_b32, vec![proof.clone()])
        .expect("begin authenticated connect");
    let attempt = begin
        .actions
        .iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(*attempt_id),
            _ => None,
        })
        .expect("connect action");
    let connected = alice.outbound_connected(attempt, ConnectionId::new(15), &bob_b32, 1_000);
    let frames = handshake_frames(&connected);
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0].message_type, MessageType::S);
    assert_eq!(frames[0].payload, proof.as_bytes());
    assert_eq!(frames[1].payload, ALICE_DESTINATION.as_bytes());
    assert_eq!(frames[2].message_type, MessageType::K);

    let mut invalid = session(ALICE_DESTINATION, None);
    assert!(
        invalid
            .begin_connect_with_control_signals(&bob_b32, vec!["not-a-signal".to_string()])
            .is_err()
    );
}

#[test]
fn heartbeat_uses_any_received_frame_as_liveness_and_times_out_at_35_seconds() {
    let (mut alice, _bob, alice_connection, _bob_connection, ready_at) = ready_pair();

    assert!(
        alice
            .tick(ready_at + HEARTBEAT_PING_INTERVAL_MS - 1)
            .actions
            .is_empty()
    );
    let ping = alice.tick(ready_at + HEARTBEAT_PING_INTERVAL_MS);
    assert!(ping.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::SendFrame { connection_id, frame }
            if *connection_id == alice_connection
                && frame.message_type == MessageType::S
                && String::from_utf8_lossy(&frame.payload).contains("PING")
    )));

    let activity_at = ready_at + HEARTBEAT_PING_INTERVAL_MS + 1;
    alice.receive_frame(
        alice_connection,
        Frame::new(
            MessageType::S,
            44,
            format!("{HEARTBEAT_PONG_PREFIX}000000000000002c"),
        ),
        activity_at,
    );
    assert!(
        alice
            .tick(activity_at + HEARTBEAT_TIMEOUT_MS - 1)
            .events
            .iter()
            .all(|event| !matches!(
                event,
                OneToOneEvent::Disconnected {
                    reason: DisconnectReason::HeartbeatTimeout,
                    ..
                }
            ))
    );

    let timeout = alice.tick(activity_at + HEARTBEAT_TIMEOUT_MS);
    assert!(timeout.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::Disconnected {
            reason: DisconnectReason::HeartbeatTimeout,
            ..
        }
    )));
    assert_eq!(alice.phase(), OneToOnePhase::Closing);
    alice.connection_closed(alice_connection);
    assert_eq!(alice.phase(), OneToOnePhase::Standby);
}

#[test]
fn incomplete_handshakes_have_a_bounded_lifetime() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let attempt = connect_attempt(&mut alice, &bob_b32);
    let connection = ConnectionId::new(12);
    let started_at = 500;
    alice.outbound_connected(attempt, connection, &bob_b32, started_at);

    assert!(
        alice
            .tick(started_at + ONE_TO_ONE_HANDSHAKE_TIMEOUT_MS - 1)
            .actions
            .is_empty()
    );
    let timeout = alice.tick(started_at + ONE_TO_ONE_HANDSHAKE_TIMEOUT_MS);
    assert!(timeout.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::Disconnected {
            reason: DisconnectReason::HandshakeTimeout,
            ..
        }
    )));
    assert_eq!(
        timeout.actions,
        vec![OneToOneAction::CloseConnection {
            connection_id: connection
        }]
    );
}

#[test]
fn graceful_shutdown_emits_quit_before_transport_close() {
    let (mut alice, _bob, alice_connection, _bob_connection, _ready_at) = ready_pair();
    let shutdown = alice.begin_shutdown();
    assert_eq!(alice.phase(), OneToOnePhase::Closed);
    assert!(shutdown.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::NotifyAndClose {
            connection_id,
            frame,
            delay_ms,
        } if *connection_id == alice_connection
            && frame.message_type == MessageType::S
            && frame.payload == QUIT_SIGNAL.as_bytes()
            && *delay_ms == GRACEFUL_CLOSE_DELAY_MS
    )));
    assert!(alice.begin_connect("invalid").is_err());
}

#[test]
fn disconnect_notifies_the_peer_and_returns_the_open_session_to_standby() {
    let (mut alice, _bob, alice_connection, _bob_connection, _ready_at) = ready_pair();

    let disconnect = alice.disconnect();
    assert_eq!(alice.phase(), OneToOnePhase::Closing);
    assert!(disconnect.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::NotifyAndClose {
            connection_id,
            frame,
            delay_ms,
        } if *connection_id == alice_connection
            && frame.message_type == MessageType::S
            && frame.payload == QUIT_SIGNAL.as_bytes()
            && *delay_ms == GRACEFUL_CLOSE_DELAY_MS
    )));

    let closed = alice.connection_closed(alice_connection);
    assert_eq!(alice.phase(), OneToOnePhase::Standby);
    assert!(
        closed
            .events
            .iter()
            .any(|event| matches!(event, OneToOneEvent::PhaseChanged(OneToOnePhase::Standby)))
    );
}

#[test]
fn disconnect_during_connect_closes_a_late_successful_stream() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let attempt = connect_attempt(&mut alice, &bob_b32);

    let disconnect = alice.disconnect();
    assert_eq!(alice.phase(), OneToOnePhase::Standby);
    assert!(disconnect.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::CancelConnect { attempt_id } if *attempt_id == attempt
    )));

    let late_connection = ConnectionId::new(41);
    let late = alice.outbound_connected(attempt, late_connection, &bob_b32, 1_100);
    assert_eq!(
        late.actions,
        vec![OneToOneAction::CloseConnection {
            connection_id: late_connection,
        }]
    );
    assert_eq!(alice.phase(), OneToOnePhase::Standby);
}

#[test]
fn temporary_leaseset_failure_retries_without_leaving_connecting() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let started_ms = 1_000;
    let initial = alice
        .begin_connect_at(&bob_b32, started_ms)
        .expect("begin connect");
    let attempt = initial
        .actions
        .iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(*attempt_id),
            _ => None,
        })
        .expect("initial connect action");

    let failed = alice.outbound_failed_at(
        attempt,
        "STREAM STATUS RESULT=CANT_REACH_PEER MESSAGE=\"LeaseSet not found\"",
        started_ms + 1_000,
    );
    assert_eq!(alice.phase(), OneToOnePhase::Connecting);
    assert!(failed.actions.is_empty());
    assert!(failed.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::ConnectRetryScheduled { attempt_id, .. } if *attempt_id == attempt
    )));

    assert!(
        alice
            .tick(started_ms + 1_000 + ONE_TO_ONE_CONNECT_RETRY_MS - 1)
            .actions
            .is_empty()
    );
    let retry = alice.tick(started_ms + 1_000 + ONE_TO_ONE_CONNECT_RETRY_MS);
    assert!(retry.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::Connect { attempt_id, peer_b32 }
            if *attempt_id != attempt && peer_b32 == &bob_b32
    )));
    assert_eq!(alice.phase(), OneToOnePhase::Connecting);
}

#[test]
fn permanent_connect_failure_returns_to_standby_without_retry() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let attempt = alice
        .begin_connect_at(&bob_b32, 1_000)
        .expect("begin connect")
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("connect action");

    let failed = alice.outbound_failed_at(attempt, "SAM I/O error: Broken pipe", 2_000);
    assert_eq!(alice.phase(), OneToOnePhase::Standby);
    assert!(failed.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::ConnectFailed { reason, .. } if reason.contains("Broken pipe")
    )));
    assert!(alice.tick(20_000).actions.is_empty());
}

#[test]
fn temporary_connect_retries_stop_at_the_overall_deadline() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let started_ms = 1_000;
    let attempt = alice
        .begin_connect_at(&bob_b32, started_ms)
        .expect("begin connect")
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("connect action");
    alice.outbound_failed_at(attempt, "LeaseSet not found", started_ms + 1_000);

    let expired = alice.tick(started_ms + ONE_TO_ONE_CONNECT_TIMEOUT_MS);
    assert_eq!(alice.phase(), OneToOnePhase::Standby);
    assert!(expired.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::ConnectFailed { reason, .. }
            if reason.contains("connection deadline expired")
    )));
    assert!(
        alice
            .tick(started_ms + ONE_TO_ONE_CONNECT_TIMEOUT_MS + 1)
            .actions
            .is_empty()
    );
}

#[test]
fn in_flight_connect_is_cancelled_at_the_overall_deadline() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let started_ms = 1_000;
    let attempt = alice
        .begin_connect_at(&bob_b32, started_ms)
        .expect("begin connect")
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("connect action");

    let expired = alice.tick(started_ms + ONE_TO_ONE_CONNECT_TIMEOUT_MS);

    assert!(expired.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::CancelConnect { attempt_id } if *attempt_id == attempt
    )));
    assert_eq!(alice.phase(), OneToOnePhase::Standby);
}

#[test]
fn disconnect_cancels_the_retry_intent() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut alice = session(ALICE_DESTINATION, None);
    let attempt = alice
        .begin_connect_at(&bob_b32, 1_000)
        .expect("begin connect")
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("connect action");
    alice.outbound_failed_at(attempt, "LeaseSet not found", 2_000);

    alice.disconnect();

    assert_eq!(alice.phase(), OneToOnePhase::Standby);
    assert!(
        alice
            .tick(2_000 + ONE_TO_ONE_CONNECT_RETRY_MS)
            .actions
            .is_empty()
    );
}

#[test]
fn retry_preserves_pre_handshake_rendezvous_signals() {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let proof = "__SIGNAL__:RENDEZVOUS:test-proof".to_string();
    let mut alice = session(ALICE_DESTINATION, None);
    let initial = alice
        .begin_connect_with_control_signals_at(&bob_b32, vec![proof.clone()], 1_000)
        .expect("begin rendezvous connect");
    let initial_attempt = initial
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("initial connect action");
    alice.outbound_failed_at(initial_attempt, "LeaseSet not found", 2_000);
    let retry = alice.tick(2_000 + ONE_TO_ONE_CONNECT_RETRY_MS);
    let retry_attempt = retry
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("retry connect action");

    let connected = alice.outbound_connected(
        retry_attempt,
        ConnectionId::new(73),
        &bob_b32,
        2_001 + ONE_TO_ONE_CONNECT_RETRY_MS,
    );
    let frames = handshake_frames(&connected);
    assert_eq!(
        frames.first().map(|frame| frame.payload.as_slice()),
        Some(proof.as_bytes())
    );
}

#[test]
fn a_ready_verified_peer_can_become_the_exact_live_tofu_pin() {
    let (mut alice, _bob, alice_connection, _bob_connection, _ready_at) = ready_pair();
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");

    let pin = alice
        .active_peer_pin_candidate()
        .expect("verified peer pin candidate");
    assert_eq!(pin.b32(), bob_b32);
    assert_eq!(pin.destination(), BOB_DESTINATION);
    alice.pin_active_peer(pin.clone()).expect("pin peer");
    assert_eq!(alice.config().pinned_peer(), Some(&pin));
    assert!(matches!(
        alice.active_peer_pin_candidate(),
        Err(commtools_core::one_to_one::OneToOneError::PeerAlreadyPinned)
    ));

    alice.disconnect();
    alice.connection_closed(alice_connection);
    let carol_b32 = destination_to_b32(CAROL_DESTINATION).expect("carol b32");
    let rejected =
        alice.incoming_connected(ConnectionId::new(42), &carol_b32, CAROL_DESTINATION, 2_000);
    assert!(rejected.actions.iter().any(|action| matches!(
        action,
        OneToOneAction::CloseConnection { connection_id }
            if *connection_id == ConnectionId::new(42)
    )));
    assert!(rejected.events.iter().any(|event| matches!(
        event,
        OneToOneEvent::ConnectionRejected {
            reason: DisconnectReason::IdentityMismatch,
            ..
        }
    )));
}

#[test]
fn a_peer_cannot_be_pinned_before_secure_identity_verification() {
    let alice = session(ALICE_DESTINATION, None);
    assert!(matches!(
        alice.active_peer_pin_candidate(),
        Err(commtools_core::one_to_one::OneToOneError::SessionNotReady)
    ));
}

fn ready_pair() -> (
    OneToOneSession,
    OneToOneSession,
    ConnectionId,
    ConnectionId,
    u64,
) {
    let mut alice = session(ALICE_DESTINATION, None);
    let mut bob = session(BOB_DESTINATION, None);
    let alice_b32 = alice.config().local_b32().to_string();
    let bob_b32 = bob.config().local_b32().to_string();
    let alice_connection = ConnectionId::new(1);
    let bob_connection = ConnectionId::new(2);
    let started_at = 1_000;

    let attempt = connect_attempt(&mut alice, &bob_b32);
    let alice_connected = alice.outbound_connected(attempt, alice_connection, &bob_b32, started_at);
    let alice_handshake = handshake_frames(&alice_connected);

    bob.incoming_connected(bob_connection, &alice_b32, ALICE_DESTINATION, started_at);
    for frame in alice_handshake {
        bob.receive_frame(bob_connection, frame, started_at + 1);
    }

    let bob_accepted = bob.accept_incoming(started_at + 2).expect("accept call");
    let bob_handshake = handshake_frames(&bob_accepted);
    assert!(bob.is_ready());
    for frame in bob_handshake {
        alice.receive_frame(alice_connection, frame, started_at + 2);
    }
    assert!(alice.is_ready());

    (alice, bob, alice_connection, bob_connection, started_at + 2)
}

fn session(local_destination: &str, pinned_peer: Option<PinnedPeer>) -> OneToOneSession {
    OneToOneSession::new(
        OneToOneConfig::new(local_destination, pinned_peer)
            .expect("session config")
            .with_control_message_seed(100),
    )
}

fn connect_attempt(session: &mut OneToOneSession, peer_b32: &str) -> u64 {
    session
        .begin_connect(peer_b32)
        .expect("begin connect")
        .actions
        .into_iter()
        .find_map(|action| match action {
            OneToOneAction::Connect { attempt_id, .. } => Some(attempt_id),
            _ => None,
        })
        .expect("connect action")
}

fn handshake_frames(output: &OneToOneOutput) -> Vec<Frame> {
    output
        .actions
        .iter()
        .find_map(|action| match action {
            OneToOneAction::SendHandshake { frames, .. } => Some(frames.clone()),
            _ => None,
        })
        .expect("handshake action")
}

fn collision_input(
    local_destination: &str,
    peer_b32: &str,
    peer_destination: &str,
    incoming_id: u64,
) -> OneToOneOutput {
    let mut session = session(local_destination, None);
    connect_attempt(&mut session, peer_b32);
    session.incoming_connected(
        ConnectionId::new(incoming_id),
        peer_b32,
        peer_destination,
        1_000,
    )
}
