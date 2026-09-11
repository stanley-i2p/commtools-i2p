use commtools_core::application::{
    ApplicationAction, ApplicationCoordinator, ApplicationCoordinatorError, ApplicationEvent,
    ApplicationPhase, ManagedSessionKey, RendezvousEvent,
};
use commtools_core::deaddrop::{PutResult, PutStatus};
use commtools_core::group_session::{GroupSession, GroupSessionAction, GroupSessionConfig};
use commtools_core::ids::{ContactId, GroupId, SessionId, TransientId};
use commtools_core::offline::OfflineState;
use commtools_core::offline_coordinator::{
    OfflineCoordinator, OfflineCoordinatorAction, OfflineCoordinatorEvent,
};
use commtools_core::one_to_one::{
    ConnectionId, OneToOneAction, OneToOneConfig, OneToOneEvent, OneToOneOutput, OneToOneSession,
    PinnedPeer,
};
use commtools_core::protocol::{Frame, MessageType};
use commtools_core::sam::destination_to_b32;
use commtools_core::storage::GroupMemberRecord;

const ALICE_DESTINATION: &str = "YWJj";
const BOB_DESTINATION: &str = "ZGVm";
const SHARED_SECRET: [u8; 32] = [9; 32];

#[test]
fn multiple_transient_sessions_are_independent_and_have_no_offline_state() {
    let mut coordinator = ApplicationCoordinator::new();
    let first_id = TransientId::new("transient-one").expect("transient id");
    let second_id = TransientId::new("transient-two").expect("transient id");
    let first = coordinator
        .open_transient(
            first_id.clone(),
            unlocked_contact_session(ALICE_DESTINATION),
        )
        .expect("open first transient");
    let second = coordinator
        .open_transient(second_id.clone(), unlocked_contact_session(BOB_DESTINATION))
        .expect("open second transient");
    let first_session = first
        .events
        .iter()
        .find_map(|event| match event {
            ApplicationEvent::SessionOpened {
                session_id,
                key: ManagedSessionKey::Transient(id),
            } if id == &first_id => Some(*session_id),
            _ => None,
        })
        .expect("first session");
    let second_session = second
        .events
        .iter()
        .find_map(|event| match event {
            ApplicationEvent::SessionOpened {
                session_id,
                key: ManagedSessionKey::Transient(id),
            } if id == &second_id => Some(*session_id),
            _ => None,
        })
        .expect("second session");

    assert_ne!(first_session, second_session);
    assert_eq!(
        coordinator.session_for_transient(&first_id),
        Some(first_session)
    );
    assert_eq!(
        coordinator.session_for_transient(&second_id),
        Some(second_session)
    );
    assert!(coordinator.offline_coordinator(first_session).is_none());
    assert!(
        !coordinator
            .generate_contact_rendezvous_request(first_session, 1_000)
            .expect("transient rendezvous request")
            .is_empty()
    );
    assert!(matches!(
        coordinator.enter_contact_offline(first_session),
        Err(ApplicationCoordinatorError::OfflineUnavailable)
    ));

    let closing = coordinator
        .close_session(first_session)
        .expect("close first transient");
    assert!(closing.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::ShutdownSam { session_id } if *session_id == first_session
    )));
    let closed = coordinator
        .sam_shutdown_completed(first_session, Ok(()))
        .expect("finish first transient shutdown");
    assert!(closed.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::SessionClosed {
            session_id,
            key: ManagedSessionKey::Transient(id),
        } if *session_id == first_session && id == &first_id
    )));
    assert_eq!(coordinator.session_for_transient(&first_id), None);
    assert_eq!(
        coordinator.session_for_transient(&second_id),
        Some(second_session)
    );
}

#[test]
fn authenticated_rendezvous_is_bound_to_the_incoming_connection_and_consumed_on_ready() {
    let mut requester = ApplicationCoordinator::new();
    let requester_session = open_contact(
        &mut requester,
        ContactId::new("rendezvous-requester").expect("contact id"),
        unlocked_contact_session(ALICE_DESTINATION),
        None,
    );
    let mut responder = ApplicationCoordinator::new();
    let responder_session = open_contact(
        &mut responder,
        ContactId::new("rendezvous-responder").expect("contact id"),
        unlocked_contact_session(BOB_DESTINATION),
        None,
    );

    let request = requester
        .generate_contact_rendezvous_request(requester_session, 1_000)
        .expect("generate request");
    let response = responder
        .answer_contact_rendezvous_request(responder_session, &request, 1_001)
        .expect("answer request");
    let connecting = requester
        .begin_contact_rendezvous_connect(requester_session, &response, 1_002)
        .expect("begin authenticated connect");
    let attempt_id = connecting
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::OneToOne {
                action: OneToOneAction::Connect { attempt_id, .. },
                ..
            } => Some(*attempt_id),
            _ => None,
        })
        .expect("connect attempt");

    let requester_b32 = destination_to_b32(ALICE_DESTINATION).expect("requester b32");
    let responder_b32 = destination_to_b32(BOB_DESTINATION).expect("responder b32");
    let requester_connection = ConnectionId::new(501);
    let responder_connection = ConnectionId::new(502);
    let requester_connected = requester
        .contact_outbound_connected(
            requester_session,
            attempt_id,
            requester_connection,
            &responder_b32,
            1_003,
        )
        .expect("outbound connected");
    responder
        .contact_incoming_connected(
            responder_session,
            responder_connection,
            &requester_b32,
            ALICE_DESTINATION,
            1_003,
        )
        .expect("incoming connected");

    let requester_frames = application_handshake_frames(&requester_connected);
    assert_eq!(requester_frames.len(), 3);
    let authenticated = responder
        .receive_contact_frame(
            responder_session,
            responder_connection,
            requester_frames[0].clone(),
            1_004,
        )
        .expect("verify proof");
    assert!(authenticated.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::Rendezvous {
            session_id,
            event: RendezvousEvent::IncomingAuthenticated { connection_id, peer_b32 },
        } if *session_id == responder_session
            && *connection_id == responder_connection
            && peer_b32 == &requester_b32
    )));

    for frame in requester_frames.into_iter().skip(1) {
        responder
            .receive_contact_frame(responder_session, responder_connection, frame, 1_005)
            .expect("receive requester handshake");
    }
    let accepted = responder
        .accept_contact_incoming(responder_session, 1_006)
        .expect("accept authenticated caller");
    assert!(accepted.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::Rendezvous {
            session_id,
            event: RendezvousEvent::InvitationConsumed { connection_id, .. },
        } if *session_id == responder_session && *connection_id == responder_connection
    )));
    for frame in application_handshake_frames(&accepted) {
        requester
            .receive_contact_frame(requester_session, requester_connection, frame, 1_006)
            .expect("receive responder handshake");
    }
    assert!(
        requester
            .one_to_one_session(requester_session)
            .is_some_and(OneToOneSession::is_ready)
    );
}

#[test]
fn rendezvous_does_not_replace_locked_contact_connect_policy() {
    let mut application = ApplicationCoordinator::new();
    let session_id = open_contact(
        &mut application,
        ContactId::new("locked-rendezvous").expect("contact id"),
        pinned_contact_session(),
        None,
    );
    assert!(matches!(
        application.generate_contact_rendezvous_request(session_id, 1_000),
        Err(ApplicationCoordinatorError::RendezvousUnavailable)
    ));

    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    assert!(
        application
            .begin_contact_connect(session_id, &bob_b32)
            .is_ok()
    );
}

#[test]
fn malformed_rendezvous_proof_rejects_the_exact_incoming_connection() {
    let mut responder = ApplicationCoordinator::new();
    let session_id = open_contact(
        &mut responder,
        ContactId::new("rendezvous-rejection").expect("contact id"),
        unlocked_contact_session(BOB_DESTINATION),
        None,
    );
    let (_pending, request) = commtools_core::rendezvous::generate_request(1_000).expect("request");
    responder
        .answer_contact_rendezvous_request(session_id, &request, 1_001)
        .expect("answer request");
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let connection_id = ConnectionId::new(601);
    responder
        .contact_incoming_connected(
            session_id,
            connection_id,
            &alice_b32,
            ALICE_DESTINATION,
            1_002,
        )
        .expect("incoming connected");
    let rejected = responder
        .receive_contact_frame(
            session_id,
            connection_id,
            Frame::new(
                MessageType::S,
                1,
                format!("{}invalid", commtools_core::rendezvous::AUTH_SIGNAL_PREFIX),
            ),
            1_003,
        )
        .expect("reject malformed proof");

    assert!(rejected.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::Rendezvous {
            event: RendezvousEvent::AuthenticationRejected {
                connection_id: rejected_connection,
                ..
            },
            ..
        } if *rejected_connection == connection_id
    )));
    assert!(rejected.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::OneToOne {
            action: OneToOneAction::CloseConnection {
                connection_id: rejected_connection,
            },
            ..
        } if *rejected_connection == connection_id
    )));
}

#[test]
fn sessions_are_unique_and_actions_remain_bound_to_their_owner() {
    let mut application = ApplicationCoordinator::new();
    let contact_id = ContactId::new("bob-contact").expect("contact id");
    let group_id = GroupId::new("core-group").expect("group id");
    let contact = open_contact(
        &mut application,
        contact_id.clone(),
        pinned_contact_session(),
        None,
    );
    let group = open_group(&mut application, group_id.clone(), group_session());

    assert!(matches!(
        application.open_contact(contact_id.clone(), pinned_contact_session(), None),
        Err(ApplicationCoordinatorError::ContactAlreadyOpen(id)) if id == contact_id
    ));
    assert!(matches!(
        application.open_group(group_id.clone(), group_session()),
        Err(ApplicationCoordinatorError::GroupAlreadyOpen(id)) if id == group_id
    ));

    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let contact_output = application
        .begin_contact_connect(contact, &bob_b32)
        .expect("contact connect");
    assert!(contact_output.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::OneToOne {
            session_id,
            action: OneToOneAction::Connect { .. },
        } if *session_id == contact
    )));
    assert!(
        contact_output
            .actions
            .iter()
            .all(|action| !matches!(action, ApplicationAction::Group { .. }))
    );

    let group_output = application
        .begin_group_connections(group, 1_000)
        .expect("group connections");
    assert!(group_output.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::Group {
            session_id,
            action: GroupSessionAction::Connect { .. },
        } if *session_id == group
    )));
    assert!(
        group_output
            .actions
            .iter()
            .all(|action| !matches!(action, ApplicationAction::OneToOne { .. }))
    );
}

#[test]
fn contact_disconnect_does_not_close_its_managed_session() {
    let mut application = ApplicationCoordinator::new();
    let contact_id = ContactId::new("disconnect-bob").expect("contact id");
    let contact = open_contact(&mut application, contact_id, pinned_contact_session(), None);
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    application
        .begin_contact_connect(contact, &bob_b32)
        .expect("begin contact connect");

    let disconnected = application
        .disconnect_contact(contact)
        .expect("disconnect contact");
    assert!(disconnected.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::OneToOne {
            session_id,
            action: OneToOneAction::CancelConnect { .. },
        } if *session_id == contact
    )));
    assert!(disconnected.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::OneToOne {
            session_id,
            event: OneToOneEvent::PhaseChanged(
                commtools_core::one_to_one::OneToOnePhase::Standby
            ),
        } if *session_id == contact
    )));
    assert!(application.one_to_one_session(contact).is_some());
}

#[test]
fn locked_contacts_persist_one_authoritative_offline_secret_before_sending_it() {
    let (alice, bob, alice_connection, bob_connection) = ready_pair();
    let alice_is_authority = alice.config().local_b32().to_ascii_lowercase()
        < bob.config().local_b32().to_ascii_lowercase();
    let (authority, receiver, authority_connection, receiver_connection) = if alice_is_authority {
        (alice, bob, alice_connection, bob_connection)
    } else {
        (bob, alice, bob_connection, alice_connection)
    };

    let mut authority_app = ApplicationCoordinator::new();
    let authority_session = open_contact(
        &mut authority_app,
        ContactId::new("offline-authority").expect("contact id"),
        authority,
        None,
    );
    let enrollment = authority_app
        .begin_contact_offline_enrollment(authority_session)
        .expect("begin enrollment");
    assert!(enrollment.actions.iter().all(|action| !matches!(
        action,
        ApplicationAction::OneToOne {
            action: OneToOneAction::SendFrame { .. },
            ..
        }
    )));
    let (enrollment_id, persisted) = enrollment
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::PersistContactOfflineEnrollment {
                enrollment_id,
                state,
                ..
            } => Some((*enrollment_id, state.clone())),
            _ => None,
        })
        .expect("enrollment persistence action");
    let shared_secret = *persisted.shared_secret.expose_secret();
    assert!(shared_secret.iter().any(|byte| *byte != 0));

    let sent = authority_app
        .offline_enrollment_persistence_completed(authority_session, enrollment_id, Ok(()))
        .expect("persist enrollment");
    assert!(sent.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::OfflineEnrollmentPersisted {
            session_id,
            contact_id,
        } if *session_id == authority_session && contact_id.as_str() == "offline-authority"
    )));
    let enrollment_frame = sent
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::OneToOne {
                session_id,
                action:
                    OneToOneAction::SendFrame {
                        connection_id,
                        frame,
                    },
            } if *session_id == authority_session
                && *connection_id == authority_connection
                && frame.message_type == MessageType::X =>
            {
                Some(frame.clone())
            }
            _ => None,
        })
        .expect("encrypted enrollment frame");
    assert_ne!(
        enrollment_frame.payload.as_slice(),
        shared_secret.as_slice()
    );
    let opened_enrollment = receiver
        .open_application_frame(&enrollment_frame)
        .expect("open enrollment frame");
    assert_eq!(
        opened_enrollment.payload.as_slice(),
        shared_secret.as_slice()
    );

    let mut receiver_app = ApplicationCoordinator::new();
    let receiver_session = open_contact(
        &mut receiver_app,
        ContactId::new("offline-receiver").expect("contact id"),
        receiver,
        None,
    );
    let received = receiver_app
        .receive_contact_frame(
            receiver_session,
            receiver_connection,
            enrollment_frame.clone(),
            2_000,
        )
        .expect("receive enrollment");
    let receiver_enrollment_id = received
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::PersistContactOfflineEnrollment {
                enrollment_id,
                state,
                ..
            } if state.shared_secret.expose_secret() == &shared_secret => Some(*enrollment_id),
            _ => None,
        })
        .expect("receiver persistence action");
    receiver_app
        .offline_enrollment_persistence_completed(receiver_session, receiver_enrollment_id, Ok(()))
        .expect("persist received enrollment");

    let duplicate = receiver_app
        .receive_contact_frame(
            receiver_session,
            receiver_connection,
            enrollment_frame,
            2_001,
        )
        .expect("receive duplicate enrollment");
    assert!(duplicate.actions.is_empty());
    assert!(
        duplicate
            .events
            .iter()
            .all(|event| !matches!(event, ApplicationEvent::OperationFailed { .. }))
    );

    let replacement = authority_app
        .one_to_one_session(authority_session)
        .expect("authority session")
        .seal_application_frame(MessageType::X, 991, &[3; 32])
        .expect("seal replacement");
    let rejected = receiver_app
        .receive_contact_frame(receiver_session, receiver_connection, replacement, 2_002)
        .expect("process replacement");
    assert!(rejected.actions.is_empty());
    assert!(rejected.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::OperationFailed {
            operation: "receive offline enrollment",
            reason,
            ..
        } if reason.contains("cannot be replaced")
    )));
}

#[test]
fn non_authoritative_peer_cannot_supply_an_offline_secret() {
    let (alice, bob, alice_connection, bob_connection) = ready_pair();
    let alice_is_authority = alice.config().local_b32().to_ascii_lowercase()
        < bob.config().local_b32().to_ascii_lowercase();
    let (authority, non_authority, authority_connection) = if alice_is_authority {
        (alice, bob, alice_connection)
    } else {
        (bob, alice, bob_connection)
    };
    let forged = non_authority
        .seal_application_frame(MessageType::X, 992, &[4; 32])
        .expect("seal forged enrollment");
    let mut application = ApplicationCoordinator::new();
    let session_id = open_contact(
        &mut application,
        ContactId::new("offline-authority-receiver").expect("contact id"),
        authority,
        None,
    );

    let rejected = application
        .receive_contact_frame(session_id, authority_connection, forged, 2_100)
        .expect("process forged enrollment");
    assert!(rejected.actions.is_empty());
    assert!(rejected.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::OperationFailed {
            operation: "receive offline enrollment",
            reason,
            ..
        } if reason.contains("non-authoritative peer")
    )));
}

#[test]
fn later_locking_non_authority_can_request_the_authoritative_secret() {
    let (alice, bob, alice_connection, bob_connection) = ready_pair();
    let alice_is_authority = alice.config().local_b32().to_ascii_lowercase()
        < bob.config().local_b32().to_ascii_lowercase();
    let (authority, non_authority, authority_connection, non_authority_connection) =
        if alice_is_authority {
            (alice, bob, alice_connection, bob_connection)
        } else {
            (bob, alice, bob_connection, alice_connection)
        };

    let mut requester = ApplicationCoordinator::new();
    let requester_session = open_contact(
        &mut requester,
        ContactId::new("offline-requester").expect("contact id"),
        non_authority,
        None,
    );
    let requested = requester
        .begin_contact_offline_enrollment(requester_session)
        .expect("request enrollment");
    assert!(requested.actions.iter().all(|action| !matches!(
        action,
        ApplicationAction::PersistContactOfflineEnrollment { .. }
    )));
    let request_frame = requested
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::OneToOne {
                session_id,
                action:
                    OneToOneAction::SendFrame {
                        connection_id,
                        frame,
                    },
            } if *session_id == requester_session
                && *connection_id == non_authority_connection
                && frame.message_type == MessageType::S =>
            {
                Some(frame.clone())
            }
            _ => None,
        })
        .expect("offline enrollment request signal");

    let mut authority_app = ApplicationCoordinator::new();
    let authority_session = open_contact(
        &mut authority_app,
        ContactId::new("offline-request-authority").expect("contact id"),
        authority,
        None,
    );
    let answered = authority_app
        .receive_contact_frame(
            authority_session,
            authority_connection,
            request_frame,
            2_200,
        )
        .expect("answer enrollment request");
    assert!(answered.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::PersistContactOfflineEnrollment {
            session_id,
            contact_id,
            ..
        } if *session_id == authority_session
            && contact_id.as_str() == "offline-request-authority"
    )));
}

#[test]
fn offline_operations_are_contact_only_and_persistence_names_the_contact() {
    let mut application = ApplicationCoordinator::new();
    let contact_id = ContactId::new("offline-bob").expect("contact id");
    let (session, offline) = persistent_contact();
    let contact = open_contact(&mut application, contact_id.clone(), session, Some(offline));
    let group = open_group(
        &mut application,
        GroupId::new("group").expect("group id"),
        group_session(),
    );
    assert!(matches!(
        application.enter_contact_offline(group),
        Err(ApplicationCoordinatorError::ExpectedContact(id)) if id == group
    ));

    application
        .enter_contact_offline(contact)
        .expect("enter offline");
    let send = application
        .begin_offline_send(
            contact,
            Frame::new(MessageType::U, 81, b"persistent message"),
        )
        .expect("begin send");
    let operation_id = send
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::Offline {
                session_id,
                action: OfflineCoordinatorAction::Put { operation_id, .. },
            } if *session_id == contact => Some(*operation_id),
            _ => None,
        })
        .expect("offline put action");
    let completed = application
        .offline_put_completed(contact, operation_id, stored_result(), 1_000)
        .expect("complete put");
    let (mutation_id, persisted) = completed
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::PersistContactOffline {
                session_id,
                contact_id: persisted_contact,
                mutation_id,
                state,
            } if *session_id == contact && persisted_contact == &contact_id => {
                Some((*mutation_id, state.clone()))
            }
            _ => None,
        })
        .expect("contact persistence action");
    assert_eq!(persisted.restore().expect("restore").send_index(), 1);
    let acknowledged = application
        .offline_persistence_completed(contact, mutation_id, Ok(()))
        .expect("persistence completion");
    assert!(acknowledged.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::OfflineStatePersisted {
            session_id,
            contact_id: persisted_contact,
            mutation_id: persisted_mutation,
        } if *session_id == contact
            && persisted_contact == &contact_id
            && *persisted_mutation == mutation_id
    )));
}

#[test]
fn contact_protocol_close_finishes_before_sam_shutdown() {
    let (alice, _bob, alice_connection, _bob_connection) = ready_pair();
    let mut application = ApplicationCoordinator::new();
    let contact = open_contact(
        &mut application,
        ContactId::new("ready-bob").expect("contact id"),
        alice,
        None,
    );

    let closing = application.close_session(contact).expect("close contact");
    assert!(closing.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::OneToOne {
            session_id,
            action: OneToOneAction::NotifyAndClose { connection_id, .. },
        } if *session_id == contact && *connection_id == alice_connection
    )));
    assert!(
        closing
            .actions
            .iter()
            .all(|action| !matches!(action, ApplicationAction::ShutdownSam { .. }))
    );

    let transport_closed = application
        .connection_closed(contact, alice_connection)
        .expect("connection closed");
    assert!(transport_closed.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::ShutdownSam { session_id } if *session_id == contact
    )));
    let finished = application
        .sam_shutdown_completed(contact, Ok(()))
        .expect("sam shutdown");
    assert!(finished.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::SessionClosed { session_id, .. } if *session_id == contact
    )));
    assert_eq!(application.session_count(), 0);
}

#[test]
fn global_shutdown_waits_for_sam_and_deaddrop_before_locking_the_vault() {
    let mut application = ApplicationCoordinator::new();
    let (session, offline) = persistent_contact();
    let contact = open_contact(
        &mut application,
        ContactId::new("offline-contact").expect("contact id"),
        session,
        Some(offline),
    );
    let group = open_group(
        &mut application,
        GroupId::new("shutdown-group").expect("group id"),
        group_session(),
    );

    let shutdown = application.begin_shutdown().expect("begin shutdown");
    assert_eq!(application.phase(), ApplicationPhase::StoppingSessions);
    assert_eq!(
        shutdown
            .actions
            .iter()
            .filter(|action| matches!(action, ApplicationAction::ShutdownSam { .. }))
            .count(),
        2
    );
    assert!(shutdown.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::Offline {
            session_id,
            action: OfflineCoordinatorAction::ShutdownDeaddrop,
        } if *session_id == contact
    )));
    assert!(
        shutdown
            .actions
            .iter()
            .all(|action| !matches!(action, ApplicationAction::LockVault))
    );

    application
        .sam_shutdown_completed(contact, Ok(()))
        .expect("contact sam shutdown");
    let group_closed = application
        .sam_shutdown_completed(group, Ok(()))
        .expect("group sam shutdown");
    assert!(
        group_closed
            .actions
            .iter()
            .all(|action| !matches!(action, ApplicationAction::LockVault))
    );
    let contact_closed = application
        .deaddrop_shutdown_completed(contact, Ok(()))
        .expect("deaddrop shutdown");
    assert!(
        contact_closed
            .actions
            .iter()
            .any(|action| matches!(action, ApplicationAction::LockVault))
    );
    assert_eq!(application.phase(), ApplicationPhase::LockingVault);
    assert_eq!(application.session_count(), 0);

    let stopped = application
        .vault_lock_completed(Ok(()))
        .expect("vault locked");
    assert_eq!(application.phase(), ApplicationPhase::Stopped);
    assert_eq!(stopped.events, vec![ApplicationEvent::Stopped]);
}

#[test]
fn offline_binding_must_match_the_exact_pinned_contact() {
    let mut application = ApplicationCoordinator::new();
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let wrong =
        OfflineCoordinator::new(SHARED_SECRET, &bob_b32, &alice_b32, OfflineState::default())
            .expect("wrongly oriented coordinator");
    assert!(matches!(
        application.open_contact(
            ContactId::new("mismatch").expect("contact id"),
            pinned_contact_session(),
            Some(wrong),
        ),
        Err(ApplicationCoordinatorError::OfflineIdentityMismatch)
    ));
}

#[test]
fn encrypted_index_sync_is_consumed_by_the_owning_contact() {
    let (alice, bob, alice_connection, _bob_connection) = ready_pair();
    let alice_b32 = alice.config().local_b32().to_string();
    let bob_b32 = bob.config().local_b32().to_string();
    let mut bob_offline =
        OfflineCoordinator::new(SHARED_SECRET, &bob_b32, &alice_b32, OfflineState::default())
            .expect("bob offline coordinator");
    bob_offline.enter_offline().expect("bob enters offline");
    let send = bob_offline
        .begin_send(Frame::new(MessageType::U, 82, b"advance index"))
        .expect("bob offline send");
    let operation_id = send
        .actions
        .iter()
        .find_map(|action| match action {
            OfflineCoordinatorAction::Put { operation_id, .. } => Some(*operation_id),
            _ => None,
        })
        .expect("bob put operation");
    bob_offline
        .put_completed(operation_id, stored_result(), 1_000)
        .expect("bob put stored");
    let index_frame = bob_offline
        .prepare_index_sync(&bob, 900)
        .expect("prepare sync")
        .actions
        .into_iter()
        .find_map(|action| match action {
            OfflineCoordinatorAction::SendIndexSync { frame, .. } => Some(frame),
            _ => None,
        })
        .expect("index sync frame");

    let alice_offline =
        OfflineCoordinator::new(SHARED_SECRET, &alice_b32, &bob_b32, OfflineState::default())
            .expect("alice offline coordinator");
    let mut application = ApplicationCoordinator::new();
    let contact = open_contact(
        &mut application,
        ContactId::new("sync-bob").expect("contact id"),
        alice,
        Some(alice_offline),
    );
    let received = application
        .receive_contact_frame(contact, alice_connection, index_frame, 2_000)
        .expect("receive index sync");

    assert!(received.events.iter().all(|event| !matches!(
        event,
        ApplicationEvent::OneToOne {
            event: OneToOneEvent::ApplicationFrame {
                frame: Frame {
                    message_type: MessageType::I,
                    ..
                },
                ..
            },
            ..
        }
    )));
    assert!(received.events.iter().any(|event| matches!(
        event,
        ApplicationEvent::Offline {
            session_id,
            event: OfflineCoordinatorEvent::IndexSyncApplied {
                remote_next_send: 1,
                ..
            },
        } if *session_id == contact
    )));
    assert!(received.actions.iter().any(|action| matches!(
        action,
        ApplicationAction::PersistContactOffline { session_id, .. }
            if *session_id == contact
    )));
}

#[test]
fn shutdown_waits_for_pending_offline_persistence() {
    let mut application = ApplicationCoordinator::new();
    let (session, offline) = persistent_contact();
    let contact = open_contact(
        &mut application,
        ContactId::new("pending-write").expect("contact id"),
        session,
        Some(offline),
    );
    application
        .enter_contact_offline(contact)
        .expect("enter offline");
    let send = application
        .begin_offline_send(contact, Frame::new(MessageType::U, 83, b"persist me"))
        .expect("begin send");
    let operation_id = send
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::Offline {
                action: OfflineCoordinatorAction::Put { operation_id, .. },
                ..
            } => Some(*operation_id),
            _ => None,
        })
        .expect("put operation");
    let stored = application
        .offline_put_completed(contact, operation_id, stored_result(), 1_000)
        .expect("put stored");
    let mutation_id = stored
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::PersistContactOffline { mutation_id, .. } => Some(*mutation_id),
            _ => None,
        })
        .expect("persistence mutation");

    application.begin_shutdown().expect("begin shutdown");
    application
        .sam_shutdown_completed(contact, Ok(()))
        .expect("sam shutdown");
    let deaddrop_closed = application
        .deaddrop_shutdown_completed(contact, Ok(()))
        .expect("deaddrop shutdown");
    assert!(
        deaddrop_closed
            .actions
            .iter()
            .all(|action| !matches!(action, ApplicationAction::LockVault))
    );
    assert_eq!(application.session_count(), 1);

    let persisted = application
        .offline_persistence_completed(contact, mutation_id, Ok(()))
        .expect("persistence completed");
    assert!(
        persisted
            .actions
            .iter()
            .any(|action| matches!(action, ApplicationAction::LockVault))
    );
    assert_eq!(application.phase(), ApplicationPhase::LockingVault);
    assert_eq!(application.session_count(), 0);
}

fn open_contact(
    application: &mut ApplicationCoordinator,
    contact_id: ContactId,
    session: OneToOneSession,
    offline: Option<OfflineCoordinator>,
) -> SessionId {
    application
        .open_contact(contact_id, session, offline)
        .expect("open contact")
        .events
        .into_iter()
        .find_map(|event| match event {
            ApplicationEvent::SessionOpened {
                session_id,
                key: ManagedSessionKey::Contact(_),
            } => Some(session_id),
            _ => None,
        })
        .expect("contact session id")
}

fn open_group(
    application: &mut ApplicationCoordinator,
    group_id: GroupId,
    session: GroupSession,
) -> SessionId {
    application
        .open_group(group_id, session)
        .expect("open group")
        .events
        .into_iter()
        .find_map(|event| match event {
            ApplicationEvent::SessionOpened {
                session_id,
                key: ManagedSessionKey::Group(_),
            } => Some(session_id),
            _ => None,
        })
        .expect("group session id")
}

fn pinned_contact_session() -> OneToOneSession {
    OneToOneSession::new(
        OneToOneConfig::new(
            ALICE_DESTINATION,
            Some(PinnedPeer::new(BOB_DESTINATION).expect("bob pin")),
        )
        .expect("contact config"),
    )
}

fn unlocked_contact_session(destination: &str) -> OneToOneSession {
    OneToOneSession::new(OneToOneConfig::new(destination, None).expect("contact config"))
}

fn application_handshake_frames(output: &commtools_core::ApplicationOutput) -> Vec<Frame> {
    output
        .actions
        .iter()
        .find_map(|action| match action {
            ApplicationAction::OneToOne {
                action: OneToOneAction::SendHandshake { frames, .. },
                ..
            } => Some(frames.clone()),
            _ => None,
        })
        .expect("handshake frames")
}

fn persistent_contact() -> (OneToOneSession, OfflineCoordinator) {
    let session = pinned_contact_session();
    let alice_b32 = session.config().local_b32().to_string();
    let bob_b32 = session
        .config()
        .pinned_peer()
        .expect("pinned peer")
        .b32()
        .to_string();
    let offline =
        OfflineCoordinator::new(SHARED_SECRET, &alice_b32, &bob_b32, OfflineState::default())
            .expect("offline coordinator");
    (session, offline)
}

fn group_session() -> GroupSession {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    GroupSession::new(
        GroupSessionConfig::new(
            ALICE_DESTINATION,
            "Alice",
            "Core Group",
            &alice_b32,
            vec![GroupMemberRecord {
                name: "Bob".into(),
                b32: bob_b32,
            }],
        )
        .expect("group config"),
    )
}

fn stored_result() -> PutResult {
    PutResult {
        status: PutStatus::Stored,
        successful_servers: vec!["drop-a".into()],
        replicas: Vec::new(),
    }
}

fn ready_pair() -> (OneToOneSession, OneToOneSession, ConnectionId, ConnectionId) {
    let mut alice = pinned_contact_session();
    let mut bob = OneToOneSession::new(
        OneToOneConfig::new(
            BOB_DESTINATION,
            Some(PinnedPeer::new(ALICE_DESTINATION).expect("alice pin")),
        )
        .expect("bob config"),
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
        .expect("attempt id");
    let alice_connected = alice.outbound_connected(attempt, alice_connection, &bob_b32, 1_000);
    bob.incoming_connected(bob_connection, &alice_b32, ALICE_DESTINATION, 1_000);
    for frame in handshake_frames(&alice_connected) {
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
