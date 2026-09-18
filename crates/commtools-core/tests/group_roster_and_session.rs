use commtools_core::group_roster::{
    GroupControlMessage, GroupInvite, GroupRosterError, InviteApplyOutcome, InviteRedemption,
    JOIN_PROOF_CONTROL, LEAVE_REQUEST_CONTROL, RosterApplyOutcome, apply_invite, apply_roster_sync,
    decode_public_invite, issue_group_dissolution, issue_private_invite, issue_public_invite,
    join_control, leave_control, redeem_join_control, rename_local_member, roster_sync,
    sign_owner_roster, verify_group_dissolution,
};
use commtools_core::group_session::{
    GROUP_HANDSHAKE_TIMEOUT_MS, GroupCollisionWinner, GroupDisconnectReason, GroupSession,
    GroupSessionAction, GroupSessionConfig, GroupSessionError, GroupSessionEvent,
};
use commtools_core::ids::GroupId;
use commtools_core::one_to_one::{ConnectionId, GRACEFUL_CLOSE_DELAY_MS, QUIT_SIGNAL};
use commtools_core::private_group_invite::{generate_request, open_invite};
use commtools_core::protocol::{Frame, MessageType};
use commtools_core::sam::destination_to_b32;
use commtools_core::storage::{GroupMemberRecord, GroupRecord, PersistentIdentity};
use commtools_core::{
    ImageTransferHeader, ImageTransferKind, OriginalImageControl, OriginalImageMetadata,
    image_sha256_hex,
};

const ALICE_DESTINATION: &str = "YWJj";
const BOB_DESTINATION: &str = "ZGVm";
const CAROL_DESTINATION: &str = "Z2hp";

#[test]
fn stored_private_group_identity_uses_only_the_runtime_public_destination_in_protocol_state() {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let mut group = owner_group();
    group.identity = Some(
        PersistentIdentity::new("cHJpdmF0ZS1kZXN0aW5hdGlvbg==", alice_b32.clone())
            .expect("stored private identity"),
    );

    let config =
        GroupSessionConfig::from_record_with_local_destination(&group, ALICE_DESTINATION, 1)
            .expect("public protocol identity");
    assert_eq!(config.local_b32(), alice_b32);
    assert!(matches!(
        GroupSessionConfig::from_record_with_local_destination(&group, BOB_DESTINATION, 1),
        Err(GroupSessionError::IdentityMismatch)
    ));
}

#[test]
fn owner_signed_roster_round_trip_pins_key_and_rejects_tampering() {
    let mut owner = owner_group();
    sign_owner_roster(&mut owner).expect("sign owner roster");
    let sync = roster_sync(&owner).expect("signed roster sync");

    let mut participant = participant_group(&owner);
    participant.roster_version = 0;
    let applied = apply_roster_sync(&mut participant, sync.clone()).expect("apply roster");
    assert_eq!(applied, RosterApplyOutcome::Applied);
    assert_eq!(
        participant.roster_signing_public_key,
        Some(sync.roster_signing_pubkey.clone())
    );

    let mut tampered = sync;
    tampered.members[0].name = "Mallory".into();
    assert!(matches!(
        apply_roster_sync(&mut participant, tampered),
        Err(GroupRosterError::InvalidRosterSignature)
    ));
}

#[test]
fn local_group_name_updates_owner_signature_but_not_participant_roster() {
    let mut owner = owner_group();
    sign_owner_roster(&mut owner).expect("initial owner signature");
    let owner_version = owner.roster_version;
    assert!(rename_local_member(&mut owner, "Alice New").expect("rename owner"));
    assert_eq!(owner.local_member_name, "Alice New");
    assert_eq!(owner.roster_version, owner_version + 1);
    roster_sync(&owner).expect("renamed owner roster remains valid");

    let mut participant = participant_group(&owner);
    let participant_version = participant.roster_version;
    assert!(rename_local_member(&mut participant, "Bob New").expect("rename participant"));
    assert_eq!(participant.local_member_name, "Bob New");
    assert_eq!(participant.roster_version, participant_version);
}

#[test]
fn participant_leave_control_uses_its_group_identity_without_an_invite_token() {
    let owner = owner_group();
    let participant = participant_group(&owner);
    let local_identity = participant.identity.as_ref().expect("participant identity");

    let control = leave_control(&participant).expect("participant leave control");

    assert_eq!(control.kind, LEAVE_REQUEST_CONTROL);
    assert!(control.token.is_empty());
    assert_eq!(control.b32, local_identity.b32);
    assert_eq!(control.name, participant.local_member_name);
    assert!(control.private_request_id.is_none());
    assert!(control.private_proof_nonce.is_none());
    assert!(control.private_proof_signature.is_none());
}

#[test]
fn group_owner_cannot_create_a_leave_control() {
    assert!(matches!(
        leave_control(&owner_group()),
        Err(GroupRosterError::OwnerCannotLeave)
    ));
}

#[test]
fn owner_dissolution_is_signed_newer_and_bound_to_the_group() {
    let mut owner = owner_group();
    owner.id = GroupId::new("owner-local-record").expect("owner local id");
    sign_owner_roster(&mut owner).expect("sign owner roster");
    let sync = roster_sync(&owner).expect("owner roster");
    let mut participant = participant_group(&owner);
    participant.id =
        GroupId::new(owner.owner_b32.as_deref().expect("owner b32")).expect("participant local id");
    assert_ne!(owner.id, participant.id);
    participant.roster_version = 0;
    apply_roster_sync(&mut participant, sync).expect("pin owner roster key");

    let dissolution = issue_group_dissolution(&mut owner).expect("issue dissolution");

    assert!(dissolution.roster_version > participant.roster_version);
    verify_group_dissolution(&participant, &dissolution).expect("verify dissolution");

    let mut tampered = dissolution.clone();
    let replacement = if tampered.signature.starts_with('A') {
        "B"
    } else {
        "A"
    };
    tampered.signature.replace_range(..1, replacement);
    assert!(matches!(
        verify_group_dissolution(&participant, &tampered),
        Err(GroupRosterError::InvalidRosterSignature)
    ));

    participant.roster_version = dissolution.roster_version;
    assert!(matches!(
        verify_group_dissolution(&participant, &dissolution),
        Err(GroupRosterError::InvalidRosterVersion)
    ));
}

#[test]
fn participant_cannot_issue_group_dissolution() {
    let owner = owner_group();
    let mut participant = participant_group(&owner);
    assert!(matches!(
        issue_group_dissolution(&mut participant),
        Err(GroupRosterError::OwnerOnly)
    ));
}

#[test]
fn public_invite_is_one_time_for_distinct_group_identities() {
    let mut owner = owner_group();
    let encoded = issue_public_invite(&mut owner).expect("issue invite");
    let invite = decode_public_invite(&encoded).expect("decode invite");
    let token = invite.invite_token.expect("join token");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let carol_b32 = destination_to_b32(CAROL_DESTINATION).expect("carol b32");

    let bob = GroupControlMessage {
        kind: JOIN_PROOF_CONTROL.into(),
        token: token.clone(),
        b32: bob_b32.clone(),
        name: "Bob".into(),
        private_request_id: None,
        private_proof_nonce: None,
        private_proof_signature: None,
    };
    assert_eq!(
        redeem_join_control(&mut owner, &bob, 1_000).expect("redeem invite"),
        InviteRedemption::NewlyRedeemed
    );
    assert_eq!(
        redeem_join_control(&mut owner, &bob, 1_001).expect("same member replay"),
        InviteRedemption::AlreadyRedeemedByMember
    );

    let carol = GroupControlMessage {
        b32: carol_b32,
        name: "Carol".into(),
        ..bob
    };
    assert!(matches!(
        redeem_join_control(&mut owner, &carol, 1_002),
        Err(GroupRosterError::InviteAlreadyRedeemed)
    ));
    assert!(owner.members.iter().any(|member| member.b32 == bob_b32));
}

#[test]
fn recipient_bound_invite_applies_and_requires_its_private_join_proof() {
    let mut owner = owner_group();
    owner.members.clear();
    let (pending, request) = generate_request(1_000).expect("private request");
    let response =
        issue_private_invite(&mut owner, &request, 1_001).expect("private invite response");
    let (invite_json, credential) =
        open_invite(&response, &pending, 1_002).expect("open private invite");
    let invite: GroupInvite = serde_json::from_slice(&invite_json).expect("decode inner invite");

    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut participant = GroupRecord::new(
        GroupId::new("pending-group").expect("temporary id"),
        "Pending",
    )
    .expect("participant group");
    participant.identity =
        Some(PersistentIdentity::new(BOB_DESTINATION, &bob_b32).expect("participant identity"));
    participant.local_member_name = "Bob".into();
    assert_eq!(
        apply_invite(&mut participant, invite, Some(credential)).expect("apply private invite"),
        InviteApplyOutcome::CreatedOrUpdated
    );
    let proof = join_control(&participant, 1_003)
        .expect("prepare join control")
        .expect("join control");
    assert_eq!(
        redeem_join_control(&mut owner, &proof, 1_004).expect("verify private proof"),
        InviteRedemption::NewlyRedeemed
    );
    assert!(owner.members.iter().any(|member| member.b32 == bob_b32));
}

#[test]
fn group_peers_handshake_fan_out_text_and_track_per_member_ack() {
    let (mut alice, mut bob, alice_connection, bob_connection, ready_at) = ready_pair();
    assert_eq!(alice.ready_member_count(), 1);
    assert_eq!(bob.ready_member_count(), 1);

    let sent = alice.send_text(77, "group hello").expect("send text");
    let encrypted = sent
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendFrame {
                connection_id,
                frame,
            } if connection_id == alice_connection => Some(frame),
            _ => None,
        })
        .expect("encrypted text frame");
    assert_ne!(encrypted.payload, b"group hello");

    let received = bob.receive_frame(bob_connection, encrypted, ready_at + 1);
    assert!(received.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::TextReceived { text, .. } if text == "group hello"
    )));
    let ack = received
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendFrame { frame, .. } if frame.message_type == MessageType::D => {
                Some(frame)
            }
            _ => None,
        })
        .expect("delivery ack");
    assert_eq!(ack.payload, 77_u64.to_be_bytes());
    let malformed_ack = alice.receive_frame(
        alice_connection,
        Frame::new(MessageType::D, 78, [0; 7]),
        ready_at + 2,
    );
    assert!(malformed_ack.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::FrameRejected { reason, .. }
            if reason.contains("must contain an 8-byte message id")
    )));

    let acked = alice.receive_frame(alice_connection, ack, ready_at + 3);
    assert!(acked.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::DeliveryUpdated(status)
            if status.message_id == 77 && status.is_complete()
    )));
}

#[test]
fn owner_dissolution_uses_the_encrypted_group_control_channel() {
    let (mut alice, mut bob, alice_connection, bob_connection, ready_at) = ready_pair();
    let mut owner = owner_group();
    let dissolution = issue_group_dissolution(&mut owner).expect("issue dissolution");

    let sent = alice
        .send_dissolution(91, &dissolution)
        .expect("send dissolution");
    let encrypted = sent
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendFrame {
                connection_id,
                frame,
            } if connection_id == alice_connection => Some(frame),
            _ => None,
        })
        .expect("encrypted dissolution frame");
    assert_eq!(encrypted.message_type, MessageType::L);
    assert_ne!(encrypted.payload, serde_json::to_vec(&dissolution).unwrap());

    let received = bob.receive_frame(bob_connection, encrypted, ready_at + 1);
    assert!(received.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::DissolutionReceived {
            dissolution: received,
            ..
        } if received == &dissolution
    )));
}

#[test]
fn participant_control_to_owner_uses_authenticated_l_frame() {
    let (mut alice, mut bob, _alice_connection, bob_connection, ready_at) = ready_pair();
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let control = GroupControlMessage {
        kind: commtools_core::group_roster::RENAME_REQUEST_CONTROL.into(),
        token: String::new(),
        b32: bob_b32.clone(),
        name: "Bob New".into(),
        private_request_id: None,
        private_proof_nonce: None,
        private_proof_signature: None,
    };
    let sent = bob
        .send_control_to_owner(91, &control)
        .expect("send encrypted owner control");
    let frame = sent
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendFrame {
                connection_id,
                frame,
            } if connection_id == bob_connection => Some(frame),
            _ => None,
        })
        .expect("owner control frame");
    assert_eq!(frame.message_type, MessageType::L);
    assert_ne!(
        frame.payload,
        serde_json::to_vec(&control).expect("plain control")
    );

    let received = alice.receive_frame(ConnectionId::new(1), frame, ready_at + 1);
    assert!(received.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::ControlReceived {
            peer_b32,
            control: received,
        } if peer_b32 == &bob_b32 && received == &control
    )));
}

#[test]
fn group_image_sequence_is_encrypted_bounded_and_acknowledged() {
    let (mut alice, mut bob, alice_connection, bob_connection, ready_at) = ready_pair();
    let mut image = b"\x89PNG\r\n\x1a\n".to_vec();
    image.extend(std::iter::repeat_n(0x5a, 9_000));
    let sent = alice
        .send_image(88, "../preview.png", "image/png", &image)
        .expect("send image");
    let frames = sent
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendFrames {
                connection_id,
                frames,
            } if connection_id == alice_connection => Some(frames),
            _ => None,
        })
        .expect("image frames");
    assert_eq!(
        frames.first().map(|frame| frame.message_type),
        Some(MessageType::J)
    );
    assert_eq!(
        frames.last().map(|frame| frame.message_type),
        Some(MessageType::Z)
    );
    assert!(
        frames
            .iter()
            .filter(|frame| frame.message_type == MessageType::G)
            .all(|frame| !frame.payload.windows(8).any(|window| window == [0x5a; 8]))
    );

    let mut ack = None;
    let mut received_image = None;
    for frame in frames {
        let output = bob.receive_frame(bob_connection, frame, ready_at + 1);
        for event in output.events {
            if let GroupSessionEvent::ImageReceived {
                filename, bytes, ..
            } = event
            {
                received_image = Some((filename, bytes));
            }
        }
        for action in output.actions {
            if let GroupSessionAction::SendFrame { frame, .. } = action
                && frame.message_type == MessageType::D
            {
                ack = Some(frame);
            }
        }
    }
    assert_eq!(received_image, Some(("preview.png".into(), image)));
    let result = alice.receive_frame(alice_connection, ack.expect("image ack"), ready_at + 2);
    assert!(result.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::DeliveryUpdated(status) if status.is_complete()
    )));
}

#[test]
fn requested_group_original_is_targeted_and_digest_validated() {
    let (mut alice, mut bob, alice_connection, bob_connection, ready_at) = ready_pair();
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let original = b"\x89PNG\r\n\x1a\nfull original image".to_vec();
    let metadata = OriginalImageMetadata::new(
        original.len() as u64,
        "image/png",
        image_sha256_hex(&original),
    )
    .expect("metadata");

    let request = bob
        .send_original_image_control(&alice_b32, 900, OriginalImageControl::Request(88))
        .expect("request original");
    let request_frame = request
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendFrame { frame, .. } => Some(frame),
            _ => None,
        })
        .expect("request frame");
    let received_request = alice.receive_frame(alice_connection, request_frame, ready_at + 1);
    assert!(received_request.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::OriginalImageControlReceived {
            peer_b32,
            control: OriginalImageControl::Request(88),
        } if peer_b32 == &bob_b32
    )));

    let header = ImageTransferHeader {
        filename: "original.png".into(),
        mime: "image/png".into(),
        total_bytes: original.len() as u64,
        kind: ImageTransferKind::Original,
        media_id: 88,
        original: Some(metadata),
    };
    let sent = alice
        .send_image_to_peer(&bob_b32, 901, &header, &original)
        .expect("send targeted original");
    let frames = sent
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendOriginalImage {
                connection_id,
                peer_b32,
                frames,
                ..
            } if connection_id == alice_connection && peer_b32 == bob_b32 => Some(frames),
            _ => None,
        })
        .expect("targeted original frames");
    let mut received = None;
    for frame in frames {
        for event in bob
            .receive_frame(bob_connection, frame, ready_at + 2)
            .events
        {
            if let GroupSessionEvent::ImageReceived { kind, bytes, .. } = event {
                received = Some((kind, bytes));
            }
        }
    }
    assert_eq!(received, Some((ImageTransferKind::Original, original)));
}

#[test]
fn cancelled_group_original_drains_residual_chunks_before_the_next_preview() {
    let (mut alice, mut bob, alice_connection, bob_connection, ready_at) = ready_pair();
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut original = b"\x89PNG\r\n\x1a\n".to_vec();
    original.extend(std::iter::repeat_n(0x5a, 9_000));
    let metadata = OriginalImageMetadata::new(
        original.len() as u64,
        "image/png",
        image_sha256_hex(&original),
    )
    .expect("metadata");

    bob.send_original_image_control(&alice_b32, 910, OriginalImageControl::Request(88))
        .expect("register original request");
    let header = ImageTransferHeader {
        filename: "original.png".into(),
        mime: "image/png".into(),
        total_bytes: original.len() as u64,
        kind: ImageTransferKind::Original,
        media_id: 88,
        original: Some(metadata),
    };
    let frames = alice
        .send_image_to_peer(&bob_b32, 911, &header, &original)
        .expect("send original")
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendOriginalImage { frames, .. } => Some(frames),
            _ => None,
        })
        .expect("original frames");
    bob.receive_frame(bob_connection, frames[0].clone(), ready_at + 1);
    bob.receive_frame(bob_connection, frames[1].clone(), ready_at + 2);

    bob.send_original_image_control(&alice_b32, 912, OriginalImageControl::Cancel(88))
        .expect("cancel original");
    for frame in frames[2..]
        .iter()
        .filter(|frame| frame.message_type == MessageType::G)
    {
        let output = bob.receive_frame(bob_connection, frame.clone(), ready_at + 3);
        assert!(output.events.is_empty());
    }

    let preview = b"\x89PNG\r\n\x1a\nnext preview".to_vec();
    let preview_frames = alice
        .send_image(913, "preview.png", "image/png", &preview)
        .expect("send preview")
        .actions
        .into_iter()
        .find_map(|action| match action {
            GroupSessionAction::SendFrames {
                connection_id,
                frames,
            } if connection_id == alice_connection => Some(frames),
            _ => None,
        })
        .expect("preview frames");
    let mut received = None;
    for frame in preview_frames {
        for event in bob
            .receive_frame(bob_connection, frame, ready_at + 4)
            .events
        {
            if let GroupSessionEvent::ImageReceived { kind, bytes, .. } = event {
                received = Some((kind, bytes));
            }
        }
    }
    assert_eq!(received, Some((ImageTransferKind::Preview, preview)));
}

#[test]
fn collision_rule_and_handshake_timeout_are_per_peer() {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let (lower_destination, higher_destination, higher_b32) = if alice_b32 < bob_b32 {
        (ALICE_DESTINATION, BOB_DESTINATION, bob_b32)
    } else {
        (BOB_DESTINATION, ALICE_DESTINATION, alice_b32)
    };
    let lower_b32 = destination_to_b32(lower_destination).expect("lower b32");
    let mut lower = group_session(
        lower_destination,
        &higher_b32,
        vec![member("Higher", &higher_b32)],
    );
    let connect = lower.begin_connections(1_000);
    let attempt = connect_attempt(&connect, &higher_b32);
    let incoming = lower.incoming_connected(
        ConnectionId::new(20),
        &higher_b32,
        higher_destination,
        1_001,
    );
    assert!(incoming.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::CollisionResolved {
            winner: GroupCollisionWinner::Outbound,
            ..
        }
    )));

    let connected = lower.outbound_connected(&higher_b32, attempt, ConnectionId::new(21), 2_000);
    assert!(
        connected
            .actions
            .iter()
            .any(|action| matches!(action, GroupSessionAction::SendHandshake { .. }))
    );
    let timed_out = lower.tick(2_000 + GROUP_HANDSHAKE_TIMEOUT_MS);
    assert!(timed_out.events.iter().any(|event| matches!(
        event,
        GroupSessionEvent::PeerDisconnected {
            peer_b32,
            reason: GroupDisconnectReason::HandshakeTimeout,
        } if peer_b32 == &higher_b32
    )));
    assert_ne!(lower_b32, higher_b32);
}

#[test]
fn shutdown_notifies_every_ready_peer_before_transport_close() {
    let (mut alice, _bob, alice_connection, _bob_connection, _ready_at) = ready_pair();
    let shutdown = alice.begin_shutdown();
    assert!(alice.is_closed());
    assert!(shutdown.actions.iter().any(|action| matches!(
        action,
        GroupSessionAction::NotifyAndClose {
            connection_id,
            frame,
            delay_ms,
        } if *connection_id == alice_connection
            && frame.message_type == MessageType::S
            && frame.payload == QUIT_SIGNAL.as_bytes()
            && *delay_ms == GRACEFUL_CLOSE_DELAY_MS
    )));
    assert!(alice.begin_connections(10_000).actions.is_empty());
}

fn owner_group() -> GroupRecord {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut group =
        GroupRecord::new(GroupId::new(&alice_b32).expect("group id"), "Core Group").expect("group");
    group.identity =
        Some(PersistentIdentity::new(ALICE_DESTINATION, &alice_b32).expect("owner identity"));
    group.local_member_name = "Alice".into();
    group.owner_b32 = Some(alice_b32);
    group.members = vec![member("Bob", &bob_b32)];
    group
}

fn participant_group(owner: &GroupRecord) -> GroupRecord {
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let mut group =
        GroupRecord::new(owner.id.clone(), owner.display_name.clone()).expect("participant group");
    group.identity =
        Some(PersistentIdentity::new(BOB_DESTINATION, &bob_b32).expect("participant identity"));
    group.local_member_name = "Bob".into();
    group.owner_b32 = owner.owner_b32.clone();
    group.members = roster_members();
    group.roster_version = owner.roster_version;
    group
}

fn ready_pair() -> (GroupSession, GroupSession, ConnectionId, ConnectionId, u64) {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    let members = roster_members();
    let mut alice = group_session(ALICE_DESTINATION, &alice_b32, members.clone());
    let mut bob = group_session(BOB_DESTINATION, &alice_b32, members);
    let alice_connection = ConnectionId::new(1);
    let bob_connection = ConnectionId::new(2);
    let started_at = 1_000;

    let attempt = connect_attempt(&alice.begin_connections(started_at), &bob_b32);
    let alice_connected = alice.outbound_connected(&bob_b32, attempt, alice_connection, started_at);
    let alice_frames = handshake_frames(&alice_connected);
    let bob_connected =
        bob.incoming_connected(bob_connection, &alice_b32, ALICE_DESTINATION, started_at);
    let bob_frames = handshake_frames(&bob_connected);

    for frame in alice_frames {
        bob.receive_frame(bob_connection, frame, started_at + 1);
    }
    for frame in bob_frames {
        alice.receive_frame(alice_connection, frame, started_at + 1);
    }
    assert_eq!(alice.ready_member_count(), 1);
    assert_eq!(bob.ready_member_count(), 1);
    (alice, bob, alice_connection, bob_connection, started_at + 1)
}

fn group_session(
    local_destination: &str,
    owner_b32: &str,
    members: Vec<GroupMemberRecord>,
) -> GroupSession {
    let local_b32 = destination_to_b32(local_destination).expect("local b32");
    let local_name = if local_b32 == owner_b32 {
        "Alice"
    } else {
        "Bob"
    };
    GroupSession::new(
        GroupSessionConfig::new(
            local_destination,
            local_name,
            "Core Group",
            owner_b32,
            members,
        )
        .expect("group config")
        .with_control_message_seed(100),
    )
}

fn roster_members() -> Vec<GroupMemberRecord> {
    let alice_b32 = destination_to_b32(ALICE_DESTINATION).expect("alice b32");
    let bob_b32 = destination_to_b32(BOB_DESTINATION).expect("bob b32");
    vec![member("Alice", &alice_b32), member("Bob", &bob_b32)]
}

fn member(name: &str, b32: &str) -> GroupMemberRecord {
    GroupMemberRecord {
        name: name.into(),
        b32: b32.into(),
    }
}

fn connect_attempt(output: &commtools_core::GroupSessionOutput, peer_b32: &str) -> u64 {
    output
        .actions
        .iter()
        .find_map(|action| match action {
            GroupSessionAction::Connect {
                attempt_id,
                peer_b32: peer,
            } if peer == peer_b32 => Some(*attempt_id),
            _ => None,
        })
        .expect("connect action")
}

fn handshake_frames(output: &commtools_core::GroupSessionOutput) -> Vec<Frame> {
    output
        .actions
        .iter()
        .find_map(|action| match action {
            GroupSessionAction::SendHandshake { frames, .. } => Some(frames.clone()),
            _ => None,
        })
        .expect("handshake action")
}
