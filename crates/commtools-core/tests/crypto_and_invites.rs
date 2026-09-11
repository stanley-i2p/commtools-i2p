use commtools_core::crypto::{
    CryptoError, SessionCrypto, derive_offline_blob_key, open_offline_blob, seal_offline_blob,
};
use commtools_core::private_group_invite::{
    InputKind as GroupInviteInputKind, MAX_DECOMPRESSED_PAYLOAD, PRIVATE_INVITE_PREFIX,
    generate_request as generate_private_request, input_kind as group_invite_input_kind,
    open_invite, seal_invite, sign_join_proof, verify_join_proof,
};
use commtools_core::rendezvous::{
    InputKind as RendezvousInputKind, IssuedState, answer_request, generate_request,
    input_kind as rendezvous_input_kind, make_auth_signal, open_response, response_matches_pending,
    verify_auth_signal,
};

const NOW_MS: u64 = 1_800_000_000_000;
const ALICE_B32: &str = "alice.b32.i2p";
const BOB_B32: &str = "bob.b32.i2p";

#[test]
fn peers_derive_one_session_and_reject_tampering() {
    let mut alice = SessionCrypto::from_private_key([1; 32]);
    let mut bob = SessionCrypto::from_private_key([2; 32]);

    assert_eq!(alice.seal(b"early"), Err(CryptoError::SessionNotReady));
    alice
        .receive_peer_key(&bob.public_key_bytes())
        .expect("alice key agreement");
    bob.receive_peer_key(&alice.public_key_bytes())
        .expect("bob key agreement");
    assert!(alice.is_ready());
    assert!(bob.is_ready());

    let sealed = alice.seal(b"authenticated payload").expect("seal");
    assert_eq!(bob.open(&sealed).expect("open"), b"authenticated payload");

    let mut tampered = sealed;
    *tampered.last_mut().expect("ciphertext byte") ^= 1;
    assert_eq!(bob.open(&tampered), Err(CryptoError::AuthenticationFailed));
}

#[test]
fn key_agreement_rejects_malformed_and_low_order_keys() {
    let mut session = SessionCrypto::from_private_key([7; 32]);
    assert_eq!(
        session.receive_peer_key(&[1; 31]),
        Err(CryptoError::InvalidPeerKeyLength(31))
    );
    assert_eq!(
        session.receive_peer_key(&[0; 32]),
        Err(CryptoError::InvalidPeerKey)
    );
    assert!(!session.is_ready());
}

#[test]
fn offline_key_vector_is_order_and_suffix_independent() {
    let expected = [
        0x53, 0xb8, 0x7a, 0x20, 0x76, 0x1a, 0x70, 0x28, 0xc1, 0x0a, 0xd8, 0x8f, 0x7d, 0x6c, 0x17,
        0x63, 0x00, 0xb7, 0xd9, 0xf9, 0x99, 0x69, 0x9f, 0xfd, 0x68, 0xe9, 0x63, 0x07, 0x1c, 0x80,
        0xd2, 0x57,
    ];
    let first = derive_offline_blob_key(b"shared-secret", ALICE_B32, BOB_B32);
    let reversed = derive_offline_blob_key(b"shared-secret", "BOB", " ALICE ");
    assert_eq!(first, expected);
    assert_eq!(reversed, expected);

    let sealed = seal_offline_blob(b"offline frame", &first).expect("seal offline blob");
    assert_eq!(
        open_offline_blob(&sealed, &first).expect("open offline blob"),
        b"offline frame"
    );
}

#[test]
fn rendezvous_request_response_and_proof_complete_once() {
    let (pending, request) = generate_request(NOW_MS).expect("request");
    assert_eq!(
        rendezvous_input_kind(&request),
        RendezvousInputKind::Request
    );

    let (mut issued, response) = answer_request(&request, BOB_B32, NOW_MS + 1).expect("response");
    assert_eq!(
        rendezvous_input_kind(&response),
        RendezvousInputKind::Response
    );
    assert!(response_matches_pending(&response, &pending));

    let outgoing = open_response(&response, &pending, NOW_MS + 2).expect("open response");
    assert_eq!(outgoing.destination_b32(), BOB_B32);
    let proof = make_auth_signal(&outgoing, ALICE_B32, BOB_B32, NOW_MS + 3).expect("proof");
    verify_auth_signal(&proof, &issued, ALICE_B32, BOB_B32, NOW_MS + 4).expect("verify proof");
    assert!(verify_auth_signal(&proof, &issued, "mallory.b32.i2p", BOB_B32, NOW_MS + 4).is_err());

    issued.reserve().expect("reserve");
    assert_eq!(issued.state(), IssuedState::Reserved);
    assert!(verify_auth_signal(&proof, &issued, ALICE_B32, BOB_B32, NOW_MS + 4).is_err());
    issued.consume().expect("consume");
    assert_eq!(issued.state(), IssuedState::Consumed);
}

#[test]
fn rendezvous_rejects_tampered_responses() {
    let (pending, request) = generate_request(NOW_MS).expect("request");
    let (_, mut response) = answer_request(&request, BOB_B32, NOW_MS + 1).expect("response");
    response.push('A');
    assert!(open_response(&response, &pending, NOW_MS + 2).is_err());
}

#[test]
fn recipient_bound_group_invite_requires_matching_join_identity() {
    let public_invite = br#"{"format":"commtools-i2p-group-invite","version":1}"#;
    let (pending, request) = generate_private_request(NOW_MS).expect("private request");
    let (binding, private_invite) =
        seal_invite(&request, public_invite, NOW_MS + 1).expect("private invite");
    assert_eq!(
        group_invite_input_kind(&private_invite, "COMMTOOLS-I2P-GROUP-INVITE-v1:"),
        GroupInviteInputKind::Private
    );
    assert!(private_invite.starts_with(PRIVATE_INVITE_PREFIX));

    let (opened, credential) =
        open_invite(&private_invite, &pending, NOW_MS + 2).expect("open private invite");
    assert_eq!(opened, public_invite);
    let proof = sign_join_proof(
        &credential,
        "owner.b32.i2p",
        "one-time-token",
        "member.b32.i2p",
        NOW_MS + 3,
    )
    .expect("join proof");
    verify_join_proof(
        &binding,
        "owner.b32.i2p",
        "one-time-token",
        "member.b32.i2p",
        &proof,
        NOW_MS + 4,
    )
    .expect("verify join proof");
    assert!(
        verify_join_proof(
            &binding,
            "owner.b32.i2p",
            "one-time-token",
            "other-member.b32.i2p",
            &proof,
            NOW_MS + 4,
        )
        .is_err()
    );

    let pending_debug = format!("{pending:?}");
    let credential_debug = format!("{credential:?}");
    assert!(!pending_debug.contains("encryption_secret"));
    assert!(!pending_debug.contains("signing_secret"));
    assert!(!credential_debug.contains("signing_secret"));
}

#[test]
fn private_invite_enforces_the_uncompressed_limit() {
    let (_, request) = generate_private_request(NOW_MS).expect("private request");
    let oversized = vec![0; MAX_DECOMPRESSED_PAYLOAD + 1];
    assert!(seal_invite(&request, &oversized, NOW_MS + 1).is_err());
}
