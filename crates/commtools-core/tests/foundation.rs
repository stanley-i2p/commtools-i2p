use commtools_core::config::{ConfigError, SamEndpoint};
use commtools_core::ids::{ContactId, GroupId, IdentifierError, SessionId};
use commtools_core::{CoreConfig, CoreEvent};
use std::path::Path;
use std::str::FromStr;

#[test]
fn core_config_requires_an_explicit_storage_root() {
    let config = CoreConfig::new("/tmp/commtools-test").expect("valid configuration");

    assert_eq!(config.storage.root(), Path::new("/tmp/commtools-test"));
    assert_eq!(config.sam.endpoint.to_string(), "127.0.0.1:7656");
    assert_eq!(
        CoreConfig::new("").unwrap_err(),
        ConfigError::EmptyStorageRoot
    );
}

#[test]
fn sam_endpoint_accepts_hostnames_ipv4_and_bracketed_ipv6() {
    let hostname = SamEndpoint::from_str("router.internal:17656").expect("hostname endpoint");
    let ipv4 = SamEndpoint::from_str("127.0.0.1:7656").expect("IPv4 endpoint");
    let ipv6 = SamEndpoint::from_str("[::1]:7656").expect("IPv6 endpoint");

    assert_eq!(hostname.host(), "router.internal");
    assert_eq!(hostname.port(), 17656);
    assert_eq!(ipv4.to_string(), "127.0.0.1:7656");
    assert_eq!(ipv6.host(), "::1");
    assert_eq!(ipv6.to_string(), "[::1]:7656");
}

#[test]
fn sam_endpoint_rejects_ambiguous_or_invalid_values() {
    for invalid in ["", "localhost", "localhost:0", "::1:7656", "host name:7656"] {
        assert!(
            SamEndpoint::from_str(invalid).is_err(),
            "accepted {invalid:?}"
        );
    }
}

#[test]
fn opaque_identifiers_reject_empty_and_control_characters() {
    assert!(matches!(
        ContactId::new(""),
        Err(IdentifierError::Empty { kind: "contact" })
    ));
    assert!(matches!(
        ContactId::new("   "),
        Err(IdentifierError::Empty { kind: "contact" })
    ));
    assert!(matches!(
        GroupId::new("group\nname"),
        Err(IdentifierError::ControlCharacter { kind: "group" })
    ));

    let contact = ContactId::new("alice").expect("valid contact identifier");
    assert_eq!(contact.as_str(), "alice");
}

#[test]
fn lifecycle_events_do_not_depend_on_a_frontend() {
    let event = CoreEvent::LogLine {
        session_id: Some(SessionId::new(42)),
        line: "session initialized".to_string(),
    };

    assert!(matches!(
        event,
        CoreEvent::LogLine {
            session_id: Some(id),
            ..
        } if id.get() == 42
    ));
}
