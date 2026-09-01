//! Boundary tests for the typed control request, unpadded base64url, origin
//! labels, host validation, and the private everpty-role grammar.
#![allow(clippy::unwrap_used)]

use eversh::limits::Limits;
use eversh::remote::*;
use eversh::role::{parse_everpty_role, EverptyRoleCommand};
use eversh::Error;

fn sample() -> ControlRequest {
    ControlRequest {
        take_over: true,
        origins: vec!["eversh:laptop-1".to_owned()],
        child_argv: vec![b"claude".to_vec(), vec![0xff, 0x80, 0x01], b"--x".to_vec()],
    }
}

#[test]
fn control_request_roundtrips_canonically() {
    let l = Limits::default();
    let encoded = sample().encode(&l).unwrap();
    assert_eq!(encoded[0], CONTROL_VERSION);
    assert_eq!(encoded[1], 0b1, "take_over flag bit");
    let decoded = ControlRequest::decode(&encoded, &l).unwrap();
    assert_eq!(decoded, sample());
    assert_eq!(decoded.encode(&l).unwrap(), encoded, "canonical encoding");

    let empty = ControlRequest::default();
    let wire = empty.encode(&l).unwrap();
    assert_eq!(wire, vec![1, 0, 0, 0, 0, 0]);
    assert_eq!(ControlRequest::decode(&wire, &l).unwrap(), empty);
}

#[test]
fn control_request_fails_closed() {
    let l = Limits::default();

    // Unknown version.
    let mut wire = sample().encode(&l).unwrap();
    wire[0] = 2;
    assert!(matches!(
        ControlRequest::decode(&wire, &l),
        Err(Error::VersionUnsupported)
    ));

    // Unknown flag bits.
    let mut wire = sample().encode(&l).unwrap();
    wire[1] = 0b10;
    assert!(matches!(
        ControlRequest::decode(&wire, &l),
        Err(Error::FlagsInvalid)
    ));

    // NUL in argv, both directions.
    let bad = ControlRequest {
        child_argv: vec![b"a\0b".to_vec()],
        ..ControlRequest::default()
    };
    assert!(matches!(bad.encode(&l), Err(Error::NullInArg)));

    // Origin bounds.
    let bad = ControlRequest {
        origins: vec!["x".repeat(l.origin_label_max + 1)],
        ..ControlRequest::default()
    };
    assert!(matches!(bad.encode(&l), Err(Error::OriginInvalid)));
    let bad = ControlRequest {
        origins: vec!["with space".to_owned()],
        ..ControlRequest::default()
    };
    assert!(matches!(bad.encode(&l), Err(Error::OriginInvalid)));

    // Total cap enforced before decode.
    let oversized = vec![1u8; l.remote_control_max + 1];
    assert!(matches!(
        ControlRequest::decode(&oversized, &l),
        Err(Error::RequestTooLarge)
    ));

    // Declared length beyond buffer.
    let mut wire = vec![1u8, 0, 0, 0, 0, 1];
    wire.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(ControlRequest::decode(&wire, &l).is_err());

    // Trailing bytes rejected.
    let mut wire = sample().encode(&l).unwrap();
    wire.push(0);
    assert!(matches!(
        ControlRequest::decode(&wire, &l),
        Err(Error::RequestTooLarge)
    ));

    // Every truncation fails.
    let wire = sample().encode(&l).unwrap();
    for cut in 0..wire.len() {
        assert!(
            ControlRequest::decode(&wire[..cut], &l).is_err(),
            "cut {cut}"
        );
    }
}

#[test]
fn base64url_is_strict_and_canonical() {
    for input in [
        Vec::new(),
        vec![0u8],
        vec![0xff],
        vec![0xff, 0xfe],
        vec![0xff, 0xfe, 0xfd],
        (0u8..=255).collect::<Vec<u8>>(),
    ] {
        let text = base64url_encode(&input);
        assert!(!text.contains('='), "no padding: {text}");
        assert_eq!(base64url_decode(&text, 4096).unwrap(), input);
    }
    // RFC 4648 test-adjacent vector using the URL alphabet.
    assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");

    for bad in ["A", "AAAA=", "AA A", "AA\n", "A+AA", "A/AA", "AB", "AAB"] {
        assert!(
            base64url_decode(bad, 4096).is_err(),
            "accepted {bad:?} (padding, whitespace, wrong alphabet, or non-canonical bits)"
        );
    }
    // Oversized declared decode rejected before allocation.
    let long = "A".repeat(400);
    assert!(matches!(
        base64url_decode(&long, 16),
        Err(Error::RequestTooLarge)
    ));
}

#[test]
fn origin_labels_and_host_labels_are_deterministic() {
    let l = Limits::default();
    assert!(validate_origin_label("eversh:host-1.example", &l).is_ok());
    for bad in ["", "a b", "a'b", "a\nb", &"x".repeat(65)] {
        assert!(validate_origin_label(bad, &l).is_err(), "{bad:?}");
    }
    assert_eq!(sanitize_host_label("laptop-1.example"), "laptop-1.example");
    assert_eq!(sanitize_host_label("host name!"), "host-name-");
    assert_eq!(sanitize_host_label(""), "unknown");
    assert_eq!(sanitize_host_label(&"y".repeat(100)), "y".repeat(32));
    assert_eq!(origin_label("box"), "eversh:box");
    // Generator and matcher share sanitization: what connect stores is what
    // list/resume matches.
    assert_eq!(
        origin_label("a b"),
        format!("eversh:{}", sanitize_host_label("a b"))
    );
}

#[test]
fn host_validation_fails_closed() {
    for good in [
        "host",
        "user@host.example",
        "192.0.2.7",
        "[2001:db8::1]",
        "2001:db8::1",
        "fe80::1%eth0",
    ] {
        assert!(validate_host(good).is_ok(), "{good}");
    }
    for bad in [
        "",
        "-host",
        "host name",
        "host\nname",
        "host'name",
        "host;true",
        "host$(x)",
        "host|x",
    ] {
        assert!(validate_host(bad).is_err(), "{bad}");
    }
}

#[test]
fn everpty_role_grammar_is_versioned_and_strict() {
    let l = Limits::default();
    let request = sample();
    let token = base64url_encode(&request.encode(&l).unwrap());

    let words = |parts: &[&str]| parts.iter().map(|p| p.to_string()).collect::<Vec<_>>();

    match parse_everpty_role(&words(&["v1", "attach-or-create", "work", &token]), &l).unwrap() {
        EverptyRoleCommand::AttachOrCreate { name, request: r } => {
            assert_eq!(name, "work");
            assert_eq!(r, request);
        }
        other => panic!("unexpected parse: {other:?}"),
    }
    match parse_everpty_role(&words(&["v1", "attach", "work", &token]), &l).unwrap() {
        EverptyRoleCommand::Attach { name, .. } => assert_eq!(name, "work"),
        other => panic!("unexpected parse: {other:?}"),
    }
    assert_eq!(
        parse_everpty_role(&words(&["v1", "observe", "work"]), &l).unwrap(),
        EverptyRoleCommand::Observe {
            name: "work".to_owned()
        }
    );
    let label = base64url_encode(b"eversh:box");
    assert_eq!(
        parse_everpty_role(&words(&["v1", "list", "json", &label]), &l).unwrap(),
        EverptyRoleCommand::List {
            json: true,
            filter_origin: Some("eversh:box".to_owned())
        }
    );
    assert_eq!(
        parse_everpty_role(&words(&["v1", "list", "text"]), &l).unwrap(),
        EverptyRoleCommand::List {
            json: false,
            filter_origin: None
        }
    );
    for (op, cmd) in [
        ("probe", EverptyRoleCommand::Probe { name: "n1".into() }),
        ("detach", EverptyRoleCommand::Detach { name: "n1".into() }),
        ("kill", EverptyRoleCommand::Kill { name: "n1".into() }),
    ] {
        assert_eq!(
            parse_everpty_role(&words(&["v1", op, "n1"]), &l).unwrap(),
            cmd
        );
    }

    // Version words fail closed before anything else.
    for bad in [&["v2", "probe", "n1"][..], &["probe", "n1"], &[]] {
        assert!(matches!(
            parse_everpty_role(&words(bad), &l),
            Err(Error::RoleVersionUnsupported)
        ));
    }
    // Wrong counts, unknown ops, bad names, bad tokens.
    assert!(parse_everpty_role(&words(&["v1", "probe"]), &l).is_err());
    assert!(parse_everpty_role(&words(&["v1", "probe", "n1", "extra"]), &l).is_err());
    assert!(parse_everpty_role(&words(&["v1", "explode", "n1"]), &l).is_err());
    assert!(matches!(
        parse_everpty_role(&words(&["v1", "probe", "-bad"]), &l),
        Err(Error::NameInvalid)
    ));
    assert!(matches!(
        parse_everpty_role(&words(&["v1", "attach", "work", "!!"]), &l),
        Err(Error::Base64Malformed)
    ));
    assert!(parse_everpty_role(&words(&["v1", "list", "yaml"]), &l).is_err());
}
