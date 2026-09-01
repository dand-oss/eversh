//! Exact-argv tests for every supervised invocation the supervisor builds:
//! ProxyCommand strings, outer ssh vectors, remote words, raw ssh, and Kitty
//! launches. These are the design 11.4 argv contracts in pure form.
#![allow(clippy::unwrap_used)]

use eversh::command::*;
use eversh::limits::Limits;
use eversh::remote::{base64url_encode, ControlRequest};
use eversh::Error;
use std::ffi::OsString;

const SELF: &str = "/usr/local/bin/eversh";

fn os(values: &[&str]) -> Vec<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn proxy_command_is_exact_and_quoted() {
    let options = vec!["-oConnectTimeout=7".to_owned(), "-4".to_owned()];
    let proxy = proxy_command(SELF, "eversh", &options).unwrap();
    assert_eq!(
        proxy,
        "'/usr/local/bin/eversh' __everlink ssh-proxy '%n' '%p' \
         --remote-eversh 'eversh' --ssh-option '-oConnectTimeout=7' --ssh-option '-4'"
    );
    let proxy = proxy_command(SELF, "/opt/eversh/bin/eversh", &[]).unwrap();
    assert!(proxy.contains("--remote-eversh '/opt/eversh/bin/eversh'"));
}

#[test]
fn proxy_command_fails_closed() {
    // Unaudited or quote-carrying options never reach a shell word.
    for option in [
        "-oProxyCommand=none",
        "-oBatchMode=yes",
        "-p22",
        "-oUser=a'b",
    ] {
        assert!(
            proxy_command(SELF, "eversh", &[option.to_owned()]).is_err(),
            "accepted {option}"
        );
    }
    for remote in [
        "",
        "-eversh",
        "ever sh",
        "eversh;true",
        "$HOME/eversh",
        "a'b",
    ] {
        assert!(
            proxy_command(SELF, remote, &[]).is_err(),
            "accepted remote word {remote:?}"
        );
    }
    for self_exe in ["relative/eversh", "/bin/ever'sh", "/bin/ever\nsh"] {
        assert!(
            validate_self_exe(std::path::Path::new(self_exe)).is_err(),
            "accepted self exe {self_exe:?}"
        );
    }
}

#[test]
fn outer_ssh_argv_is_ordered_and_exact() {
    let limits = Limits::default();
    let request = ControlRequest {
        take_over: false,
        origins: vec!["eversh:box".to_owned()],
        child_argv: vec![b"claude".to_vec()],
    };
    let words = remote_words(
        "eversh",
        &RemoteOp::AttachOrCreate {
            name: "work",
            request: &request,
        },
        &limits,
    )
    .unwrap();
    let token = base64url_encode(&request.encode(&limits).unwrap());
    assert_eq!(
        words,
        vec![
            "eversh".to_owned(),
            "__everpty".to_owned(),
            "v1".to_owned(),
            "attach-or-create".to_owned(),
            "work".to_owned(),
            token.clone(),
        ]
    );

    let proxy = proxy_command(SELF, "eversh", &[]).unwrap();
    let args = outer_ssh_args(&proxy, &["-4".to_owned()], "user@alias", &words, true).unwrap();
    assert_eq!(
        args,
        os(&[
            "-o",
            &format!("ProxyCommand={proxy}"),
            "-4",
            "-t",
            "--",
            "user@alias",
            "eversh",
            "__everpty",
            "v1",
            "attach-or-create",
            "work",
            &token,
        ])
    );
    // ProxyCommand is FIRST so OpenSSH first-value semantics protect it.
    assert_eq!(args[0], OsString::from("-o"));
    assert!(args[1].to_str().unwrap().starts_with("ProxyCommand="));

    // Batch operations omit -t.
    let words = remote_words("eversh", &RemoteOp::Probe { name: "work" }, &limits).unwrap();
    let args = outer_ssh_args(&proxy, &[], "host", &words, false).unwrap();
    assert!(!args.contains(&OsString::from("-t")));
    assert_eq!(
        args,
        os(&[
            "-o",
            &format!("ProxyCommand={proxy}"),
            "--",
            "host",
            "eversh",
            "__everpty",
            "v1",
            "probe",
            "work",
        ])
    );

    assert!(outer_ssh_args(&proxy, &[], "-badhost", &words, false).is_err());
    assert!(matches!(
        remote_words("eversh", &RemoteOp::Probe { name: "-bad" }, &limits),
        Err(Error::NameInvalid)
    ));
}

#[test]
fn list_words_carry_the_filter_as_the_single_token() {
    let limits = Limits::default();
    let words = remote_words(
        "eversh",
        &RemoteOp::List {
            json: true,
            filter_origin: Some("eversh:box"),
        },
        &limits,
    )
    .unwrap();
    assert_eq!(
        words,
        vec![
            "eversh".to_owned(),
            "__everpty".to_owned(),
            "v1".to_owned(),
            "list".to_owned(),
            "json".to_owned(),
            base64url_encode(b"eversh:box"),
        ]
    );
    // Every word is a plain shell-safe token (no spaces/quotes/metacharacters).
    for word in &words {
        assert!(
            word.bytes()
                .all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'.' | b'_' | b'-' | b'/')),
            "unsafe remote word {word:?}"
        );
    }
}

#[test]
fn raw_ssh_argv_injects_only_the_proxy() {
    let proxy = proxy_command(SELF, "eversh", &[]).unwrap();
    // No inner `--`: every token is an option (legacy behavior preserved).
    let args = raw_ssh_args(
        &proxy,
        &["-L".to_owned(), "8080:localhost:80".to_owned()],
        "host",
        &[],
    )
    .unwrap();
    assert_eq!(
        args,
        os(&[
            "-o",
            &format!("ProxyCommand={proxy}"),
            "-L",
            "8080:localhost:80",
            "--",
            "host",
        ])
    );
}

#[test]
fn raw_ssh_argv_splits_pre_and_post_on_inner_separator() {
    let proxy = proxy_command(SELF, "eversh", &[]).unwrap();

    // With an inner `--`: options before it precede the destination; the
    // remote command after it follows the destination (finding 4).
    let tokens = ["-4", "--", "/bin/sh", "-c", "exit 0"].map(str::to_owned);
    let (pre, post) = split_raw_tokens(&tokens);
    assert_eq!(pre, ["-4".to_owned()]);
    assert_eq!(post, ["/bin/sh", "-c", "exit 0"].map(str::to_owned));
    let args = raw_ssh_args(&proxy, pre, "host", post).unwrap();
    assert_eq!(
        args,
        os(&[
            "-o",
            &format!("ProxyCommand={proxy}"),
            "-4",
            "--",
            "host",
            "/bin/sh",
            "-c",
            "exit 0",
        ])
    );

    // No inner `--`: every token stays a pre-destination option, and the
    // remote command half is empty.
    let tokens = ["-L", "8080:localhost:80"].map(str::to_owned);
    let (pre, post) = split_raw_tokens(&tokens);
    assert_eq!(pre, tokens);
    assert!(post.is_empty());
}

#[test]
fn raw_mode_audited_subset_mirrors_into_the_proxy_command() {
    // A passing option is forwarded into the everlink bootstrap; an
    // unaudited token stays outer-ssh-only and never errors (finding 4).
    let tokens = ["-4", "-L", "8080:localhost:80"].map(str::to_owned);
    let audited = audited_subset(&tokens);
    assert_eq!(audited, vec!["-4".to_owned()]);

    let proxy = proxy_command(SELF, "eversh", &audited).unwrap();
    assert!(proxy.contains("--ssh-option '-4'"), "{proxy}");
    assert!(!proxy.contains("-L"), "{proxy}");

    // Building the raw argv itself never errors on the unaudited token.
    let args = raw_ssh_args(&proxy, &tokens, "host", &[]).unwrap();
    assert!(args.iter().any(|arg| arg == "-L"));
}

#[test]
fn kitty_launch_argv_is_exact() {
    let limits = Limits::default();
    let args = kitty_launch_args(
        Some("unix:/tmp/kitty.sock"),
        SELF,
        "host",
        "work",
        &["-4".to_owned()],
        &limits,
    )
    .unwrap();
    assert_eq!(
        args,
        os(&[
            "@",
            "--to",
            "unix:/tmp/kitty.sock",
            "launch",
            "--type=tab",
            "--tab-title",
            "eversh host work",
            "--",
            SELF,
            "attach",
            "host",
            "work",
            "--hold-on-error",
            "--ssh-option",
            "-4",
        ])
    );
    let args = kitty_launch_args(None, SELF, "host", "work", &[], &limits).unwrap();
    assert!(!args.contains(&OsString::from("--to")));
    assert!(kitty_launch_args(None, SELF, "host", "bad name", &[], &limits).is_err());
}

#[test]
fn role_markers_agree_across_crates() {
    // The combined dispatcher and everlink's remote bootstrap policy must
    // spell the everlink role marker identically.
    assert_eq!(
        eversh::role::EVERLINK_ROLE,
        everlink::ssh_policy::COMBINED_EVERLINK_ROLE
    );
}
