#![no_main]

use everlink::bootstrap::{decode_auth_frame, encode_auth_frame, AUTH_FRAME_LEN};
use everlink::limits::Limits;
use libfuzzer_sys::fuzz_target;

const MAX_CHUNK_STEPS: usize = 32;

fn feed_chunk(
    wire: &[u8],
    requested: usize,
    frame: &mut [u8; AUTH_FRAME_LEN],
    filled: &mut usize,
    limits: &Limits,
) {
    assert!(*filled <= AUTH_FRAME_LEN);
    assert!(*filled <= wire.len());
    if *filled == AUTH_FRAME_LEN {
        return;
    }

    let offered = requested.min(wire.len() - *filled);
    let consumed = offered.min(AUTH_FRAME_LEN - *filled);
    let end = *filled + consumed;
    frame[*filled..end].copy_from_slice(&wire[*filled..end]);
    *filled = end;

    assert!(
        *filled <= AUTH_FRAME_LEN,
        "auth parser crossed its boundary"
    );
    if *filled < AUTH_FRAME_LEN {
        assert!(
            decode_auth_frame(&frame[..*filled], limits).is_err(),
            "a partial authentication frame was accepted"
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    let (plan, wire) = if let Some((&declared, remainder)) = data.split_first() {
        let plan_len = usize::from(declared)
            .min(MAX_CHUNK_STEPS)
            .min(remainder.len());
        remainder.split_at(plan_len)
    } else {
        (&[][..], data)
    };

    let opaque_before = if wire.len() >= AUTH_FRAME_LEN {
        Some(&wire[AUTH_FRAME_LEN..])
    } else {
        None
    };
    let mut frame = [0_u8; AUTH_FRAME_LEN];
    let mut filled = 0_usize;

    assert!(
        decode_auth_frame(&frame[..0], &limits).is_err(),
        "an empty authentication frame was accepted"
    );

    for &requested in plan {
        if filled == AUTH_FRAME_LEN {
            break;
        }
        feed_chunk(
            wire,
            usize::from(requested),
            &mut frame,
            &mut filled,
            &limits,
        );
    }

    if filled < AUTH_FRAME_LEN {
        let remainder = wire.len() - filled;
        feed_chunk(wire, remainder, &mut frame, &mut filled, &limits);
    }

    assert!(
        frame[..filled] == wire[..filled],
        "chunked authentication bytes diverged from the wire prefix"
    );
    assert!(
        frame[filled..].iter().all(|byte| *byte == 0),
        "bytes beyond a partial prefix were overwritten"
    );

    if filled < AUTH_FRAME_LEN {
        assert_eq!(filled, wire.len());
        assert!(
            decode_auth_frame(&frame[..filled], &limits).is_err(),
            "a final partial authentication frame was accepted"
        );
        assert!(opaque_before.is_none());
        return;
    }

    assert_eq!(filled, AUTH_FRAME_LEN);
    let Some(opaque_before) = opaque_before else {
        panic!("the authentication boundary was reached without a complete wire prefix");
    };
    let opaque_after = &wire[filled..];
    assert!(
        std::ptr::eq(opaque_after.as_ptr(), opaque_before.as_ptr()),
        "opaque payload start moved"
    );
    assert_eq!(
        opaque_after.len(),
        wire.len() - AUTH_FRAME_LEN,
        "opaque payload length changed"
    );
    assert!(
        opaque_after == opaque_before,
        "opaque payload bytes changed during authentication"
    );
    assert!(
        frame.as_slice() == &wire[..AUTH_FRAME_LEN],
        "opaque payload bytes entered the authentication frame"
    );

    let chunked = decode_auth_frame(&frame, &limits);
    let direct = decode_auth_frame(&wire[..AUTH_FRAME_LEN], &limits);
    match (chunked, direct) {
        (Ok((chunked_token, chunked_port)), Ok((direct_token, direct_port))) => {
            assert!(
                chunked_token == direct_token,
                "chunked and direct token decoding diverged"
            );
            assert_eq!(
                chunked_port, direct_port,
                "chunked and direct port decoding diverged"
            );
            let encoded = encode_auth_frame(&chunked_token, chunked_port, &limits);
            let encoded_bytes: &[u8] = encoded.as_ref();
            assert!(
                encoded_bytes == frame.as_slice(),
                "an accepted authentication frame was not canonical"
            );
        }
        (Err(chunked_error), Err(direct_error)) => assert_eq!(
            std::mem::discriminant(&chunked_error),
            std::mem::discriminant(&direct_error),
            "chunked and direct rejection types diverged"
        ),
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => {
            panic!("chunked and direct authentication outcomes diverged");
        }
    }
});
