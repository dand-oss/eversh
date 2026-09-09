//! Benchmark-only stdio bridge for the frozen zmosh QUIC client module.
//!
//! The pinned zmosh SHA contains the QUIC gateway and socket-owning client,
//! but predates CLI dispatch to that client. This adapter performs only the
//! missing stdin/stdout plumbing around its public API. It is built outside
//! the pinned tree and is hash-bound in the qualification receipt.

const std = @import("std");
const crypto = @import("src/crypto.zig");
const lib_posix = @import("src/posix.zig");
const quic_client = @import("src/quic_client.zig");
const quic_transport = @import("src/quic_transport.zig");

// True means new transport work was queued: drive pump again before polling.
fn queueInput(client: anytype, bytes: []const u8) !bool {
    client.sendInput(bytes) catch |err| switch (err) {
        error.WouldBlock => return false,
        else => return err,
    };
    return true;
}

fn writeAll(fd: lib_posix.fd_t, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = lib_posix.write(fd, bytes[offset..]) catch |err| switch (err) {
            error.WouldBlock => {
                var pfd = [_]lib_posix.pollfd{.{
                    .fd = fd,
                    .events = lib_posix.POLL.OUT,
                    .revents = 0,
                }};
                _ = try lib_posix.poll(&pfd, 1000);
                continue;
            },
            else => return err,
        };
        if (count == 0) return error.WriteZero;
        offset += count;
    }
}

fn reportEvent(event: quic_client.ControlEvent) !bool {
    switch (event) {
        .hello_ack => return false,
        .session_end => {
            std.debug.print("zmosh-quic-bridge: SESSION_END\n", .{});
            return true;
        },
        .err => |failure| {
            var buffer: [512]u8 = undefined;
            const message = try std.fmt.bufPrint(
                &buffer,
                "zmosh-quic-bridge: peer error {d}: {s}\n",
                .{ failure.code, failure.reason },
            );
            try writeAll(lib_posix.STDERR_FILENO, message);
            return failure.terminal;
        },
    }
}

pub fn main(init: std.process.Init) !void {
    const alloc = init.gpa;
    const io = init.io;
    var args = init.minimal.args.iterate();
    defer args.deinit();
    _ = args.next();
    const host = args.next() orelse return error.MissingHost;
    const port_raw = args.next() orelse return error.MissingPort;
    const key_raw = args.next() orelse return error.MissingKey;
    if (args.next() != null) return error.TooManyArguments;

    const port = try std.fmt.parseInt(u16, port_raw, 10);
    var bootstrap = try crypto.keyFromBase64(key_raw);
    defer std.crypto.secureZero(u8, &bootstrap);
    var psk: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &psk);
    quic_transport.derivePsk(&psk, &bootstrap);
    const remote = try lib_posix.resolveHost(host, port);

    var client = try quic_client.Client.connect(alloc, io, &psk, remote, lib_posix.nowNs());
    defer client.deinit();

    const stdin_flags = try lib_posix.fcntl(lib_posix.STDIN_FILENO, lib_posix.F.GETFL, 0);
    _ = try lib_posix.fcntl(
        lib_posix.STDIN_FILENO,
        lib_posix.F.SETFL,
        stdin_flags | lib_posix.O_NONBLOCK,
    );
    defer _ = lib_posix.fcntl(lib_posix.STDIN_FILENO, lib_posix.F.SETFL, stdin_flags) catch {};

    var first_resize_sent = false;
    var input_ready = false;
    var input: [8192]u8 = undefined;
    var pending_len: usize = 0;
    var output: [16384]u8 = undefined;
    var first_input_reported = false;
    var first_output_reported = false;
    var last_state = client.session.stateTag();
    std.debug.print("zmosh-quic-bridge: state={s}\n", .{@tagName(last_state)});

    while (true) {
        const now = lib_posix.nowNs();
        if (try client.pump(now)) |event| {
            switch (event) {
                .hello_ack => {
                    std.debug.print("zmosh-quic-bridge: HELLO_ACK\n", .{});
                    if (!first_resize_sent) {
                        try client.sendResize(24, 80, 0, 0);
                        first_resize_sent = true;
                    }
                },
                else => if (try reportEvent(event)) return,
            }
        }
        const state = client.session.stateTag();
        if (state != last_state) {
            std.debug.print("zmosh-quic-bridge: state={s}\n", .{@tagName(state)});
            last_state = state;
        }
        while (try client.pollOutput(&output)) |count| {
            if (count == 0) break;
            if (!first_output_reported) {
                std.debug.print("zmosh-quic-bridge: first output bytes={d}\n", .{count});
                first_output_reported = true;
            }
            try writeAll(lib_posix.STDOUT_FILENO, output[0..count]);
        }

        if (!input_ready and first_resize_sent) {
            var blocked = false;
            client.sendInput("") catch |err| switch (err) {
                error.NotActive, error.WouldBlock => blocked = true,
                else => return err,
            };
            if (!blocked) input_ready = true;
        }
        if (pending_len != 0) {
            if (try queueInput(&client, input[0..pending_len])) {
                if (!first_input_reported) {
                    std.debug.print("zmosh-quic-bridge: first input bytes={d}\n", .{pending_len});
                    first_input_reported = true;
                }
                pending_len = 0;
                // sendInput queues stream data; pump owns actual UDP sends.
                // Do not insert the idle poll timeout into each keystroke.
                continue;
            }
        }

        var poll_fds = [_]lib_posix.pollfd{
            .{
                .fd = client.sock.getFd(),
                .events = lib_posix.POLL.IN,
                .revents = 0,
            },
            .{
                .fd = lib_posix.STDIN_FILENO,
                .events = if (input_ready and pending_len == 0) lib_posix.POLL.IN else 0,
                .revents = 0,
            },
        };
        var timeout_ms: i32 = 10;
        if (client.nextDeadline(now)) |deadline| {
            const remaining = @max(deadline - now, 0);
            timeout_ms = @intCast(@min(@divTrunc(remaining + std.time.ns_per_ms - 1, std.time.ns_per_ms), 10));
        }
        _ = try lib_posix.poll(&poll_fds, timeout_ms);
        if (poll_fds[1].revents & lib_posix.POLL.IN != 0) {
            pending_len = lib_posix.read(lib_posix.STDIN_FILENO, &input) catch |err| switch (err) {
                error.WouldBlock => 0,
                else => return err,
            };
            if (pending_len == 0) {
                std.debug.print("zmosh-quic-bridge: stdin EOF\n", .{});
                return;
            }
        }
    }
}

test "bridge queued input requires immediate drive while blocked input waits" {
    const Fake = struct {
        blocked: bool = false,
        closed: bool = false,
        accepted: usize = 0,

        fn sendInput(self: *@This(), bytes: []const u8) !void {
            if (self.closed) return error.NotActive;
            if (self.blocked) return error.WouldBlock;
            self.accepted += bytes.len;
        }
    };
    var client = Fake{};
    try std.testing.expect(try queueInput(&client, "key"));
    try std.testing.expectEqual(@as(usize, 3), client.accepted);
    client.blocked = true;
    try std.testing.expect(!try queueInput(&client, "next"));
    try std.testing.expectEqual(@as(usize, 3), client.accepted);
    client.blocked = false;
    try std.testing.expect(try queueInput(&client, "next"));
    try std.testing.expectEqual(@as(usize, 7), client.accepted);
    client.closed = true;
    try std.testing.expectError(error.NotActive, queueInput(&client, "no"));
}
