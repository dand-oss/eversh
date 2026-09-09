use crate::error::WireError;
use crate::limits::Limits;

pub const WIRE_VERSION: u8 = 1;
pub const HEADER_LEN: usize = 14;
pub const FAST_DATAGRAM_HEADER_LEN: usize = 21;
pub const FAST_DATAGRAM_PAYLOAD_MAX: usize = 1_024;
pub const ALPN: &[u8] = b"everudp-link/1";
pub const BOOTSTRAP_PREFIX: &str = "everudp v1 ";
pub const STATUS_PREFIX: &str = "everudp-status-v1 ";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    Control,
    Input,
    Output,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionRole {
    Writer,
    Observer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FastDirection {
    ClientToGateway = 1,
    GatewayToClient = 2,
}

impl FastDirection {
    fn decode(value: u8) -> Result<Self, WireError> {
        match value {
            1 => Ok(Self::ClientToGateway),
            2 => Ok(Self::GatewayToClient),
            other => Err(WireError::DatagramDirection(other)),
        }
    }

    const fn stream(self) -> StreamRole {
        match self {
            Self::ClientToGateway => StreamRole::Input,
            Self::GatewayToClient => StreamRole::Output,
        }
    }

    const fn kind(self) -> Kind {
        match self {
            Self::ClientToGateway => Kind::Input,
            Self::GatewayToClient => Kind::Output,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    ClientHello = 0x01,
    ServerHello = 0x02,
    AckInput = 0x03,
    AckOutput = 0x04,
    Gap = 0x05,
    LinkStatus = 0x06,
    Detach = 0x07,
    Kill = 0x08,
    ProtocolClose = 0x09,
    Input = 0x20,
    Resize = 0x21,
    Signal = 0x22,
    InputClose = 0x23,
    Output = 0x40,
    Ownership = 0x41,
    Exit = 0x42,
}

impl Kind {
    fn decode(value: u8) -> Result<Self, WireError> {
        match value {
            0x01 => Ok(Self::ClientHello),
            0x02 => Ok(Self::ServerHello),
            0x03 => Ok(Self::AckInput),
            0x04 => Ok(Self::AckOutput),
            0x05 => Ok(Self::Gap),
            0x06 => Ok(Self::LinkStatus),
            0x07 => Ok(Self::Detach),
            0x08 => Ok(Self::Kill),
            0x09 => Ok(Self::ProtocolClose),
            0x20 => Ok(Self::Input),
            0x21 => Ok(Self::Resize),
            0x22 => Ok(Self::Signal),
            0x23 => Ok(Self::InputClose),
            0x40 => Ok(Self::Output),
            0x41 => Ok(Self::Ownership),
            0x42 => Ok(Self::Exit),
            other => Err(WireError::UnknownKind(other)),
        }
    }

    pub(crate) fn stream(self) -> StreamRole {
        match self {
            Self::ClientHello
            | Self::ServerHello
            | Self::AckInput
            | Self::AckOutput
            | Self::Gap
            | Self::LinkStatus
            | Self::Detach
            | Self::Kill
            | Self::ProtocolClose => StreamRole::Control,
            Self::Input | Self::Resize | Self::Signal | Self::InputClose => StreamRole::Input,
            Self::Output | Self::Ownership | Self::Exit => StreamRole::Output,
        }
    }

    pub(crate) fn payload_bounds(self, limits: &Limits) -> (usize, usize) {
        match self {
            Self::ClientHello | Self::ServerHello | Self::LinkStatus | Self::ProtocolClose => {
                (1, limits.control_frame_max)
            }
            Self::AckInput | Self::AckOutput => (Ack::WIRE_LEN, Ack::WIRE_LEN),
            Self::Detach | Self::Kill | Self::InputClose => (0, 0),
            Self::Gap => (16, 16),
            Self::Input | Self::Output => (1, limits.terminal_frame_max),
            Self::Resize => (Resize::WIRE_LEN, Resize::WIRE_LEN),
            Self::Signal | Self::Ownership => (1, 1),
            Self::Exit => (4, 4),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameHeader {
    pub kind: Kind,
    pub sequence: u64,
    pub payload_len: u32,
}

impl FrameHeader {
    pub const fn new(kind: Kind, sequence: u64, payload_len: u32) -> Self {
        Self {
            kind,
            sequence,
            payload_len,
        }
    }

    pub fn encode(self) -> [u8; HEADER_LEN] {
        let mut bytes = [0_u8; HEADER_LEN];
        bytes[0] = WIRE_VERSION;
        bytes[1] = self.kind as u8;
        bytes[2..10].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[10..14].copy_from_slice(&self.payload_len.to_be_bytes());
        bytes
    }

    pub(crate) fn decode(
        input: &[u8],
        stream: StreamRole,
        limits: &Limits,
    ) -> Result<Self, WireError> {
        if input.len() < HEADER_LEN {
            return Err(WireError::Incomplete {
                needed: HEADER_LEN,
                available: input.len(),
            });
        }
        if input[0] != WIRE_VERSION {
            return Err(WireError::VersionUnsupported(input[0]));
        }
        let kind = Kind::decode(input[1])?;
        if kind.stream() != stream {
            return Err(WireError::KindNotAllowed { kind, stream });
        }
        let sequence = u64::from_be_bytes(
            input[2..10]
                .try_into()
                .map_err(|_| WireError::LengthOverflow)?,
        );
        let payload_len = u32::from_be_bytes(
            input[10..14]
                .try_into()
                .map_err(|_| WireError::LengthOverflow)?,
        );
        let length = payload_len as usize;
        let (minimum, maximum) = kind.payload_bounds(limits);
        if length > maximum {
            return Err(WireError::PayloadTooLarge {
                kind,
                length,
                maximum,
            });
        }
        if length < minimum {
            return Err(WireError::LengthInvalid { kind, length });
        }
        Ok(Self {
            kind,
            sequence,
            payload_len,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub header: FrameHeader,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FastDatagram<'a> {
    pub direction: FastDirection,
    pub kind: Kind,
    pub epoch: u64,
    pub sequence: u64,
    pub payload: &'a [u8],
}

pub fn encode_fast_datagram(
    direction: FastDirection,
    kind: Kind,
    epoch: u64,
    sequence: u64,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, WireError> {
    if kind != direction.kind() {
        return Err(WireError::KindNotAllowed {
            kind,
            stream: direction.stream(),
        });
    }
    if payload.is_empty() {
        return Err(WireError::LengthInvalid { kind, length: 0 });
    }
    if payload.len() > FAST_DATAGRAM_PAYLOAD_MAX {
        return Err(WireError::PayloadTooLarge {
            kind,
            length: payload.len(),
            maximum: FAST_DATAGRAM_PAYLOAD_MAX,
        });
    }
    let payload_len = u16::try_from(payload.len()).map_err(|_| WireError::LengthOverflow)?;
    let total = FAST_DATAGRAM_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(WireError::LengthOverflow)?;
    if output.len() < total {
        return Err(WireError::OutputTooSmall {
            needed: total,
            available: output.len(),
        });
    }
    output[0] = WIRE_VERSION;
    output[1] = direction as u8;
    output[2] = kind as u8;
    output[3..11].copy_from_slice(&epoch.to_be_bytes());
    output[11..19].copy_from_slice(&sequence.to_be_bytes());
    output[19..21].copy_from_slice(&payload_len.to_be_bytes());
    output[FAST_DATAGRAM_HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

pub fn decode_fast_datagram(
    expected_direction: FastDirection,
    input: &[u8],
) -> Result<FastDatagram<'_>, WireError> {
    if input.len() < FAST_DATAGRAM_HEADER_LEN {
        return Err(WireError::Incomplete {
            needed: FAST_DATAGRAM_HEADER_LEN,
            available: input.len(),
        });
    }
    if input[0] != WIRE_VERSION {
        return Err(WireError::VersionUnsupported(input[0]));
    }
    let direction = FastDirection::decode(input[1])?;
    if direction != expected_direction {
        return Err(WireError::DatagramDirection(input[1]));
    }
    let kind = Kind::decode(input[2])?;
    if kind != direction.kind() {
        return Err(WireError::KindNotAllowed {
            kind,
            stream: direction.stream(),
        });
    }
    let epoch = u64::from_be_bytes(
        input[3..11]
            .try_into()
            .map_err(|_| WireError::LengthOverflow)?,
    );
    let sequence = u64::from_be_bytes(
        input[11..19]
            .try_into()
            .map_err(|_| WireError::LengthOverflow)?,
    );
    let payload_len = u16::from_be_bytes(
        input[19..21]
            .try_into()
            .map_err(|_| WireError::LengthOverflow)?,
    ) as usize;
    if payload_len == 0 {
        return Err(WireError::LengthInvalid { kind, length: 0 });
    }
    if payload_len > FAST_DATAGRAM_PAYLOAD_MAX {
        return Err(WireError::PayloadTooLarge {
            kind,
            length: payload_len,
            maximum: FAST_DATAGRAM_PAYLOAD_MAX,
        });
    }
    let total = FAST_DATAGRAM_HEADER_LEN
        .checked_add(payload_len)
        .ok_or(WireError::LengthOverflow)?;
    if input.len() < total {
        return Err(WireError::Incomplete {
            needed: total,
            available: input.len(),
        });
    }
    if input.len() != total {
        return Err(WireError::LengthInvalid {
            kind,
            length: input.len() - FAST_DATAGRAM_HEADER_LEN,
        });
    }
    Ok(FastDatagram {
        direction,
        kind,
        epoch,
        sequence,
        payload: &input[FAST_DATAGRAM_HEADER_LEN..],
    })
}

pub fn decode_record<'a>(
    stream: StreamRole,
    input: &'a [u8],
    limits: &Limits,
) -> Result<(Record<'a>, usize), WireError> {
    limits.validate()?;
    let header = FrameHeader::decode(input, stream, limits)?;
    let total = HEADER_LEN
        .checked_add(header.payload_len as usize)
        .ok_or(WireError::LengthOverflow)?;
    if input.len() < total {
        return Err(WireError::Incomplete {
            needed: total,
            available: input.len(),
        });
    }
    Ok((
        Record {
            header,
            payload: &input[HEADER_LEN..total],
        },
        total,
    ))
}

pub fn encode_record(
    stream: StreamRole,
    kind: Kind,
    sequence: u64,
    payload: &[u8],
    limits: &Limits,
    output: &mut [u8],
) -> Result<usize, WireError> {
    limits.validate()?;
    let payload_len = u32::try_from(payload.len()).map_err(|_| WireError::LengthOverflow)?;
    let header = FrameHeader::new(kind, sequence, payload_len);
    let encoded_header = header.encode();
    FrameHeader::decode(&encoded_header, stream, limits)?;
    let total = HEADER_LEN
        .checked_add(payload.len())
        .ok_or(WireError::LengthOverflow)?;
    if output.len() < total {
        return Err(WireError::OutputTooSmall {
            needed: total,
            available: output.len(),
        });
    }
    output[..HEADER_LEN].copy_from_slice(&encoded_header);
    output[HEADER_LEN..total].copy_from_slice(payload);
    Ok(total)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamLayout {
    connection_role: ConnectionRole,
    control: bool,
    input: bool,
    output: bool,
}

impl StreamLayout {
    pub const fn new(connection_role: ConnectionRole) -> Self {
        Self {
            connection_role,
            control: false,
            input: false,
            output: false,
        }
    }

    pub fn admit(&mut self, stream: StreamRole) -> Result<(), WireError> {
        if self.connection_role == ConnectionRole::Observer && stream == StreamRole::Input {
            return Err(WireError::ObserverInputStream);
        }
        let occupied = match stream {
            StreamRole::Control => &mut self.control,
            StreamRole::Input => &mut self.input,
            StreamRole::Output => &mut self.output,
        };
        if *occupied {
            return Err(WireError::DuplicateStream(stream));
        }
        *occupied = true;
        Ok(())
    }

    pub const fn is_complete(&self) -> bool {
        self.control
            && self.output
            && (self.input || matches!(self.connection_role, ConnectionRole::Observer))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resize {
    pub rows: u16,
    pub columns: u16,
    pub pixel_width: u16,
    pub pixel_height: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ack {
    pub epoch: u64,
    pub next_expected: u64,
}

impl Ack {
    pub const WIRE_LEN: usize = 16;

    pub fn encode(self) -> [u8; Self::WIRE_LEN] {
        let mut bytes = [0_u8; Self::WIRE_LEN];
        bytes[0..8].copy_from_slice(&self.epoch.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.next_expected.to_be_bytes());
        bytes
    }

    pub fn decode_exact(bytes: &[u8], kind: Kind) -> Result<Self, WireError> {
        if !matches!(kind, Kind::AckInput | Kind::AckOutput) || bytes.len() != Self::WIRE_LEN {
            return Err(WireError::LengthInvalid {
                kind,
                length: bytes.len(),
            });
        }
        Ok(Self {
            epoch: u64::from_be_bytes(
                bytes[0..8]
                    .try_into()
                    .map_err(|_| WireError::LengthOverflow)?,
            ),
            next_expected: u64::from_be_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| WireError::LengthOverflow)?,
            ),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochGap {
    pub abandoned_epoch: u64,
    pub replacement_epoch: u64,
}

impl EpochGap {
    pub const WIRE_LEN: usize = 16;

    pub fn new(abandoned_epoch: u64, replacement_epoch: u64) -> Result<Self, WireError> {
        if replacement_epoch <= abandoned_epoch {
            return Err(WireError::LengthInvalid {
                kind: Kind::Gap,
                length: Self::WIRE_LEN,
            });
        }
        Ok(Self {
            abandoned_epoch,
            replacement_epoch,
        })
    }

    pub fn encode(self) -> [u8; Self::WIRE_LEN] {
        let mut bytes = [0_u8; Self::WIRE_LEN];
        bytes[0..8].copy_from_slice(&self.abandoned_epoch.to_be_bytes());
        bytes[8..16].copy_from_slice(&self.replacement_epoch.to_be_bytes());
        bytes
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != Self::WIRE_LEN {
            return Err(WireError::LengthInvalid {
                kind: Kind::Gap,
                length: bytes.len(),
            });
        }
        Self::new(
            u64::from_be_bytes(
                bytes[0..8]
                    .try_into()
                    .map_err(|_| WireError::LengthOverflow)?,
            ),
            u64::from_be_bytes(
                bytes[8..16]
                    .try_into()
                    .map_err(|_| WireError::LengthOverflow)?,
            ),
        )
    }
}

impl Resize {
    pub const WIRE_LEN: usize = 8;

    pub fn encode(self) -> [u8; Self::WIRE_LEN] {
        let mut bytes = [0_u8; Self::WIRE_LEN];
        bytes[0..2].copy_from_slice(&self.rows.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.columns.to_be_bytes());
        bytes[4..6].copy_from_slice(&self.pixel_width.to_be_bytes());
        bytes[6..8].copy_from_slice(&self.pixel_height.to_be_bytes());
        bytes
    }

    pub fn decode_exact(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() != Self::WIRE_LEN {
            return Err(WireError::LengthInvalid {
                kind: Kind::Resize,
                length: bytes.len(),
            });
        }
        Ok(Self {
            rows: u16::from_be_bytes([bytes[0], bytes[1]]),
            columns: u16::from_be_bytes([bytes[2], bytes[3]]),
            pixel_width: u16::from_be_bytes([bytes[4], bytes[5]]),
            pixel_height: u16::from_be_bytes([bytes[6], bytes[7]]),
        })
    }
}
