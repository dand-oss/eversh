//! Compact Input/Echo datagram codec. Exact widths, total parsing, and no
//! allocation before the length cap is known.

pub const MTU_CEILING: usize = 1200;
pub const MAX_PAYLOAD: usize = 1024;

pub const INPUT: u8 = 1;
pub const ECHO: u8 = 2;
pub const KEEPALIVE: u8 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    pub epoch: u32,
    pub seq: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Echo {
    pub ack: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Input(Input),
    Echo(Echo),
    Keepalive,
}

#[derive(Debug, PartialEq, Eq)]
pub struct FrameError;

impl Input {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(1 + 4 + 8 + 2 + self.bytes.len());
        out.push(INPUT);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.push((self.bytes.len() >> 8) as u8);
        out.push(self.bytes.len() as u8);
        out.extend_from_slice(&self.bytes);
    }
}

impl Echo {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.clear();
        out.reserve(1 + 8 + 2 + self.bytes.len());
        out.push(ECHO);
        out.extend_from_slice(&self.ack.to_be_bytes());
        out.push((self.bytes.len() >> 8) as u8);
        out.push(self.bytes.len() as u8);
        out.extend_from_slice(&self.bytes);
    }
}

pub fn decode(bytes: &[u8]) -> Result<Frame, FrameError> {
    let Some((&kind, rest)) = bytes.split_first() else {
        return Err(FrameError);
    };
    match kind {
        INPUT => {
            if rest.len() < 14 {
                return Err(FrameError);
            }
            let epoch = u32::from_be_bytes(rest[0..4].try_into().map_err(|_| FrameError)?);
            let seq = u64::from_be_bytes(rest[4..12].try_into().map_err(|_| FrameError)?);
            let len = u16::from_be_bytes(rest[12..14].try_into().map_err(|_| FrameError)?) as usize;
            let payload = rest.get(14..14 + len).ok_or(FrameError)?;
            if rest.len() != 14 + len || len > MAX_PAYLOAD {
                return Err(FrameError);
            }
            Ok(Frame::Input(Input {
                epoch,
                seq,
                bytes: payload.to_vec(),
            }))
        }
        ECHO => {
            if rest.len() < 10 {
                return Err(FrameError);
            }
            let ack = u64::from_be_bytes(rest[0..8].try_into().map_err(|_| FrameError)?);
            let len = u16::from_be_bytes(rest[8..10].try_into().map_err(|_| FrameError)?) as usize;
            let payload = rest.get(10..10 + len).ok_or(FrameError)?;
            if rest.len() != 10 + len || len > MAX_PAYLOAD {
                return Err(FrameError);
            }
            Ok(Frame::Echo(Echo {
                ack,
                bytes: payload.to_vec(),
            }))
        }
        KEEPALIVE if rest.is_empty() => Ok(Frame::Keepalive),
        _ => Err(FrameError),
    }
}
