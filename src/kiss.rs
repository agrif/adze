use crate::parse::{Unparse, UnparseError, UnparseOutput, UnparseResult};

pub const FEND: u8 = 0xc0;
pub const FESC: u8 = 0xdb;
pub const TFEND: u8 = 0xdc;
pub const TFESC: u8 = 0xdd;

#[derive(Debug, Clone)]
pub struct Encoder {
    buffer: Vec<u8>,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum EncodeError {
    #[error("KISS buffer overflow, message longer than {0} bytes")]
    BufferOverflow(usize),
}

impl Encoder {
    pub fn new() -> Self {
        Self::new_with_size(1024)
    }

    pub fn new_with_size(buffer_size: usize) -> Self {
        Self {
            buffer: vec![0; buffer_size],
        }
    }

    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    pub fn encode_frame(&mut self, data: &[u8]) -> Result<&[u8], EncodeError> {
        if data.len() + 2 > self.buffer.len() {
            return Err(EncodeError::BufferOverflow(self.buffer.len()));
        }

        self.buffer[1..1 + data.len()].copy_from_slice(data);
        self.escape_buffer(data.len())
    }

    pub fn encode<T>(&mut self, data: &T) -> Result<&[u8], EncodeError>
    where
        T: Unparse,
    {
        let buffer_len = self.buffer.len();
        let mut output = &mut self.buffer[1..];
        match data.unparse(&mut output) {
            Err(UnparseError::BufferOverflow) => {
                return Err(EncodeError::BufferOverflow(self.buffer.len()))
            }
            Ok(_) => (),
        };

        let len = buffer_len - output.len() - 1;

        self.escape_buffer(len)
    }

    fn escape_buffer(&mut self, len: usize) -> Result<&[u8], EncodeError> {
        if self.buffer.len() < len + 2 {
            return Err(EncodeError::BufferOverflow(self.buffer.len()));
        }

        self.buffer[0] = FEND;
        self.buffer[1 + len] = FEND;

        let mut escapes = 0;
        for v in &self.buffer[1..1 + len] {
            if *v == FEND || *v == FESC {
                escapes += 1;
            }
        }

        if escapes == 0 {
            return Ok(&self.buffer[..len + 2]);
        }

        let escaped_len = len + escapes;
        if self.buffer.len() < escaped_len + 2 {
            return Err(EncodeError::BufferOverflow(self.buffer.len()));
        }

        self.buffer.copy_within(1..2 + len, 1 + escapes);

        let mut src = 1 + escapes;
        let mut dst = 1;
        while dst < 1 + escaped_len {
            assert!(src < 1 + escaped_len);

            match self.buffer[src] {
                FEND => {
                    self.buffer[dst] = FESC;
                    dst += 1;
                    self.buffer[dst] = TFEND;
                    dst += 1;
                }
                FESC => {
                    self.buffer[dst] = FESC;
                    dst += 1;
                    self.buffer[dst] = TFESC;
                    dst += 1;
                }
                v => {
                    self.buffer[dst] = v;
                    dst += 1;
                }
            }

            src += 1;
        }

        Ok(&self.buffer[..escaped_len + 2])
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
pub struct Decoder {
    buffer: Vec<u8>,
    state: DecodeState,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecodeError {
    #[error("KISS buffer overflow, message longer than {0} bytes")]
    BufferOverflow(usize),
    #[error("bad KISS escape (0x{0:x?})")]
    BadEscape(u8),
    #[error("cannot parse zero-length KISS message")]
    ZeroLength,
}

#[derive(Debug, Clone, Copy)]
enum DecodeState {
    Idle,
    Frame(usize),
    Escaped(usize),
}

impl Decoder {
    pub fn new() -> Self {
        Self::new_with_size(1024)
    }

    pub fn new_with_size(buffer_size: usize) -> Self {
        Self {
            buffer: vec![0; buffer_size],
            state: DecodeState::Idle,
        }
    }

    pub fn size(&self) -> usize {
        self.buffer.len()
    }

    pub fn reset(&mut self) {
        self.state = DecodeState::Idle;
    }

    pub fn decode_frame<'decoder>(
        &'decoder mut self,
        data: &mut &[u8],
    ) -> Option<Result<&'decoder [u8], DecodeError>> {
        for (data_idx, b) in data.iter().enumerate() {
            match self.state {
                DecodeState::Idle => {
                    // look for a frame boundary
                    if *b == FEND {
                        self.state = DecodeState::Frame(0);
                    }

                    // otherwise do nothing
                }

                DecodeState::Frame(i) => {
                    match *b {
                        FEND => {
                            // repeated FENDs are ignored
                            if i > 0 {
                                // this is a whole frame
                                self.state = DecodeState::Idle;
                                // +1 to consume this byte also
                                *data = &data[data_idx + 1..];
                                return Some(Ok(&self.buffer[..i]));
                            }
                        }

                        FESC => {
                            // escape the next byte
                            self.state = DecodeState::Escaped(i);
                        }

                        _ => {
                            // this is normal data
                            if let Some(dest) = self.buffer.get_mut(i) {
                                *dest = *b;
                                self.state = DecodeState::Frame(i + 1);
                            } else {
                                // frame too big for buffer, reset decoder
                                self.state = DecodeState::Idle;
                                *data = &data[data_idx + 1..];
                                return Some(Err(DecodeError::BufferOverflow(self.buffer.len())));
                            }
                        }
                    }
                }

                DecodeState::Escaped(i) => {
                    let c = match *b {
                        TFEND => FEND,
                        TFESC => FESC,
                        _ => {
                            // this is a protocol error, but some
                            // clients use this explicitly to reset
                            // the other side
                            // nonetheless, let the caller know
                            self.state = DecodeState::Idle;
                            *data = &data[data_idx + 1..];
                            return Some(Err(DecodeError::BadEscape(*b)));
                        }
                    };

                    if let Some(dest) = self.buffer.get_mut(i) {
                        *dest = c;
                        self.state = DecodeState::Frame(i + 1);
                    } else {
                        // frame to big for buffer, reset decoder
                        self.state = DecodeState::Idle;
                        *data = &data[data_idx + 1..];
                        return Some(Err(DecodeError::BufferOverflow(self.buffer.len())));
                    }
                }
            }
        }

        // we consumed everything and found nothing
        *data = &[];
        None
    }

    pub fn decode<'decoder>(
        &'decoder mut self,
        data: &mut &[u8],
    ) -> Option<Result<Message<&'decoder [u8]>, DecodeError>> {
        self.decode_frame(data)
            .map(|res| res.and_then(Message::decode))
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, enum_tools::EnumTools)]
#[cfg_attr(test, derive(derive_quickcheck_arbitrary::Arbitrary))]
#[enum_tools(try_from, into, next, next_back, MAX, MIN, iter, range)]
#[enum_tools(TryFrom, Into)]
#[repr(u8)]
pub enum Port {
    P0,
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
    P8,
    P9,
    P10,
    P11,
    P12,
    P13,
    P14,
    P15,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(test, derive(derive_quickcheck_arbitrary::Arbitrary))]
#[cfg_attr(test, arbitrary(where(Buffer: quickcheck::Arbitrary)))]
pub enum Message<Buffer> {
    Data(Port, Buffer),

    #[cfg_attr(test, arbitrary(skip))]
    Unknown(u8, Buffer),
}

impl<Buffer> Message<Buffer> {
    pub fn map<T>(self, f: impl FnOnce(Buffer) -> T) -> Message<T> {
        match self {
            Self::Data(port, data) => Message::Data(port, f(data)),
            Self::Unknown(cmd, data) => Message::Unknown(cmd, f(data)),
        }
    }
}

impl<'a> Message<&'a [u8]> {
    pub fn into_owned(self) -> Message<Vec<u8>> {
        self.map(|data| data.to_owned())
    }

    pub fn decode(data: &'a [u8]) -> Result<Self, DecodeError> {
        if data.is_empty() {
            return Err(DecodeError::ZeroLength);
        }

        let cmd = data[0];
        let rest = &data[1..];

        // unwrap: value is always less than 16
        let port = Port::try_from((cmd >> 4) & 0xf).unwrap();

        match cmd & 0x0f {
            0 => Ok(Message::Data(port, rest)),
            _ => Ok(Message::Unknown(cmd, rest)),
        }
    }
}

impl<Buffer> Unparse for Message<Buffer>
where
    Buffer: Unparse,
{
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        match self {
            Self::Data(port, data) => {
                output.write_u8((*port as u8) << 4)?;
                output.write_unparse(data)
            }

            Self::Unknown(cmd, data) => {
                output.write_u8(*cmd)?;
                output.write_unparse(data)
            }
        }
    }
}

#[cfg(test)]
mod test {
    use quickcheck::TestResult;
    use quickcheck_macros::quickcheck;

    use super::{DecodeError, Decoder, EncodeError, Encoder, Message};
    use crate::parse::UnparseOutput;

    #[quickcheck]
    fn roundtrip_frame(frame: Vec<u8>) -> anyhow::Result<TestResult> {
        if frame.is_empty() {
            // empty frames are not a thing in KISS
            return Ok(TestResult::discard());
        }

        let mut enc = Encoder::new();
        let mut dec = Decoder::new();

        let mut encoded = match enc.encode_frame(&frame) {
            Ok(d) => d,
            Err(err @ EncodeError::BufferOverflow(size)) => {
                if size < 2 * frame.len() + 2 {
                    // this can happen if the frame is "oops all escapes"
                    return Ok(TestResult::discard());
                } else {
                    return Err(err.into());
                }
            }
        };

        match dec.decode_frame(&mut encoded) {
            None => Ok(TestResult::failed()),
            Some(Ok(decoded)) => Ok(TestResult::from_bool(frame == decoded)),
            Some(Err(err @ DecodeError::BufferOverflow(size))) => {
                if size < frame.len() {
                    // this is expected
                    Ok(TestResult::discard())
                } else {
                    Err(err.into())
                }
            }
            Some(Err(err)) => Err(err.into()),
        }
    }

    #[quickcheck]
    fn roundtrip_message(msg: Message<Vec<u8>>) -> anyhow::Result<bool> {
        let mut encoded = Vec::new();
        encoded.write_unparse(&msg)?;

        let decoded = Message::decode(&encoded)?.into_owned();

        Ok(decoded == msg)
    }

    #[quickcheck]
    fn roundtrip_frame_message(msg: Message<Vec<u8>>) -> anyhow::Result<TestResult> {
        let mut enc = Encoder::new();
        let mut dec = Decoder::new();

        let mut encoded = match enc.encode(&msg) {
            Ok(d) => d,
            Err(EncodeError::BufferOverflow(_)) => {
                // this can happen if the message is too big
                // assume the roundtrip_frame test catches the specifics
                return Ok(TestResult::discard());
            }
        };

        match dec.decode(&mut encoded) {
            None => Ok(TestResult::failed()),
            Some(Ok(decoded)) => Ok(TestResult::from_bool(msg == decoded.into_owned())),
            Some(Err(DecodeError::BufferOverflow(_))) => {
                // this is caught more specifically in roundtrip_frame
                Ok(TestResult::discard())
            }
            Some(Err(err)) => Err(err.into()),
        }
    }
}
