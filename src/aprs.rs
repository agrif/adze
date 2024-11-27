use arrayvec::ArrayString;

use crate::ax25;
use crate::parse::{ParseInput, Unparse, UnparseOutput, UnparseResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Packet<Buffer> {
    Message {
        destination: Address,
        text: Buffer,
        number: Option<MessageNumber>,
    },

    MessageAck {
        destination: Address,
        number: MessageNumber,
    },

    MessageRej {
        destination: Address,
        number: MessageNumber,
    },
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParseError {
    #[error("AX25 packet is not APRS")]
    NotAprs,
    #[error("APRS packet type not recognized")]
    UnknownType,
    #[error("APRS packet is malformed")]
    BadFormat,
    #[error("APRS text is not UTF-8")]
    BadEncoding,
}

impl<'a> Packet<&'a str> {
    pub fn into_owned(self) -> Packet<String> {
        match self {
            Self::Message {
                destination,
                text,
                number,
            } => Packet::Message {
                destination,
                text: text.to_owned(),
                number,
            },

            Self::MessageAck {
                destination,
                number,
            } => Packet::MessageAck {
                destination,
                number,
            },

            Self::MessageRej {
                destination,
                number,
            } => Packet::MessageRej {
                destination,
                number,
            },
        }
    }
    pub fn parse(packet: &ax25::Packet<&'a [u8]>) -> Result<Self, ParseError> {
        if packet.control.frame_type()
            != ax25::FrameType::U(ax25::UnnumberedType::UI(ax25::Protocol::None))
        {
            return Err(ParseError::NotAprs);
        }

        let mut input = ParseInput::new(packet.information);

        match input.peek_u8().ok_or(ParseError::NotAprs)? {
            b':' => Self::parse_message(input),
            _ => Err(ParseError::UnknownType),
        }
    }

    fn parse_message(mut input: ParseInput<'a>) -> Result<Self, ParseError> {
        if input.read_u8() != Some(b':') {
            return Err(ParseError::BadFormat);
        }

        let destination_str = input
            .read_str(9)
            .ok_or(ParseError::BadFormat)?
            .trim_end_matches(' ');
        // unwrap: destination_str is at most 9 bytes
        let destination = ArrayString::from(destination_str).unwrap();

        if input.read_u8() != Some(b':') {
            return Err(ParseError::BadFormat);
        }

        let text = input.read_all_str().ok_or(ParseError::BadEncoding)?;

        if text.starts_with("ack") {
            if let Ok(number) = text.split_at(3).1.try_into() {
                return Ok(Self::MessageAck {
                    destination,
                    number,
                });
            }
        }

        if text.starts_with("rej") {
            if let Ok(number) = text.split_at(3).1.try_into() {
                return Ok(Self::MessageRej {
                    destination,
                    number,
                });
            }
        }

        if let Some((text, number)) = text.rsplit_once('{') {
            if number.as_bytes().len() <= 5 {
                return Ok(Self::Message {
                    destination,
                    text,
                    number: number.try_into().ok(),
                });
            }

            // right now anything after { longer than 5 bytes
            // is treated as part of the message. should it?
        }

        Ok(Self::Message {
            destination,
            text,
            number: None,
        })
    }
}

impl<Buffer> Unparse for Packet<Buffer>
where
    Buffer: Unparse,
{
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        match self {
            Self::Message {
                destination,
                text,
                number,
            } => {
                output.write_u8(b':')?;

                output.write(destination.as_bytes())?;
                for _ in destination.as_bytes().len()..9 {
                    output.write_u8(b' ')?;
                }

                output.write_u8(b':')?;
                output.write_unparse(text)?;

                if let Some(n) = number {
                    output.write_u8(b'{')?;
                    output.write(n.as_bytes())?;
                }

                Ok(())
            }

            Self::MessageAck {
                destination,
                number,
            } => {
                output.write_u8(b':')?;

                output.write(destination.as_bytes())?;
                for _ in destination.as_bytes().len()..9 {
                    output.write_u8(b' ')?;
                }

                output.write_u8(b':')?;
                output.write(b"ack")?;
                output.write(number.as_bytes())?;

                Ok(())
            }

            Self::MessageRej {
                destination,
                number,
            } => {
                output.write_u8(b':')?;

                output.write(destination.as_bytes())?;
                for _ in destination.as_bytes().len()..9 {
                    output.write_u8(b' ')?;
                }

                output.write_u8(b':')?;
                output.write(b"rej")?;
                output.write(number.as_bytes())?;

                Ok(())
            }
        }
    }
}

pub type Address = ArrayString<9>;

pub type MessageNumber = ArrayString<5>;
