use arrayvec::{ArrayString, ArrayVec};
use bounded_integer::BoundedU8;

use crate::parse::{Unparse, UnparseOutput, UnparseResult};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Packet<Buffer> {
    pub destination: AddressFlags,
    pub source: AddressFlags,
    pub path: ArrayVec<AddressFlags, 8>,
    pub control: Control,
    pub information: Buffer,
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ParseError {
    #[error("AX25 packet has malformed address")]
    BadAddress,
    #[error("AX25 packet has malformed path")]
    BadPath,
    #[error("AX25 packet has malformed control field")]
    BadControl,
    #[error("AX25 packet has malformed protocol field")]
    BadProtocol,
}

impl<Buffer> Packet<Buffer> {
    pub fn map<T>(self, f: impl FnOnce(Buffer) -> T) -> Packet<T> {
        Packet {
            destination: self.destination,
            source: self.source,
            path: self.path,
            control: self.control,
            information: f(self.information),
        }
    }
}

impl<'a> Packet<&'a [u8]> {
    pub fn into_owned(self) -> Packet<Vec<u8>> {
        self.map(|data| data.to_owned())
    }

    pub fn parse(input: &'a [u8]) -> Result<Self, ParseError> {
        let (input, destination, end) = AddressFlags::parse(input)?;
        if end {
            return Err(ParseError::BadAddress);
        }

        let (mut input, source, end) = AddressFlags::parse(input)?;

        let mut path = ArrayVec::new();
        if !end {
            loop {
                let (new_input, addr, end) = AddressFlags::parse(input)?;
                input = new_input;

                if path.is_full() {
                    return Err(ParseError::BadPath);
                }
                path.push(addr);

                if end {
                    break;
                }
            }
        }

        let (input, control) = Control::parse(input)?;

        // FIXME test input for empty if packet type requires it

        Ok(Self {
            destination,
            source,
            path,
            control,
            information: input,
        })
    }
}

impl<Buffer> Unparse for Packet<Buffer>
where
    Buffer: Unparse,
{
    fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        self.destination.unparse(output, false)?;
        self.source.unparse(output, self.path.is_empty())?;

        for (i, part) in self.path.iter().enumerate() {
            part.unparse(output, i == self.path.len() - 1)?;
        }

        self.control.unparse(output)?;
        output.write_unparse(&self.information)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Control {
    pub pf: bool,
    pub frame: ControlType,
}

impl Control {
    pub fn i(pf: bool, nr: PacketNumber, ns: PacketNumber, protocol: Protocol) -> Self {
        Self {
            pf,
            frame: ControlType::I { nr, ns, protocol },
        }
    }

    pub fn ie(pf: bool, nr: PacketNumberExt, ns: PacketNumberExt, protocol: Protocol) -> Self {
        Self {
            pf,
            frame: ControlType::IE { nr, ns, protocol },
        }
    }

    pub fn s(pf: bool, nr: PacketNumber, s: SupervisoryType) -> Self {
        Self {
            pf,
            frame: ControlType::S { nr, s },
        }
    }

    pub fn se(pf: bool, nr: PacketNumberExt, s: SupervisoryType) -> Self {
        Self {
            pf,
            frame: ControlType::SE { nr, s },
        }
    }

    pub fn u(pf: bool, m: UnnumberedType) -> Self {
        Self {
            pf,
            frame: ControlType::U { m },
        }
    }

    pub fn s_rr(pf: bool, nr: PacketNumber) -> Self {
        Self::s(pf, nr, SupervisoryType::RR)
    }

    pub fn s_rnr(pf: bool, nr: PacketNumber) -> Self {
        Self::s(pf, nr, SupervisoryType::RNR)
    }

    pub fn s_rej(pf: bool, nr: PacketNumber) -> Self {
        Self::s(pf, nr, SupervisoryType::REJ)
    }

    pub fn s_srej(pf: bool, nr: PacketNumber) -> Self {
        Self::s(pf, nr, SupervisoryType::SREJ)
    }

    pub fn se_rr(pf: bool, nr: PacketNumberExt) -> Self {
        Self::se(pf, nr, SupervisoryType::RR)
    }

    pub fn se_rnr(pf: bool, nr: PacketNumberExt) -> Self {
        Self::se(pf, nr, SupervisoryType::RNR)
    }

    pub fn se_rej(pf: bool, nr: PacketNumberExt) -> Self {
        Self::se(pf, nr, SupervisoryType::REJ)
    }

    pub fn se_srej(pf: bool, nr: PacketNumberExt) -> Self {
        Self::se(pf, nr, SupervisoryType::SREJ)
    }

    pub fn u_sabme(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::SABME)
    }

    pub fn u_sabm(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::SABM)
    }

    pub fn u_disc(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::DISC)
    }

    pub fn u_dm(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::DM)
    }

    pub fn u_ua(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::UA)
    }

    pub fn u_frmr(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::FRMR)
    }

    pub fn u_ui(pf: bool, protocol: Protocol) -> Self {
        Self::u(pf, UnnumberedType::UI(protocol))
    }

    pub fn u_xid(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::XID)
    }

    pub fn u_test(pf: bool) -> Self {
        Self::u(pf, UnnumberedType::TEST)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ControlType {
    I {
        nr: PacketNumber,
        ns: PacketNumber,
        protocol: Protocol,
    },
    IE {
        nr: PacketNumberExt,
        ns: PacketNumberExt,
        protocol: Protocol,
    },
    S {
        nr: PacketNumber,
        s: SupervisoryType,
    },
    SE {
        nr: PacketNumberExt,
        s: SupervisoryType,
    },
    U {
        m: UnnumberedType,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    None,
    Unknown(u8),
    UnknownEscaped(u8),
}

// FIXME these should be wrapping types, omg
type PacketNumber = BoundedU8<0, 7>;
type PacketNumberExt = BoundedU8<0, 127>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FrameType {
    I(Protocol),
    S(SupervisoryType),
    U(UnnumberedType),
}

impl FrameType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::I(_) => "I",
            Self::S(s) => s.name(),
            Self::U(u) => u.name(),
        }
    }

    pub fn protocol(&self) -> Option<Protocol> {
        match self {
            Self::I(p) => Some(*p),
            Self::S(_) => None,
            Self::U(u) => u.protocol(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SupervisoryType {
    RR,
    RNR,
    REJ,
    SREJ,
}

impl SupervisoryType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::RR => "RR",
            Self::RNR => "RNR",
            Self::REJ => "REJ",
            Self::SREJ => "SREJ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnnumberedType {
    SABME,
    SABM,
    DISC,
    DM,
    UA,
    FRMR,
    UI(Protocol),
    XID,
    TEST,
}

impl UnnumberedType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::SABME => "SABME",
            Self::SABM => "SABM",
            Self::DISC => "DISC",
            Self::DM => "DM",
            Self::UA => "UA",
            Self::FRMR => "FRMR",
            Self::UI(_) => "UI",
            Self::XID => "XID",
            Self::TEST => "TEST",
        }
    }

    pub fn protocol(&self) -> Option<Protocol> {
        match self {
            Self::UI(p) => Some(*p),
            _ => None,
        }
    }
}

impl Control {
    pub fn frame_type(&self) -> FrameType {
        match self.frame {
            ControlType::I { protocol, .. } => FrameType::I(protocol),
            ControlType::IE { protocol, .. } => FrameType::I(protocol),
            ControlType::S { s, .. } => FrameType::S(s),
            ControlType::SE { s, .. } => FrameType::S(s),
            ControlType::U { m, .. } => FrameType::U(m),
        }
    }

    pub fn extended(&self) -> bool {
        matches!(self.frame, ControlType::IE { .. } | ControlType::SE { .. })
    }

    pub fn parse(mut input: &[u8]) -> Result<(&[u8], Self), ParseError> {
        if input.is_empty() {
            return Err(ParseError::BadControl);
        }

        let control = input[0];
        input = &input[1..];

        let mut pf = control & (1 << 4) > 0;

        let frame = if control & 0b01 == 0b00 {
            // I frame. assume it's non-ext, we can convert it later
            let (new_input, protocol) = Protocol::parse(input)?;
            input = new_input;

            ControlType::I {
                // unwrap: we ensure the number is inside 0..=7
                nr: PacketNumber::new((control >> 5) & 0b111).unwrap(),
                ns: PacketNumber::new((control >> 1) & 0b111).unwrap(),
                protocol,
            }
        } else if control & 0b11 == 0b01 {
            // S frame. these never have an info or PID, so we can
            // tell if it's ext or not based on data left

            // first though, decode the type
            let s = match (control >> 2) & 0b11 {
                0b00 => SupervisoryType::RR,
                0b01 => SupervisoryType::RNR,
                0b10 => SupervisoryType::REJ,
                0b11 => SupervisoryType::SREJ,
                _ => unreachable!(),
            };

            if input.is_empty() {
                // not ext
                ControlType::S {
                    // unwrap: we ensure the number is inside 0..=7
                    nr: PacketNumber::new((control >> 5) & 0b111).unwrap(),
                    s,
                }
            } else {
                // ext
                let control = (control as u16) | ((input[0] as u16) << 8);
                input = &input[1..];

                pf = control & (1 << 8) > 0;

                if control & 0b1111_0000 != 0 {
                    return Err(ParseError::BadControl);
                }

                ControlType::SE {
                    // unwrap: we ensure the number is inside 0..=7
                    nr: PacketNumberExt::new(((control >> 9) & 0b0111_1111) as u8).unwrap(),
                    s,
                }
            }
        } else if control & 0b11 == 0b11 {
            // U frame. these are never ext
            let m = match control & 0b1110_1100 {
                0b0110_1100 => UnnumberedType::SABME,
                0b0010_1100 => UnnumberedType::SABM,
                0b0100_0000 => UnnumberedType::DISC,
                0b0000_1100 => UnnumberedType::DM,
                0b0110_0000 => UnnumberedType::UA,
                0b1000_0100 => UnnumberedType::FRMR,
                0b0000_0000 => {
                    // UI frames also have a protocol field
                    let (new_input, protocol) = Protocol::parse(input)?;
                    input = new_input;

                    UnnumberedType::UI(protocol)
                }
                0b1010_1100 => UnnumberedType::XID,
                0b1110_0000 => UnnumberedType::TEST,
                _ => return Err(ParseError::BadControl),
            };

            ControlType::U { m }
        } else {
            // the above conditions cover all cases
            unreachable!()
        };

        Ok((input, Control { pf, frame }))
    }

    pub fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        match self.frame {
            ControlType::I { nr, ns, protocol } => {
                output.write_u8((nr.get() << 5) | ((self.pf as u8) << 4) | (ns.get() << 1))?;
                protocol.unparse(output)
            }
            ControlType::IE { nr, ns, protocol } => {
                output.write_u8(ns.get() << 1)?;
                output.write_u8((nr.get() << 1) | (self.pf as u8))?;
                protocol.unparse(output)
            }
            ControlType::S { nr, s } => output
                .write_u8((nr.get() << 5) | ((self.pf as u8) << 4) | (Self::get_s(s) << 2) | 0b01),
            ControlType::SE { nr, s } => {
                output.write_u8((Self::get_s(s) << 2) | 0b01)?;
                output.write_u8((nr.get() << 1) | (self.pf as u8))
            }
            ControlType::U { m } => {
                let (menc, protocol) = Self::get_m(m);
                output.write_u8(menc | ((self.pf as u8) << 4) | 0b11)?;
                if let Some(p) = protocol {
                    p.unparse(output)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn get_s(s: SupervisoryType) -> u8 {
        match s {
            SupervisoryType::RR => 0b00,
            SupervisoryType::RNR => 0b01,
            SupervisoryType::REJ => 0b10,
            SupervisoryType::SREJ => 0b11,
        }
    }

    fn get_m(m: UnnumberedType) -> (u8, Option<Protocol>) {
        match m {
            UnnumberedType::SABME => (0b0110_1100, None),
            UnnumberedType::SABM => (0b0010_1100, None),
            UnnumberedType::DISC => (0b0100_0000, None),
            UnnumberedType::DM => (0b0000_1100, None),
            UnnumberedType::UA => (0b0110_0000, None),
            UnnumberedType::FRMR => (0b1000_0100, None),
            UnnumberedType::UI(protocol) => (0b0000_0000, Some(protocol)),
            UnnumberedType::XID => (0b1010_1100, None),
            UnnumberedType::TEST => (0b1110_0000, None),
        }
    }
}

impl Protocol {
    fn parse(mut input: &[u8]) -> Result<(&[u8], Protocol), ParseError> {
        if input.is_empty() {
            return Err(ParseError::BadProtocol);
        }

        let protocol = match input[0] {
            0xf0 => Protocol::None,
            0xff => {
                // this is an escape character, the next octet has more info
                if input.is_empty() {
                    return Err(ParseError::BadProtocol);
                }

                // somewhat subtle: failing here is fine, even though we expect
                // extended I frames to parse as normal I and be extended later
                // parsing extended I as regular I will always work, even if
                // this code erroniously reads a control field byte as PID 0xff

                let p = Protocol::UnknownEscaped(input[0]);
                input = &input[1..];

                p
            }
            v => Protocol::Unknown(v),
        };

        Ok((&input[1..], protocol))
    }

    pub fn unparse(&self, output: &mut impl UnparseOutput) -> UnparseResult {
        match self {
            Self::None => output.write_u8(0xf0),
            Self::Unknown(pid) => output.write_u8(*pid),
            Self::UnknownEscaped(pid) => output.write(&[0xff, *pid]),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AddressFlags {
    pub address: Address,
    pub reserved5: bool,
    pub reserved6: bool,
    pub flag: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    // invariants assured by Address::check_callsign
    callsign: ArrayString<6>,
    ssid: Ssid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, enum_tools::EnumTools)]
#[enum_tools(try_from, into, next, next_back, MAX, MIN, iter, range)]
#[enum_tools(TryFrom, Into)]
#[repr(u8)]
pub enum Ssid {
    S0,
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    S8,
    S9,
    S10,
    S11,
    S12,
    S13,
    S14,
    S15,
}

impl AddressFlags {
    pub fn new(address: Address) -> Self {
        Self {
            address,
            // reserved bits are usually true
            reserved5: true,
            reserved6: true,
            flag: false,
        }
    }

    pub fn parse(input: &[u8]) -> Result<(&[u8], Self, bool), ParseError> {
        if input.len() < 7 {
            return Err(ParseError::BadAddress);
        }

        let mut callsign_bytes = &input[..6];
        let ssid_etc = input[6];
        let rest = &input[7..];

        if callsign_bytes.iter().any(|v| v & 1 > 0) {
            return Err(ParseError::BadAddress);
        }

        // strip spaces at the end
        while callsign_bytes[callsign_bytes.len() - 1] == b' ' << 1 {
            callsign_bytes = &callsign_bytes[..callsign_bytes.len() - 1];
        }

        let callsign_ascii: ArrayVec<u8, 6> = callsign_bytes.iter().map(|v| v >> 1).collect();

        let end = ssid_etc & 1 > 0;
        // unwrap: value is known to be less than 16
        let ssid = Ssid::try_from((ssid_etc >> 1) & 0xf).unwrap();
        let reserved5 = ssid_etc & 0x20 > 0;
        let reserved6 = ssid_etc & 0x40 > 0;
        let flag = ssid_etc & 0x80 > 0;

        let address = Self {
            address: Address::new_from_bytes(&callsign_ascii, ssid)?,
            reserved5,
            reserved6,
            flag,
        };

        Ok((rest, address, end))
    }

    pub fn unparse(&self, output: &mut impl UnparseOutput, end: bool) -> UnparseResult {
        let callsign = self.address.callsign().as_bytes();

        let mut i = 0;
        while i < callsign.len() {
            output.write_u8(callsign[i] << 1)?;
            i += 1;
        }

        while i < 6 {
            output.write_u8(b' ' << 1)?;
            i += 1;
        }

        let mut ssid_etc = 0;
        ssid_etc |= if self.flag { 1 << 7 } else { 0 };
        ssid_etc |= if self.reserved6 { 1 << 6 } else { 0 };
        ssid_etc |= if self.reserved5 { 1 << 5 } else { 0 };
        ssid_etc |= (self.address.ssid() as u8) << 1;
        ssid_etc |= if end { 1 } else { 0 };
        output.write_u8(ssid_etc)
    }
}

impl From<Address> for AddressFlags {
    fn from(other: Address) -> Self {
        Self::new(other)
    }
}

impl TryFrom<&str> for AddressFlags {
    type Error = ParseError;
    fn try_from(other: &str) -> Result<Self, Self::Error> {
        Address::new_parse(other).map(Self::new)
    }
}

impl std::str::FromStr for AddressFlags {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Address::new_parse(s).map(Self::new)
    }
}

impl Address {
    pub fn new(callsign: &str, ssid: Ssid) -> Result<Self, ParseError> {
        Self::new_from_bytes(callsign.as_bytes(), ssid)
    }

    pub fn new_from_bytes(callsign: &[u8], ssid: Ssid) -> Result<Self, ParseError> {
        Ok(Self {
            callsign: Self::check_callsign(callsign)?,
            ssid,
        })
    }

    pub fn new_parse(callsign_and_ssid: &str) -> Result<Self, ParseError> {
        if let Some((callsign, ssid)) = callsign_and_ssid.rsplit_once('-') {
            let ssid_num = ssid.parse().or(Err(ParseError::BadAddress))?;
            let ssid = Ssid::try_from(ssid_num).ok_or(ParseError::BadAddress)?;
            Self::new(callsign, ssid)
        } else {
            Self::new(callsign_and_ssid, Ssid::S0)
        }
    }

    fn check_callsign(callsign: &[u8]) -> Result<ArrayString<6>, ParseError> {
        // invariants: always 7 bits, high bit never set
        // never ends in a ASCII space ' '
        if (callsign.len() <= 6 || callsign.iter().all(|v| v & 0x80 == 0))
            && callsign[callsign.len() - 1] != b' '
        {
            // unwrap: valid ASCII (7-bit) is also valid UTF-8
            // and length is at most 6
            Ok(ArrayString::from(std::str::from_utf8(callsign).unwrap()).unwrap())
        } else {
            Err(ParseError::BadAddress)
        }
    }

    pub fn callsign(&self) -> &str {
        &self.callsign
    }

    pub fn set_callsign(&mut self, callsign: &str) -> Result<(), ParseError> {
        self.set_callsign_bytes(callsign.as_bytes())
    }

    pub fn set_callsign_bytes(&mut self, callsign: &[u8]) -> Result<(), ParseError> {
        self.callsign = Self::check_callsign(callsign)?;
        Ok(())
    }

    pub fn ssid(&self) -> Ssid {
        self.ssid
    }

    pub fn set_ssid(&mut self, ssid: Ssid) {
        self.ssid = ssid;
    }
}

impl TryFrom<&str> for Address {
    type Error = ParseError;
    fn try_from(other: &str) -> Result<Self, Self::Error> {
        Self::new_parse(other)
    }
}

impl std::str::FromStr for Address {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new_parse(s)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.callsign)?;
        if self.ssid > Ssid::S0 {
            write!(f, "-{}", self.ssid.into())?;
        }

        Ok(())
    }
}
