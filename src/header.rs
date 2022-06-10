// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::binutils::*;
use crate::CorruptedPackageError;
use crate::NotImplementedError;

macro_rules! u16_flag {
    ($bits:literal is $typ:tt with: $($variant:tt = $value:literal)+) => {
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum $typ {
            $($variant = $value,)*
        }

        impl From<u16> for $typ {
            #[inline]
            fn from(n: u16) -> Self {
                match $crate::header::mask_shift($bits, n) {
                    $($value => Self::$variant,)*
                    _ => ::std::unreachable!("Bitwise operations should make this imposible. Failed with mask {} for value {}", $bits, n),
                }
            }
        }

        impl From<$typ> for u16 {
            #[inline]
            fn from(flag: $typ) -> Self {
                $crate::header::unshift($bits, flag as u16)
            }
        }
    };
}

macro_rules! u16_flag_reserved {
    ($bits:literal is $typ:tt with: $($variant:tt = $value:literal)+) => {
        #[non_exhaustive]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum $typ {
            $($variant = $value,)*
        }

        impl TryFrom<u16> for $typ {
            type Error = NotImplementedError;

            #[inline]
            fn try_from(n: u16) -> Result<Self, Self::Error> {
                match $crate::header::mask_shift($bits, n) {
                    $($value => Ok(Self::$variant),)*
                    n => Err(NotImplementedError::HeaderFlag(stringify!($typ), n)),
                }
            }
        }

        impl From<$typ> for u16 {
            #[inline]
            fn from(flag: $typ) -> Self {
                $crate::header::unshift($bits, flag as u16)
            }
        }
    };
}

#[inline]
fn mask_shift(mask: u16, n: u16) -> u16 {
    (n & mask) >> mask.trailing_zeros()
}

#[inline]
fn unshift(mask: u16, n: u16) -> u16 {
    n << mask.trailing_zeros()
}

//
//       0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//
// ID: Random identifier of connnection
// QR: Query (0) or Response (1)
// OPCODE: Standard query (0), Inverse query (1), Server status query (2), Notify (4), Update (5), DSO (6)
// AA: Authoritative Answer
// TC: TrunCation
// RD: Recursion Desired
// RA: Recursion Available
// Z: Zero (reserved)
// RCODE: Response code NOERROR (0), FORMERR (1), SERVFAIL (2), NXDOMAIN (3), NOTIMP (4), REFUSED (5)
// QDCOUNT: Question records count
// ANCOUNT: Answer records count
// NSCOUNT: Name server records count
// ARCOUNT: Aditional records count
//
#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: Flags,
    pub questions: u16,
    pub answers: u16,
    pub authority: u16,
    pub additional: u16,
}

impl TryFrom<&[u8]> for DnsHeader {
    type Error = crate::ParseError;
    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 12 {
            Err(CorruptedPackageError::HeaderLength(bytes.len()))?
        } else {
            let header = DnsHeader {
                id: safe_u16_read(bytes, 0)?,
                flags: safe_u16_read(bytes, 2)?.try_into()?,
                questions: safe_u16_read(bytes, 4)?,
                answers: safe_u16_read(bytes, 6)?,
                authority: safe_u16_read(bytes, 8)?,
                additional: safe_u16_read(bytes, 10)?,
            };
            Ok(header)
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Flags {
    pub qr: QueryResponse,
    pub opcode: OpCode,
    pub aa: AuthoritativeAnswer,
    pub tc: TrunCation,
    pub rd: RecursionDesired,
    pub ra: RecursionAvailable,
    pub z: Zero,
    pub ad: AuthenticData,
    pub cd: CheckingDisabled,
    pub rcode: ResponseCode,
}

impl TryFrom<u16> for Flags {
    type Error = NotImplementedError;

    #[inline]
    fn try_from(n: u16) -> Result<Self, Self::Error> {
        Ok(Flags {
            qr: n.into(),
            opcode: n.try_into()?,
            aa: n.into(),
            tc: n.into(),
            rd: n.into(),
            ra: n.into(),
            z: n.into(),
            ad: n.into(),
            cd: n.into(),
            rcode: n.try_into()?,
        })
    }
}

impl From<Flags> for u16 {
    #[inline]
    fn from(flags: Flags) -> Self {
        u16::from(flags.qr)
            | u16::from(flags.opcode)
            | u16::from(flags.aa)
            | u16::from(flags.tc)
            | u16::from(flags.rd)
            | u16::from(flags.ra)
            | u16::from(flags.z)
            | u16::from(flags.ad)
            | u16::from(flags.cd)
            | u16::from(flags.rcode)
    }
}

u16_flag! {
    0b1000000000000000 is QueryResponse with:
        Query = 0
        Response = 1
}

// TODO: Not exaustive. https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
u16_flag_reserved! {
    0b0111100000000000 is OpCode with:
        Query = 0
        Iquery = 1
        Status = 2
        Notify = 4
        Update = 5
        Dso = 6
}

u16_flag! {
    0b0000010000000000 is AuthoritativeAnswer with:
        NonAuthoritative = 0
        Authoritative = 1
}

u16_flag! {
    0b0000001000000000 is TrunCation with:
        NotTruncated = 0
        Truncated = 1
}

u16_flag! {
    0b0000000100000000 is RecursionDesired with:
        NotDesired = 0
        Desired = 1
}

u16_flag! {
    0b0000000010000000 is RecursionAvailable with:
        NotAvailable = 0
        Available = 1
}

u16_flag! {
    0b0000000001000000 is Zero with:
        Zero = 0
        Reserved = 1
}

u16_flag! {
    0b0000000000100000 is AuthenticData with:
        NotAuthentic = 0
        Authentic = 1
}

u16_flag! {
    0b0000000000010000 is CheckingDisabled with:
        Enabled = 0
        Disabled = 1
}

// TODO: Not exaustive. https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
u16_flag_reserved! {
    0b0000000000001111 is ResponseCode with:
        NoError = 0
        FormErr = 1
        ServFail = 2
        NXDomain = 3
        NotImp = 4
        Refused = 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_header() {
        let buff = [
            0x12u8, 0x34u8, 0u8, 0u8, 0u8, 1u8, 0u8, 2u8, 0u8, 3u8, 0u8, 4u8,
        ];
        if let Ok(head) = DnsHeader::try_from(&buff[..]) {
            assert_eq!(head.id, 0x1234u16);
            assert_eq!(head.questions, 1u16);
            assert_eq!(head.answers, 2u16);
            assert_eq!(head.authority, 3u16);
            assert_eq!(head.additional, 4u16);
        } else {
            panic!("Test should error with small buffer");
        }
    }

    #[test]
    fn header_err() {
        let buff = [
            0x12u8, 0x34u8, 0u8, 0u8, 0u8, 1u8, 0u8, 1u8, 0u8, 1u8, 0u8, 1u8,
        ];
        if let Ok(_) = DnsHeader::try_from(&buff[..5]) {
            panic!("Test should error with small buffer");
        }
    }

    #[test]
    fn flags_standard_query() {
        let bits: u16 = 0b0000000000000000;
        let flags: Flags = bits.try_into().expect("Failed when transforming flags");
        let transformed: u16 = flags.into();

        assert_eq!(flags.qr, QueryResponse::Query);
        assert_eq!(flags.opcode, OpCode::Query);
        assert_eq!(transformed, bits);
    }

    #[test]
    fn flags_inverse_query() {
        let bits: u16 = 0b0000100000000000;
        let flags: Flags = bits.try_into().expect("Failed when transforming flags");
        let transformed: u16 = flags.into();

        assert_eq!(flags.qr, QueryResponse::Query);
        assert_eq!(flags.opcode, OpCode::Iquery);
        assert_eq!(transformed, bits);
    }

    #[test]
    fn flags_response_noerror() {
        let bits: u16 = 0b1000010000000000;
        let flags: Flags = bits.try_into().expect("Failed when transforming flags");
        let transformed: u16 = flags.into();

        assert_eq!(flags.qr, QueryResponse::Response);
        assert_eq!(flags.aa, AuthoritativeAnswer::Authoritative);
        assert_eq!(flags.rcode, ResponseCode::NoError);
        assert_eq!(transformed, bits);
    }

    #[test]
    fn flags_response_servfail() {
        let bits: u16 = 0b1000010000000010;
        let flags: Flags = bits.try_into().expect("Failed when transforming flags");
        let transformed: u16 = flags.into();

        assert_eq!(flags.qr, QueryResponse::Response);
        assert_eq!(flags.aa, AuthoritativeAnswer::Authoritative);
        assert_eq!(flags.rcode, ResponseCode::ServFail);
        assert_eq!(transformed, bits);
    }

    #[test]
    fn flags_response_nxdomain() {
        let bits: u16 = 0b1000010000000011;
        let flags: Flags = bits.try_into().expect("Failed when transforming flags");
        let transformed: u16 = flags.into();

        assert_eq!(flags.qr, QueryResponse::Response);
        assert_eq!(flags.aa, AuthoritativeAnswer::Authoritative);
        assert_eq!(flags.rcode, ResponseCode::NXDomain);
        assert_eq!(transformed, bits);
    }

    #[test]
    fn flags_response_refused() {
        let bits: u16 = 0b1000010000000101;
        let flags: Flags = bits.try_into().expect("Failed when transforming flags");
        let transformed: u16 = flags.into();

        assert_eq!(flags.qr, QueryResponse::Response);
        assert_eq!(flags.aa, AuthoritativeAnswer::Authoritative);
        assert_eq!(flags.rcode, ResponseCode::Refused);
        assert_eq!(transformed, bits);
    }
}
