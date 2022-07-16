// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use crate::binutils::*;
use crate::ParseError;

macro_rules! u16_flag {
    (
        $(#[$outer:meta])*
        $bits:literal is $typ:tt with: $(
            #[$inner:meta]
            $variant:tt = $value:literal
        )+
    ) => {
        $(#[$outer])*
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum $typ {
            $(
                #[$inner]
                $variant = $value,
            )*
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
    (
        $(#[$outer:meta])*
        $bits:literal is $typ:tt with: $(
            #[$inner:meta]
            $variant:tt = $value:literal
        )+
    ) => {
        $(#[$outer])*
        #[non_exhaustive]
        #[derive(Copy, Clone, Debug, PartialEq, Eq)]
        pub enum $typ {
            $(
                #[$inner]
                $variant = $value,
            )*
        }

        impl TryFrom<u16> for $typ {
            type Error = ParseError;

            #[inline]
            fn try_from(n: u16) -> Result<Self, Self::Error> {
                match $crate::header::mask_shift($bits, n) {
                    $($value => Ok(Self::$variant),)*
                    n => Err(ParseError::HeaderFlag(stringify!($typ), n)),
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

/// A DNS header.
///
/// The header of a DNS packet follows the following structure:
///
/// ```text
///       0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      ID                       |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    QDCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ANCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    NSCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                    ARCOUNT                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///
/// ID: Random identifier of connnection
/// QR: Query (0) or Response (1)
/// OPCODE: Standard query (0), Inverse query (1), Server status query (2), Notify (4), Update (5), DSO (6)
/// AA: Authoritative Answer
/// TC: TrunCation
/// RD: Recursion Desired
/// RA: Recursion Available
/// Z: Zero (reserved)
/// AD: Authentic data (for DNSSEC)
/// AD: Checking disabled (for DNSSEC)
/// RCODE: Response code NOERROR (0), FORMERR (1), SERVFAIL (2), NXDOMAIN (3), NOTIMP (4), REFUSED (5)
/// QDCOUNT: Question records count
/// ANCOUNT: Answer records count
/// NSCOUNT: Name server records count
/// ARCOUNT: Aditional records count
/// ```
#[derive(Clone, Debug)]
pub struct DnsHeader {
    /// Random identifier of connnection
    pub id: u16,
    /// The different flags of a DNS header.
    pub flags: Flags,
    /// Question records count
    pub questions: u16,
    /// Answer records count
    pub answers: u16,
    /// Name server records count
    pub authority: u16,
    /// Aditional records count
    pub additional: u16,
}

impl TryFrom<&[u8]> for DnsHeader {
    type Error = crate::ParseError;
    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() < 12 {
            Err(ParseError::HeaderLength(bytes.len()))?
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

impl From<&DnsHeader> for Vec<u8> {
    #[inline]
    fn from(header: &DnsHeader) -> Self {
        let mut target = Vec::with_capacity(12);
        header.serialize(&mut target);
        target
    }
}

impl DnsHeader {
    /// Serialize a [DnsHeader] into a vector of bytes.
    ///
    /// Usefult when you need to be able to apend the bytes to an existing `Vec<u8`,
    /// in any other case the `From` trait is implemented to be able to convert from an
    /// [DnsHeader] to an `Vec<u8>`.
    #[inline]
    pub fn serialize(&self, target: &mut Vec<u8>) {
        push_u16(target, self.id);
        push_u16(target, self.flags.into());
        push_u16(target, self.questions);
        push_u16(target, self.answers);
        push_u16(target, self.authority);
        push_u16(target, self.additional);
    }
}

/// DNS Flags
///
/// ```text
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// QR: Query (0) or Response (1)
/// OPCODE: Standard query (0), Inverse query (1), Server status query (2), Notify (4), Update (5), DSO (6)
/// AA: Authoritative Answer
/// TC: TrunCation
/// RD: Recursion Desired
/// RA: Recursion Available
/// Z: Zero (reserved)
/// AD: Authentic data (for DNSSEC)
/// AD: Checking disabled (for DNSSEC)
/// RCODE: Response code NOERROR (0), FORMERR (1), SERVFAIL (2), NXDOMAIN (3), NOTIMP (4), REFUSED (5)
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Flags {
    /// Query (0) or Response (1)
    pub qr: QueryResponse,
    /// Standard query (0), Inverse query (1), Server status query (2), Notify (4), Update (5), DSO (6)
    pub opcode: OpCode,
    /// The answer is authoritative.
    pub aa: AuthoritativeAnswer,
    /// The packet has been truncated.
    pub tc: TrunCation,
    /// The client desires recursion.
    pub rd: RecursionDesired,
    /// The server has recursion availbale.
    pub ra: RecursionAvailable,
    /// Reserved (has to be 0).
    pub z: Zero,
    /// Authentic data (for DNSSEC)
    pub ad: AuthenticData,
    /// Checking disabled (for DNSSEC)
    pub cd: CheckingDisabled,
    /// Response code NOERROR (0), FORMERR (1), SERVFAIL (2), NXDOMAIN (3), NOTIMP (4), REFUSED (5)
    pub rcode: ResponseCode,
}

impl TryFrom<u16> for Flags {
    type Error = ParseError;

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
    /// Query (0) or Response (1) packet.
    0b1000000000000000 is QueryResponse with:
        /// Query packet
        Query = 0
        /// Response packet
        Response = 1
}

// TODO: Not exaustive. https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml
u16_flag_reserved! {
    /// Standard query (0), Inverse query (1), Server status query (2), Notify (4), Update (5), DSO (6)
    0b0111100000000000 is OpCode with:
        /// Standard query
        Query = 0
        /// Inverse query
        Iquery = 1
        /// Server status query
        Status = 2
        /// Notify
        Notify = 4
        /// Update
        Update = 5
        /// DSO
        Dso = 6
}

u16_flag! {
    /// Flag to indicate if the answer is authoritative
    0b0000010000000000 is AuthoritativeAnswer with:
        /// The answer is not authoritative
        NonAuthoritative = 0
        /// The answer is authoritative
        Authoritative = 1
}

u16_flag! {
    /// Flag to indicate if the packet has been truncated.
    0b0000001000000000 is TrunCation with:
        /// The packet has not been truncated
        NotTruncated = 0
        /// The packet has been truncated
        Truncated = 1
}

u16_flag! {
    /// Flag to indicate if recursion is desired by the client.
    0b0000000100000000 is RecursionDesired with:
        /// Recursion is not desired
        NotDesired = 0
        /// Recursion is desired
        Desired = 1
}

u16_flag! {
    /// Flag to indicate if recursion is available by the server.
    0b0000000010000000 is RecursionAvailable with:
        /// Recursion is not available
        NotAvailable = 0
        /// Recursion is available
        Available = 1
}

u16_flag! {
    /// Reserved, should be 0.
    0b0000000001000000 is Zero with:
        /// Standard value
        Zero = 0
        /// Not used value.
        Reserved = 1
}

u16_flag! {
    /// DNSSEC flag to indicate if the data has been cryptographically authenticated
    0b0000000000100000 is AuthenticData with:
        /// The data is not cryptographically authenticated
        NotAuthentic = 0
        /// The data is cryptographically authenticated
        Authentic = 1
}

u16_flag! {
    /// DNSSEC flag to indicate if the client has enabled checking of the data.
    0b0000000000010000 is CheckingDisabled with:
        /// Checking has been enabled
        Enabled = 0
        /// Checking has been disabled
        Disabled = 1
}

// TODO: Not exaustive. https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
u16_flag_reserved! {
    /// Response code
    0b0000000000001111 is ResponseCode with:
        /// There was no error.
        NoError = 0
        /// Format error - The name server was unable to interpret the query.
        FormErr = 1
        /// Server failure - The name server was unable to process this query due to a problem with the name server.
        ServFail = 2
        /// Name Error - Meaningful only for responses from an authoritative name server, this code signifies that the domain name referenced in the query does not exist.
        NXDomain = 3
        /// Not Implemented - The name server does not support the requested kind of query.
        NotImp = 4
        /// Refused - The name server refuses to perform the specified operation for policy reasons.  For example, a name server may not wish to provide the information to the particular requester, or a name server may not wish to perform a particular operation
        Refused = 5
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_header() {
        let mut used = Vec::with_capacity(12);
        let initial = vec![
            0x12u8, 0x34u8, 0u8, 0u8, 0u8, 1u8, 0u8, 2u8, 0u8, 3u8, 0u8, 4u8,
        ];
        let header = DnsHeader::try_from(&initial[..]).unwrap();
        header.serialize(&mut used);
        assert_eq!(initial, used);
    }

    #[test]
    fn serialize_from_header() {
        let initial = vec![
            0x12u8, 0x34u8, 0u8, 0u8, 0u8, 1u8, 0u8, 2u8, 0u8, 3u8, 0u8, 4u8,
        ];
        let header = DnsHeader::try_from(&initial[..]).unwrap();
        let used = Vec::<u8>::from(&header);
        assert_eq!(initial, used);
    }

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
