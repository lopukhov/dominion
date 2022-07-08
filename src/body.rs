// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Domain name structure and funtions
pub mod name;

use crate::binutils::*;
use crate::body::name::Name;
use crate::NotImplementedError;
use crate::ParseError;
use std::net::Ipv4Addr;

const INIT_RR_SIZE: usize = 64;

/// A query for a [ResourceRecord] of the specified [QType] and [Class].
///
/// ```text
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                                               |
///    /                     QNAME                     /
///    /                                               /
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                     QTYPE                     |
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                     QCLASS                    |
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Clone, Debug)]
pub struct Question<'a> {
    /// The domain name to be queried
    pub name: Name<'a>,
    /// The type of [ResourceRecord] being queried
    pub rrtype: QType,
    /// The class of [ResourceRecord] being queried
    pub class: Class,
}

impl From<Question<'_>> for Vec<u8> {
    fn from(question: Question<'_>) -> Self {
        let mut out = question.name.into();
        push_u16(&mut out, question.rrtype as _);
        push_u16(&mut out, question.class as _);
        out
    }
}

impl<'a> Question<'a> {
    /// Parse from the specified `buff`, starting at position `start`.
    ///
    /// # Errors
    ///
    /// It will error if the buffer does not contain a valid question. If the domain name
    /// in the question has been compressed the buffer should include all previous bytes from
    /// the DNS packet to be considered valid.
    pub fn parse(buff: &'a [u8], start: usize) -> Result<(Self, usize), crate::ParseError> {
        let (name, size) = Name::parse(buff, start)?;
        let n = start + size;
        Ok((
            Question {
                name,
                rrtype: safe_u16_read(buff, n)?.try_into()?,
                class: safe_u16_read(buff, n + 2)?.try_into()?,
            },
            size + 4,
        ))
    }

    /// Serialize the [Question] and append it tho the end of the provided `packet`
    pub fn serialize(&self, packet: &mut Vec<u8>) {
        self.name.serialize(packet);
        push_u16(packet, self.rrtype as _);
        push_u16(packet, self.class as _);
    }
}

/// A description of a resource that can be used as an answer to a question
/// or to provide additional information in the `authority` or `additional` fields
/// of a DNS packet.
///
/// ```text
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                                               |
///    /                                               /
///    /                      NAME                     /
///    |                                               |
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                      TYPE                     |
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                     CLASS                     |
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                      TTL                      |
///    |                                               |
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///    |                   RDLENGTH                    |
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
///    /                     RDATA                     /
///    /                                               /
///    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone)]
pub struct ResourceRecord<'a> {
    /// Contains general information that every [ResourceRecord] shares, like type or class.
    pub preamble: RecordPreamble<'a>,
    /// The RDATA section of a resource record in some DNS packet.
    pub data: RecordData<'a>,
}

impl From<ResourceRecord<'_>> for Vec<u8> {
    fn from(rr: ResourceRecord<'_>) -> Self {
        let mut out = Vec::with_capacity(INIT_RR_SIZE);
        rr.serialize(&mut out);
        out
    }
}

impl<'a> ResourceRecord<'a> {
    /// Parse from the specified `buff`, starting at position `pos`.
    pub fn parse(buff: &'a [u8], pos: usize) -> Result<(Self, usize), ParseError> {
        let (preamble, size) = RecordPreamble::parse(buff, pos)?;
        let data = RecordData::parse(buff, pos + size, preamble.rrtype)?;
        let size = size + preamble.rdlen as usize;
        Ok((Self { preamble, data }, size))
    }

    /// Serialize the [ResourceRecord] and append it tho the end of the provided `packet`
    pub fn serialize(&self, packet: &mut Vec<u8>) {
        self.preamble.serialize(packet);
        self.data.serialize(packet);
    }
}

/// The [ResourceRecord] preamble. Common data to all resource record types.
#[derive(Debug, Clone)]
pub struct RecordPreamble<'a> {
    /// The domain name the RR refers to.
    pub name: Name<'a>,
    /// The RR type.
    pub rrtype: QType,
    /// The RR class.
    pub class: Class,
    /// The time interval that the resource record may be cached before the source of the information should again be consulted.
    pub ttl: i32,
    /// The length of the RR data.
    pub rdlen: u16,
}

impl<'a> RecordPreamble<'a> {
    fn parse(buff: &'a [u8], pos: usize) -> Result<(Self, usize), ParseError> {
        let (name, size) = Name::parse(buff, pos)?;
        let n = size + pos;
        Ok((
            RecordPreamble {
                name,
                rrtype: safe_u16_read(buff, n)?.try_into()?,
                class: safe_u16_read(buff, n + 2)?.try_into()?,
                ttl: safe_i32_read(buff, n + 4)?,
                rdlen: safe_u16_read(buff, n + 8)?,
            },
            size + 10,
        ))
    }

    fn serialize(&self, packet: &mut Vec<u8>) {
        self.name.serialize(packet);
        push_u16(packet, self.rrtype as _);
        push_u16(packet, self.class as _);
        push_i32(packet, self.ttl);
        push_u16(packet, self.rdlen);
    }
}

/// The [ResourceRecord] data associated with the corresponding [Name].
#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum RecordData<'a> {
    /// A host address.
    A(Ipv4Addr),
    /// An authoritative name server
    Ns(Name<'a>),
    /// The canonical name for an alias.
    Cname(Name<'a>),
    /// Mail exchange.
    Mx {
        /// The preference given to this RR among others at the same owner.
        preference: u16,
        /// A host willing to act as a mail exchange for the owner name.
        exchange: Name<'a>,
    },
}

impl<'a> RecordData<'a> {
    fn parse(buff: &'a [u8], pos: usize, rrtype: QType) -> Result<Self, ParseError> {
        match rrtype {
            QType::A => Ok(Self::A(safe_ipv4_read(buff, pos)?)),
            QType::Ns => {
                let (name, _) = Name::parse(buff, pos)?;
                Ok(Self::Ns(name))
            }
            QType::Cname => {
                let (name, _) = Name::parse(buff, pos)?;
                Ok(Self::Cname(name))
            }
            QType::Mx => {
                let (exchange, _) = Name::parse(buff, pos + 2)?;
                Ok(Self::Mx {
                    preference: safe_u16_read(buff, pos)?,
                    exchange,
                })
            }
            QType::All => Err(NotImplementedError::RecordType(rrtype as _))?,
        }
    }

    fn serialize(&self, packet: &mut Vec<u8>) {
        match self {
            Self::A(ip) => packet.extend(ip.octets()),
            Self::Ns(name) => name.serialize(packet),
            Self::Cname(name) => name.serialize(packet),
            Self::Mx {
                preference,
                exchange,
            } => {
                push_u16(packet, *preference);
                exchange.serialize(packet);
            }
        }
    }
}

/// The type of [Question] or [ResourceRecord].
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
pub enum QType {
    /// A host address (IPv4)
    A = 1,
    /// An authoritative name server
    Ns = 2,
    /// The canonical name for an alias
    Cname = 5,
    /// A mail exchange
    Mx = 15,
    /// All types
    All = 255,
}

impl TryFrom<u16> for QType {
    type Error = NotImplementedError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::A),
            2 => Ok(Self::Ns),
            5 => Ok(Self::Cname),
            15 => Ok(Self::Mx),
            255 => Ok(Self::All),
            _ => Err(NotImplementedError::RecordType(value)),
        }
    }
}

/// An enumeration of the different available DNS Classes.
///
/// In practice should allways be `Class::IN`, but the rest are included for completeness.
/// The enum is `non_exhaustive` because classes may be added in the future.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
pub enum Class {
    /// IN: the Internet
    IN = 1,
    /// CS: the CSNET class (Obsolete)
    CS = 2,
    /// CH: the CHAOS class
    CH = 3,
    /// HS: Hesiod [Dyer 87]
    HS = 4,
    /// *: any class
    Any = 255,
}

impl TryFrom<u16> for Class {
    type Error = NotImplementedError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::IN),
            2 => Ok(Self::CS),
            3 => Ok(Self::CH),
            4 => Ok(Self::HS),
            255 => Ok(Self::Any),
            _ => Err(NotImplementedError::RecordClass(value)),
        }
    }
}
