// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/// Domain name structure and funtions
pub mod name;

use crate::binutils::*;
use crate::body::name::Name;
use crate::ParseError;
use std::net::Ipv4Addr;

const INIT_RR_SIZE: usize = 64;

macro_rules! types {
    (
        $(
            #[$inner:meta]
            $variant:tt = $value:literal
        )+
    ) => {
        /// The type of [ResourceRecord].
        #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
        pub enum Type {
            $(
                #[$inner]
                $variant,
            )*
            /// ?: A value has been received that does not correspond to any known qtype.
            Unknown(u16),
        }

        impl TryFrom<QType> for Type {
            type Error = &'static str;

            #[inline]
            fn try_from(value: QType) -> Result<Self, Self::Error> {
                match value {
                    $(QType::$variant => Ok(Self::$variant),)*
                    QType::Unknown(n) => Ok(Self::Unknown(n)),
                    _ => Err("QType is not a valid Type")
                }
            }
        }

        impl From<u16> for Type {
            #[inline]
            fn from(value: u16) -> Self {
                match value {
                    $($value => Self::$variant,)*
                    _ => Self::Unknown(value),
                }
            }
        }

        impl From<Type> for u16 {
            #[inline]
            fn from(value: Type) -> Self {
                match value {
                    $(Type::$variant => $value,)*
                    Type::Unknown(n) => n,
                }
            }
        }

        /// The type of [Question].
        #[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
        pub enum QType {
            $(
                #[$inner]
                $variant,
            )*
            /// All types
            All,
            /// ?: A value has been received that does not correspond to any known qtype.
            Unknown(u16),
        }

        impl From<Type> for QType {
            #[inline]
            fn from(value: Type) -> Self {
                match value {
                    $(Type::$variant => Self::$variant,)*
                    Type::Unknown(n) => Self::Unknown(n),
                }
            }
        }

        impl From<u16> for QType {
            #[inline]
            fn from(value: u16) -> Self {
                match value {
                    $($value => Self::$variant,)*
                    255 => Self::All,
                    _ => Self::Unknown(value),
                }
            }
        }

        impl From<QType> for u16 {
            #[inline]
            fn from(value: QType) -> Self {
                match value {
                    $(QType::$variant => $value,)*
                    QType::All => 255,
                    QType::Unknown(n) => n,
                }
            }
        }
    };
}

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
    pub qtype: QType,
    /// The class of [ResourceRecord] being queried
    pub class: Class,
}

impl From<Question<'_>> for Vec<u8> {
    #[inline]
    fn from(question: Question<'_>) -> Self {
        let mut out = question.name.into();
        push_u16(&mut out, question.qtype.into());
        push_u16(&mut out, question.class.into());
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
    #[inline]
    pub fn parse(buff: &'a [u8], start: usize) -> Result<(Self, usize), crate::ParseError> {
        let (name, size) = Name::parse(buff, start)?;
        let n = start + size;
        Ok((
            Question {
                name,
                qtype: safe_u16_read(buff, n)?.into(),
                class: safe_u16_read(buff, n + 2)?.into(),
            },
            size + 4,
        ))
    }

    /// Serialize the [Question] and append it tho the end of the provided `packet`
    #[inline]
    pub fn serialize(&self, packet: &mut Vec<u8>) {
        self.name.serialize(packet);
        push_u16(packet, self.qtype.into());
        push_u16(packet, self.class.into());
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
    #[inline]
    fn from(rr: ResourceRecord<'_>) -> Self {
        let mut out = Vec::with_capacity(INIT_RR_SIZE);
        rr.serialize(&mut out);
        out
    }
}

impl<'a> ResourceRecord<'a> {
    /// Parse from the specified `buff`, starting at position `pos`.
    #[inline]
    pub fn parse(buff: &'a [u8], pos: usize) -> Result<(Self, usize), ParseError> {
        let (preamble, size) = RecordPreamble::parse(buff, pos)?;
        let data = RecordData::parse(buff, pos + size, preamble.rrtype)?;
        let size = size + preamble.rdlen as usize;
        Ok((Self { preamble, data }, size))
    }

    /// Serialize the [ResourceRecord] and append it tho the end of the provided `packet`
    #[inline]
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
    pub rrtype: Type,
    /// The RR class.
    pub class: Class,
    /// The time interval that the resource record may be cached before the source of the information should again be consulted.
    pub ttl: i32,
    /// The length of the RR data.
    pub rdlen: u16,
}

impl<'a> RecordPreamble<'a> {
    #[inline]
    fn parse(buff: &'a [u8], pos: usize) -> Result<(Self, usize), ParseError> {
        let (name, size) = Name::parse(buff, pos)?;
        let n = size + pos;
        Ok((
            RecordPreamble {
                name,
                rrtype: safe_u16_read(buff, n)?.into(),
                class: safe_u16_read(buff, n + 2)?.into(),
                ttl: safe_i32_read(buff, n + 4)?,
                rdlen: safe_u16_read(buff, n + 8)?,
            },
            size + 10,
        ))
    }

    #[inline]
    fn serialize(&self, packet: &mut Vec<u8>) {
        self.name.serialize(packet);
        push_u16(packet, self.rrtype.into());
        push_u16(packet, self.class.into());
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
    /// ?: A value has been received that does not correspond to any known type.
    Unknown(&'a [u8]),
}

impl<'a> RecordData<'a> {
    #[inline]
    fn parse(buff: &'a [u8], pos: usize, rrtype: Type) -> Result<Self, ParseError> {
        match rrtype {
            Type::A => Ok(Self::A(safe_ipv4_read(buff, pos)?)),
            Type::Ns => {
                let (name, _) = Name::parse(buff, pos)?;
                Ok(Self::Ns(name))
            }
            Type::Cname => {
                let (name, _) = Name::parse(buff, pos)?;
                Ok(Self::Cname(name))
            }
            Type::Mx => {
                let (exchange, _) = Name::parse(buff, pos + 2)?;
                Ok(Self::Mx {
                    preference: safe_u16_read(buff, pos)?,
                    exchange,
                })
            }
            Type::Unknown(_) => todo!(),
        }
    }

    #[inline]
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
            Self::Unknown(_buff) => todo!(),
        }
    }
}

types! {
    /// A host address (IPv4)
    A = 1
    /// An authoritative name server
    Ns = 2
    /// The canonical name for an alias
    Cname = 5
    /// A mail exchange
    Mx = 15
}

/// An enumeration of the different available DNS Classes.
///
/// In practice should allways be `Class::IN`, but the rest are included for completeness.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
pub enum Class {
    /// IN: the Internet
    IN,
    /// CS: the CSNET class (Obsolete)
    CS,
    /// CH: the CHAOS class
    CH,
    /// HS: Hesiod [Dyer 87]
    HS,
    /// *: any class
    Any,
    /// ?: A value has been received that does not correspond to any known class
    Unknown(u16),
}

impl From<u16> for Class {
    #[inline]
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            2 => Self::CS,
            3 => Self::CH,
            4 => Self::HS,
            255 => Self::Any,
            _ => Self::Unknown(value),
        }
    }
}

impl From<Class> for u16 {
    #[inline]
    fn from(value: Class) -> Self {
        match value {
            Class::IN => 1,
            Class::CS => 2,
            Class::CH => 3,
            Class::HS => 4,
            Class::Any => 255,
            Class::Unknown(n) => n,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_transformations() {
        assert_eq!(Class::IN, From::from(1u16));
        assert_eq!(Class::CS, From::from(2u16));
        assert_eq!(Class::CH, From::from(3u16));
        assert_eq!(Class::HS, From::from(4u16));
        assert_eq!(Class::Any, From::from(255u16));
        assert_eq!(Class::Unknown(225u16), From::from(225u16));

        assert_eq!(1u16, From::from(Class::IN));
        assert_eq!(2u16, From::from(Class::CS));
        assert_eq!(3u16, From::from(Class::CH));
        assert_eq!(4u16, From::from(Class::HS));
        assert_eq!(255u16, From::from(Class::Any));
        assert_eq!(225u16, From::from(Class::Unknown(225u16)));
    }

    #[test]
    fn qtype_transformations() {
        assert_eq!(QType::A, From::from(1u16));
        assert_eq!(QType::Ns, From::from(2u16));
        assert_eq!(QType::Cname, From::from(5u16));
        assert_eq!(QType::Mx, From::from(15u16));
        assert_eq!(QType::All, From::from(255u16));
        assert_eq!(QType::Unknown(225u16), From::from(225u16));

        assert_eq!(1u16, From::from(QType::A));
        assert_eq!(2u16, From::from(QType::Ns));
        assert_eq!(5u16, From::from(QType::Cname));
        assert_eq!(15u16, From::from(QType::Mx));
        assert_eq!(255u16, From::from(QType::All));
        assert_eq!(225u16, From::from(QType::Unknown(225u16)));
    }
}
