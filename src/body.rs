// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub(crate) mod name;

use crate::binutils::*;
use crate::body::name::Name;
use crate::NotImplementedError;
use crate::ParseError;
use std::net::Ipv4Addr;

const INIT_RR_SIZE: usize = 64;

#[derive(Clone, Debug)]
pub struct Question<'a> {
    pub name: Name<'a>,
    pub rrtype: QType,
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

    pub fn serialize(&self, packet: &mut Vec<u8>) {
        self.name.serialize(packet);
        push_u16(packet, self.rrtype as _);
        push_u16(packet, self.class as _);
    }
}

#[derive(Debug, Clone)]
pub struct ResourceRecord<'a> {
    pub preamble: RecordPreamble<'a>,
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
    pub fn parse(buff: &'a [u8], pos: usize) -> Result<(Self, usize), ParseError> {
        let (preamble, size) = RecordPreamble::parse(buff, pos)?;
        let data = RecordData::parse(buff, pos + size, preamble.rrtype)?;
        let size = size + preamble.rdlen as usize;
        Ok((Self { preamble, data }, size))
    }

    pub fn serialize(&self, packet: &mut Vec<u8>) {
        self.preamble.serialize(packet);
        self.data.serialize(packet);
    }
}

#[derive(Debug, Clone)]
pub struct RecordPreamble<'a> {
    pub name: Name<'a>,
    pub rrtype: QType,
    pub class: Class,
    pub ttl: i32,
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

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum RecordData<'a> {
    A(Ipv4Addr),
    Ns(Name<'a>),
    Cname(Name<'a>),
    Mx { preference: u16, exchange: Name<'a> },
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

#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
pub enum QType {
    A = 1,
    Ns = 2,
    Cname = 5,
    Mx = 15,
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

#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd)]
pub enum Class {
    IN = 1,
    CS = 2,
    CH = 3,
    HS = 4,
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
