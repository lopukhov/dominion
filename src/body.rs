// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

pub(crate) mod name;

use crate::binutils::*;
use crate::body::name::Name;
use crate::NotImplementedError;
use crate::ParseError;
use std::net::Ipv4Addr;

#[derive(Clone, Debug)]
pub struct Question {
    pub name: Name,
    pub rrtype: QType,
    pub class: Class,
}

impl Question {
    pub(crate) fn parse(buff: &[u8], start: usize) -> Result<(Self, usize), crate::ParseError> {
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
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ResourceRecords {
    pub preamble: RecordPreamble,
    pub data: RecordData,
}

impl ResourceRecords {
    pub fn parse(buff: &[u8], pos: usize) -> Result<(Self, usize), ParseError> {
        let (preamble, size) = RecordPreamble::parse(buff, pos)?;
        let data = RecordData::parse(buff, pos + size, preamble.rrtype)?;
        let size = size + preamble.rdlen as usize;
        Ok((Self { preamble, data }, size))
    }
}

#[derive(Debug, Clone)]
pub struct RecordPreamble {
    pub name: Name,
    pub rrtype: QType,
    pub class: Class,
    pub ttl: i32,
    pub rdlen: u16,
}

impl RecordPreamble {
    fn parse(buff: &[u8], pos: usize) -> Result<(Self, usize), ParseError> {
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
}

#[non_exhaustive]
#[derive(Debug, Clone)]
pub enum RecordData {
    A(Ipv4Addr),
    Ns(Name),
    Cname(Name),
    Mx { preference: u16, exchange: Name },
}

impl RecordData {
    pub(crate) fn parse(buff: &[u8], pos: usize, rrtype: QType) -> Result<Self, ParseError> {
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
