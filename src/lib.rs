// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
// #![warn(missing_docs)]

use thiserror::Error;

use body::Question;
use body::ResourceRecord;
use header::DnsHeader;

mod binutils;
pub mod body;
pub mod header;

// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question(s) for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
#[derive(Debug, Clone)]
pub struct DnsPacket<'a> {
    pub header: DnsHeader,
    pub questions: Vec<Question<'a>>,
    pub answers: Vec<ResourceRecord<'a>>,
    pub authority: Vec<ResourceRecord<'a>>,
    pub additional: Vec<ResourceRecord<'a>>,
}

impl<'a> TryFrom<&'a [u8]> for DnsPacket<'a> {
    type Error = ParseError;

    fn try_from(buff: &'a [u8]) -> Result<Self, Self::Error> {
        let header = DnsHeader::try_from(buff)?;
        let mut questions = Vec::with_capacity(header.questions as _);
        let mut answers = Vec::with_capacity(header.answers as _);
        let mut authority = Vec::with_capacity(header.authority as _);
        let mut additional = Vec::with_capacity(header.additional as _);
        let mut pos = 12;
        for _ in 0..header.questions {
            let (q, size) = Question::parse(buff, pos)?;
            pos += size;
            questions.push(q);
        }
        for _ in 0..header.answers {
            let (a, size) = ResourceRecord::parse(buff, pos)?;
            pos += size;
            answers.push(a)
        }
        for _ in 0..header.authority {
            let (a, size) = ResourceRecord::parse(buff, pos)?;
            pos += size;
            authority.push(a)
        }
        for _ in 0..header.additional {
            let (a, size) = ResourceRecord::parse(buff, pos)?;
            pos += size;
            additional.push(a)
        }
        Ok(Self {
            header,
            questions,
            answers,
            authority,
            additional,
        })
    }
}

impl From<&DnsPacket<'_>> for Vec<u8> {
    fn from(dns: &DnsPacket<'_>) -> Self {
        let mut out = (&dns.header).into();
        for question in &dns.questions {
            question.serialize(&mut out);
        }
        for answer in &dns.answers {
            answer.serialize(&mut out);
        }
        for auth in &dns.authority {
            auth.serialize(&mut out);
        }
        for extra in &dns.additional {
            extra.serialize(&mut out);
        }
        out
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Packet contains behaviour not implemented: {0}")]
    NotImplemented(#[from] NotImplementedError),
    #[error("Packet has been corruped or does not conform to DNS standard: {0}")]
    CorruptPackage(#[from] CorruptedPackageError),
}

#[derive(Error, Debug)]
pub enum NotImplementedError {
    #[error("Flag {0} has no implementation for value {1} in the current version.")]
    HeaderFlag(&'static str, u16),
    #[error("DNS record or query type not implemented with value {0}.")]
    RecordType(u16),
    #[error("DNS record or query class not implemented with value {0}.")]
    RecordClass(u16),
    #[error("Byte {0:#b} does not have a pointer or length prefix.")]
    LabelPrefix(u8),
}

#[derive(Error, Debug, PartialEq)]
pub enum CorruptedPackageError {
    #[error(
        "Length of package ({0} bytes) is too small to contain a DNS header (12 bytes in length)."
    )]
    HeaderLength(usize),
    #[error(
        "Specified name length ({0}) is too long, is bigger than DNS specification (maximum {}).",
        crate::body::name::MAX_NAME_SIZE
    )]
    NameLength(usize),
    #[error("Jump points to a section of the package equal or greater than the current position.")]
    InvalidJump,
    #[error(
        "DNS compression contains excesive number of jumps {0} (maximum {})",
        crate::body::name::MAX_JUMPS
    )]
    ExcesiveJumps(u8),
    #[error("Specified label length ({0}) is too long, it overflows the rest of the package or is bigger than DNS specification (maximum {}).",
        crate::body::name::MAX_LABEL_SIZE
    )]
    LabelLength(usize),
    #[error("Out-of-bounds read attempt at position {0}")]
    OobRead(usize),
    #[error("Non UTF-8 label: {0}")]
    NonUtf8(#[from] std::str::Utf8Error),
}
