// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]

use thiserror::Error;

use body::Question;
use body::ResourceRecords;
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
#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecords>,
    pub authority: Vec<ResourceRecords>,
    pub additional: Vec<ResourceRecords>,
}

impl TryFrom<&[u8]> for DnsPacket {
    type Error = ParseError;

    fn try_from(buff: &[u8]) -> Result<Self, Self::Error> {
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
            let (a, size) = ResourceRecords::parse(buff, pos)?;
            pos += size;
            answers.push(a)
        }
        for _ in 0..header.authority {
            let (a, size) = ResourceRecords::parse(buff, pos)?;
            pos += size;
            authority.push(a)
        }
        for _ in 0..header.additional {
            let (a, size) = ResourceRecords::parse(buff, pos)?;
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
