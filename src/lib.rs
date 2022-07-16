// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # Dominion Parser
//!
//! DNS parser with a focus on usage of the type system to create a declarative
//! experience when parsing or serializing DNS packets. It allows parsing and serializing
//! whole packets or individual elements, like the header or the different questions and
//! resource records. Not all resource records have been implemented, if some are missing
//! that are relevant for your use case please open an [issue](https://github.com/lopukhov/dominion/issues).
//!
//! ## Parsing
//!
//! ```rust
//!
//! use dominion_parser::DnsPacket;
//!
//! const REQ: &'static [u8; 33] = include_bytes!("../assets/dns_request.bin");
//!
//! fn main() {
//!     let packet = DnsPacket::try_from(&REQ[..]).unwrap();
//!     println!("The request was:");
//!     println!("{:#?}", packet);
//! }
//! ```
//!
//! Parsing can fail with a [ParseError].
//!
//! ## Serializing
//!
//! ```rust
//! use dominion_parser::body::{RecordData, RecordPreamble, ResourceRecord};
//! use dominion_parser::header::{AuthenticData, QueryResponse, RecursionAvailable};
//! use dominion_parser::DnsPacket;
//!
//! const REQ: &'static [u8; 33] = include_bytes!("../assets/dns_request.bin");
//!
//! fn main() {
//!     let mut res = DnsPacket::try_from(&REQ[..]).unwrap();
//!
//!     // Change some flags
//!     res.header.flags.qr = QueryResponse::Response;
//!     res.header.flags.ra = RecursionAvailable::Available;
//!     res.header.flags.ad = AuthenticData::NotAuthentic;
//!
//!     // Add answer
//!     let preamble = RecordPreamble {
//!         name: res.questions[0].name.clone(),
//!         rrtype: res.questions[0]
//!             .qtype
//!             .try_into()
//!             .expect("QType is not a valid Type"),
//!         class: res.questions[0].class,
//!         ttl: 300,
//!         rdlen: 4,
//!     };
//!     let data = RecordData::A("204.74.99.100".parse().unwrap());
//!     let answer = ResourceRecord { preamble, data };
//!     res.header.answers = 1;
//!     res.answers.push(answer);
//!
//!     let res = Vec::<u8>::from(&res);
//!
//!     println!("=================== My Response ===================");
//!     println!("{:?}", res);
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links
)]

use thiserror::Error;

use body::Question;
use body::ResourceRecord;
use header::DnsHeader;

mod binutils;
/// The body of the DNS packet (Questions and Resource Records)
pub mod body;
/// The header of the DNS packet
pub mod header;

/// Represents a complete DNS packet.
///
/// A DNS packet has the following sections in order:
///
/// ```text
/// +---------------------+
/// |        Header       |
/// +---------------------+
/// |       Question      | the question(s) for the name server
/// +---------------------+
/// |        Answer       | RRs answering the question
/// +---------------------+
/// |      Authority      | RRs pointing toward an authority
/// +---------------------+
/// |      Additional     | RRs holding additional information
/// +---------------------+
/// ```
///
/// For the header the [DnsHeader] type is used. For the rest, Questions are represented
/// with the [Question] type, and RRs with the [ResourceRecord] type.
#[derive(Debug, Clone)]
pub struct DnsPacket<'a> {
    /// The DNS Header
    pub header: DnsHeader,
    /// The question(s) for the name server
    pub questions: Vec<Question<'a>>,
    /// Resource Records answering the question(s)
    pub answers: Vec<ResourceRecord<'a>>,
    /// Resource Records pointing toward a domain authority
    pub authority: Vec<ResourceRecord<'a>>,
    /// Resource Records holding additional information
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

/// An error was encountered when trying to parse a byte buffer into a DNS packet
#[derive(Error, Debug)]
pub enum ParseError {
    /// The length of the header is too small.
    #[error(
        "Length of packet ({0} bytes) is too small to contain a DNS header (12 bytes in length)."
    )]
    HeaderLength(usize),
    /// Some header flag used a value that has not been implemented.
    #[error("Flag {0} has no implementation for value {1} in the current version.")]
    HeaderFlag(&'static str, u16),
    /// There was a jump to a position forward in the packet (it does not follow the specification) or to itself (it is not sound as it would result in a DoS).
    #[error("Jump points to a section of the packet  equal or greater than the current position.")]
    InvalidJump,
    /// Some domain name has been compressed with too many jumps. This error may be removed in the future.
    #[error(
        "DNS compression contains excesive number of jumps {0} (maximum {})",
        crate::body::name::MAX_JUMPS
    )]
    ExcesiveJumps(u8),
    /// Some label in the DNS packet it too long, overflowing the packet or not following the DNS specification.
    #[error("Specified label length ({0}) is too long, it overflows the rest of the packet or is bigger than DNS specification (maximum {}).",
        crate::body::name::MAX_LABEL_SIZE
    )]
    LabelLength(usize),
    /// The DNS packet contains a label prefix that is not a length prefix or a pointer. Those values dont have a standard definition so are not implemented.
    #[error("Byte {0:#b} does not have a pointer or length prefix.")]
    LabelPrefix(u8),
    /// One of the labels in the packet has a length that is bigger than the DNS specification.
    #[error(
        "Specified name length ({0}) is too long, is bigger than DNS specification (maximum {}).",
        crate::body::name::MAX_NAME_SIZE
    )]
    NameLength(usize),
    /// The packet tried to cause an out-of-bound read.
    #[error("Out-of-bounds read attempt at position {0}")]
    OobRead(usize),
    /// Some label in one of the domain names is not valid UTF-8.
    #[error("Non UTF-8 label: {0}")]
    NonUtf8(#[from] std::str::Utf8Error),
}
