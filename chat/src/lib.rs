// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use dominion::{DnsPacket, Name, QType, ServerService};
use serde::Deserialize;
use std::net::SocketAddr;

mod a;

#[derive(Debug)]
pub struct Chat<'a> {
    domain: Name<'a>,
    xor: Option<Xor>,
}

impl<'a> Chat<'a> {
    pub fn new(name: Name<'a>, xor: Option<Xor>) -> Self {
        Chat { domain: name, xor }
    }
}

impl ServerService for Chat<'_> {
    fn run<'b>(&self, client: SocketAddr, question: DnsPacket<'b>) -> Option<DnsPacket<'b>> {
        if question.header.questions > 0 {
            match question.questions[0].qtype {
                QType::A => Some(a::response(client, question, &self.domain, &self.xor)),
                _ => Some(refused(question.header.id)),
            }
        } else {
            Some(refused(question.header.id))
        }
    }
}

#[derive(Debug, Deserialize)]
/// Configuration from file
pub struct Xor {
    key: u8,
    signal: String,
}

fn refused(id: u16) -> DnsPacket<'static> {
    use dominion::*;

    let flags = Flags {
        qr: QueryResponse::Response,
        opcode: OpCode::Query,
        aa: AuthoritativeAnswer::Authoritative,
        tc: TrunCation::NotTruncated,
        rd: RecursionDesired::NotDesired,
        ra: RecursionAvailable::NotAvailable,
        z: Zero::Zero,
        ad: AuthenticData::NotAuthentic,
        cd: CheckingDisabled::Disabled,
        rcode: ResponseCode::Refused,
    };

    let header = DnsHeader {
        id,
        flags,
        questions: 0,
        answers: 0,
        authority: 0,
        additional: 0,
    };
    DnsPacket {
        header,
        questions: vec![],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}
