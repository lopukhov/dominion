// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![warn(rust_2018_idioms, missing_debug_implementations)]

use dominion::{DnsPacket, Name, QType, ServerService};
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr};

mod a;
mod txt;

#[derive(Debug)]
pub struct Chat<'a> {
    domain: Name<'a>,
    xor: Option<Xor>,
    answers: a::AHandler,
    files: Option<txt::TxtHandler>,
}
type SMap = BTreeMap<String, String>;

impl<'a> Chat<'a> {
    pub fn new(name: Name<'a>, xor: Option<Xor>, files: Option<SMap>, answers: SMap) -> Self {
        let answers = a::AHandler::new(answers);
        let files = files.map(|f| txt::TxtHandler::new(f.into_iter()));
        Chat {
            domain: name,
            files,
            answers,
            xor,
        }
    }
}

impl ServerService for Chat<'_> {
    fn run<'a>(&self, client: SocketAddr, question: &'a DnsPacket<'a>) -> Option<DnsPacket<'a>> {
        if question.header.questions > 0 {
            match question.questions[0].qtype {
                QType::A => Some(
                    self.answers
                        .response(client, question, &self.domain, &self.xor),
                ),
                QType::Txt => self
                    .files
                    .as_ref()
                    .map(|files| files.response(question, &self.domain, &self.xor)),
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
