// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![warn(rust_2018_idioms, missing_debug_implementations)]

use dominion::{DnsPacket, Name, QType, ServerService};
use serde::Deserialize;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

mod a;
mod txt;

#[derive(Debug)]
pub struct Chat<'a> {
    answers: a::AHandler<'a>,
    files: Option<txt::TxtHandler<'a>>,
}
type SMap = BTreeMap<String, String>;

impl<'a> Chat<'a> {
    pub fn new(
        name: Name<'a>,
        xor: Option<Xor>,
        files: Option<SMap>,
        answers: SMap,
    ) -> Result<Self, &'static str> {
        let name = Arc::new(name);
        let answers = a::AHandler::new(answers, name.clone(), xor);
        let files = if let Some(files) = files {
            Some(txt::TxtHandler::new(files.into_iter(), name)?)
        } else {
            None
        };
        Ok(Chat { files, answers })
    }
}

impl ServerService for Chat<'_> {
    fn run<'a>(&self, _client: SocketAddr, question: &'a DnsPacket<'a>) -> Option<DnsPacket<'a>> {
        if question.header.questions > 0 {
            match question.questions[0].qtype {
                QType::A => Some(self.answers.response(question)),
                QType::Aaaa => Some(self.answers.response_v6(question)),
                QType::Txt => self.files.as_ref().map(|files| files.response(question)),
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
