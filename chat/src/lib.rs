// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![warn(rust_2018_idioms, missing_debug_implementations)]

use dominion::{DnsPacket, Name, QType, ServerService};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

mod a;
mod cname;
mod txt;

#[derive(Debug)]
pub struct Chat<'a> {
    a_handler: a::AHandler<'a>,
    txt_handler: Option<txt::TxtHandler<'a>>,
    cname_handler: cname::CnameHandler<'a>,
}
type SMap = BTreeMap<String, String>;

impl<'a> Chat<'a> {
    pub fn new(name: Name<'a>, files: Option<SMap>, answers: SMap) -> Result<Self, &'static str> {
        let name = Arc::new(name);
        let answers = Arc::new(answers);
        let a_handler = a::AHandler::new(answers.clone(), name.clone());
        let cname_handler = cname::CnameHandler::new(answers, name.clone());
        let txt_handler = if let Some(files) = files {
            Some(txt::TxtHandler::new(files.into_iter(), name)?)
        } else {
            None
        };
        Ok(Chat {
            a_handler,
            txt_handler,
            cname_handler,
        })
    }
}

impl ServerService for Chat<'_> {
    fn run<'a>(&self, _client: SocketAddr, question: &'a DnsPacket<'a>) -> Option<DnsPacket<'a>> {
        if question.header.questions > 0 {
            match question.questions[0].qtype {
                QType::A => Some(self.a_handler.response(question)),
                QType::Aaaa => Some(self.a_handler.response_v6(question)),
                QType::Cname => Some(self.cname_handler.response(question)),
                QType::Txt => self
                    .txt_handler
                    .as_ref()
                    .map(|files| files.response(question)),
                _ => Some(refused(question.header.id)),
            }
        } else {
            Some(refused(question.header.id))
        }
    }
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
