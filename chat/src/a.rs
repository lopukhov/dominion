// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use owo_colors::OwoColorize;
use std::{collections::BTreeMap, sync::Arc};

use dominion::{DnsHeader, DnsPacket, Flags, Name, ResourceRecord};

#[derive(Debug)]
pub(crate) struct AHandler<'a> {
    answers: BTreeMap<String, String>,
    filter: Arc<Name<'a>>,
}

impl<'me> AHandler<'me> {
    pub(crate) fn new(answers: BTreeMap<String, String>, filter: Arc<Name<'me>>) -> Self {
        Self { answers, filter }
    }

    pub(crate) fn response<'a>(&self, question: &'a DnsPacket<'a>) -> DnsPacket<'a> {
        let id = question.header.id;
        let name = question.questions[0].name.clone();
        let Some(text) = self.read_message(&name) else {
            return super::refused(id);
        };
        println!("✉️  {}\n\n\t{text}\n\n", "A".red());
        let ip = match self.answers.get(&text.to_ascii_lowercase()) {
            Some(ip) => ip,
            None => "127.0.0.1",
        };
        answer(question, ip)
    }

    pub(crate) fn response_v6<'a>(&self, question: &'a DnsPacket<'a>) -> DnsPacket<'a> {
        let id = question.header.id;
        let name = question.questions[0].name.clone();
        let Some(text) = self.read_message(&name) else {
            return super::refused(id);
        };
        println!("✉️  {}\n\n\t{text}\n\n", "AAAA".blue());
        let ip = match self.answers.get(&text.to_ascii_lowercase()) {
            Some(ip) => ip,
            None => "::1",
        };
        answer_v6(question, ip)
    }

    fn read_message<'a>(&self, name: &'a Name<'a>) -> Option<String> {
        // Si no es un subdominio no es una petición nuestra
        if !self.filter.is_subdomain(name) {
            return None;
        }

        let mut labels = name.iter_hierarchy();
        // Descartamos la parte del domino conocido
        let _ = labels
            .nth(self.filter.label_count() - 1)
            .expect("Because it is a subdomain it should have at least one more label");
        let text: String = labels.rev().collect();
        Some(text)
    }
}

fn flags() -> Flags {
    use dominion::*;

    Flags {
        qr: QueryResponse::Response,
        opcode: OpCode::Query,
        aa: AuthoritativeAnswer::Authoritative,
        tc: TrunCation::NotTruncated,
        rd: RecursionDesired::NotDesired,
        ra: RecursionAvailable::NotAvailable,
        z: Zero::Zero,
        ad: AuthenticData::NotAuthentic,
        cd: CheckingDisabled::Disabled,
        rcode: ResponseCode::NoError,
    }
}

fn answer<'a>(question: &'a DnsPacket<'a>, ip: &str) -> DnsPacket<'a> {
    use dominion::RecordPreamble;
    let name = question.questions[0].name.clone();
    let preamble = RecordPreamble {
        name,
        rrtype: dominion::Type::A,
        class: dominion::Class::IN,
        ttl: 0,
        rdlen: 4,
    };
    let rr = ResourceRecord {
        preamble,
        data: dominion::RecordData::A(ip.parse().unwrap()),
    };

    let header = DnsHeader {
        id: question.header.id,
        flags: flags(),
        questions: 1,
        answers: 1,
        authority: 0,
        additional: 0,
    };
    DnsPacket {
        header,
        questions: question.questions.clone(),
        answers: vec![rr],
        authority: vec![],
        additional: vec![],
    }
}

fn answer_v6<'a>(question: &'a DnsPacket<'a>, ip: &str) -> DnsPacket<'a> {
    use dominion::RecordPreamble;
    let name = question.questions[0].name.clone();
    let preamble = RecordPreamble {
        name,
        rrtype: dominion::Type::Aaaa,
        class: dominion::Class::IN,
        ttl: 0,
        rdlen: 16,
    };
    let rr = ResourceRecord {
        preamble,
        data: dominion::RecordData::Aaaa(ip.parse().unwrap()),
    };

    let header = DnsHeader {
        id: question.header.id,
        flags: flags(),
        questions: 1,
        answers: 1,
        authority: 0,
        additional: 0,
    };
    DnsPacket {
        header,
        questions: question.questions.clone(),
        answers: vec![rr],
        authority: vec![],
        additional: vec![],
    }
}
