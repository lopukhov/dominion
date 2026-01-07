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
    xor: Option<crate::Xor>,
}

impl<'me> AHandler<'me> {
    pub(crate) fn new(
        answers: BTreeMap<String, String>,
        filter: Arc<Name<'me>>,
        xor: Option<crate::Xor>,
    ) -> Self {
        Self {
            answers,
            filter,
            xor,
        }
    }

    pub(crate) fn response<'a>(&self, question: &'a DnsPacket<'a>) -> DnsPacket<'a> {
        let id = question.header.id;
        let name = question.questions[0].name.clone();
        let printer = |msg: &_, e| {
            if e {
                println!("🔒 {}\n\n\t{}\n\n", "A".red(), msg);
            } else {
                println!("✉️  {}\n\n\t{}\n\n", "A".red(), msg);
            }
        };
        let Some(label) = self.read_message(&name, printer) else {
            return super::refused(id);
        };
        let ip = match self.answers.get(label) {
            Some(ip) => ip,
            None => "127.0.0.1",
        };
        answer(question, ip)
    }

    pub(crate) fn response_v6<'a>(&self, question: &'a DnsPacket<'a>) -> DnsPacket<'a> {
        let id = question.header.id;
        let name = question.questions[0].name.clone();
        let printer = |msg: &_, e| {
            if e {
                println!("🔒 {}\n\n\t{}\n\n", "AAAA".blue(), msg);
            } else {
                println!("✉️  {}\n\n\t{}\n\n", "AAAA".blue(), msg);
            }
        };
        let Some(label) = self.read_message(&name, printer) else {
            return super::refused(id);
        };
        let ip = match self.answers.get(label) {
            Some(ip) => ip,
            None => "::1",
        };
        answer_v6(question, ip)
    }

    fn read_message<'a>(&self, name: &'a Name<'a>, printer: fn(&str, bool)) -> Option<&'a str> {
        // Si no es un subdominio no es una petición nuestra
        if !self.filter.is_subdomain(name) {
            return None;
        }

        let mut labels = name.iter_hierarchy();
        let signal = labels
            .nth(self.filter.label_count())
            .expect("Because it is a subdomain it should have at least one more label");
        let text: String = labels.rev().collect();

        match &self.xor {
            Some(xor) if signal == xor.signal => {
                if let Some(text) = decrypt(&text, xor.key) {
                    printer(&text, true);
                } else {
                    let text = format!("Cannot decrypt {text}");
                    printer(&text, false)
                }
            }
            _ => {
                let text = format!("{text}{signal}");
                printer(&text, false)
            }
        }
        // Usamos solo la signal porque el texto puede estar vacío
        Some(signal)
    }
}

fn decrypt(label: impl AsRef<[u8]>, key: u8) -> Option<String> {
    let mut bytes = hex::decode(label).ok()?;
    for b in &mut bytes {
        *b ^= key
    }
    Some(String::from_utf8_lossy(&bytes).into())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypt_xor() {
        let key = 0x5;
        let bytes = "71607671257d6a7725616066777c7571";
        let plain = decrypt(bytes, key);
        assert_eq!(Some("test xor decrypt".to_string()), plain)
    }
}
