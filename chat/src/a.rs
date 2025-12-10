// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use owo_colors::OwoColorize;
use std::{collections::BTreeMap, net::SocketAddr};

use dominion::{DnsHeader, DnsPacket, Flags, Name, ResourceRecord};

#[derive(Debug)]
pub(crate) struct AHandler {
    answers: BTreeMap<String, String>,
}

impl AHandler {
    pub(crate) fn new(answers: BTreeMap<String, String>) -> Self {
        Self { answers }
    }

    pub(crate) fn response<'a>(
        &self,
        client: SocketAddr,
        question: &'a DnsPacket<'a>,
        filter: &Name<'_>,
        xor: &Option<crate::Xor>,
    ) -> DnsPacket<'a> {
        let id = question.header.id;
        let name = question.questions[0].name.clone();

        // Si no es un subdominio no es una petición nuestra
        if !filter.is_subdomain(&name) {
            return super::refused(id);
        }

        let mut labels = name.iter_hierarchy();
        let signal = labels
            .nth(filter.label_count())
            .expect("Because it is a subdomain it should have at least one more label");
        let text: String = labels.rev().collect();
        println!("DEBUG {text}{signal}");

        match xor {
            Some(xor) if signal == xor.signal => {
                if let Some(text) = decrypt(&text, xor.key) {
                    encrypted(client, &text);
                } else {
                    let text = format!("Cannot decrypt {text}");
                    clear(client, &text)
                }
            }
            _ => {
                let text = format!("{text}{signal}");
                clear(client, &text)
            }
        }

        // Usamos solo la signal porque el texto puede estar vacío
        let ip = match self.answers.get(signal) {
            Some(ip) => ip,
            None => "127.0.0.1",
        };
        answer(question, ip)
    }
}

fn decrypt(label: impl AsRef<[u8]>, key: u8) -> Option<String> {
    let mut bytes = hex::decode(label).ok()?;
    for b in &mut bytes {
        *b ^= key
    }
    Some(String::from_utf8_lossy(&bytes).into())
}

fn clear(client: SocketAddr, label: &'_ str) {
    let red = format!("{}:", client.ip());
    println!("✉️  {}\n\n\t{}\n\n", red.red(), label);
}

fn encrypted(client: SocketAddr, label: &str) {
    let red = format!("{}:", client.ip());
    println!("🔒 {}\n\n\t{}\n\n", red.red(), label);
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
