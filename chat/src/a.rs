// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use owo_colors::OwoColorize;
use std::net::SocketAddr;

use dominion::{DnsHeader, DnsPacket, Flags, Name, ResourceRecord};

pub(crate) fn response<'a>(
    client: SocketAddr,
    question: DnsPacket<'a>,
    filter: &Name<'_>,
    xor: &Option<crate::Xor>,
) -> DnsPacket<'a> {
    use std::ops::Deref;
    let name = question.questions[0].name.clone();
    if filter.is_subdomain(&name) {
        let mut labels = name.iter_hierarchy();
        let label = labels
            .nth(filter.label_count())
            .expect("Because it is a subdomain it should have at least one more label");
        let signal = labels.next();

        match (signal, xor) {
            (Some(sig), Some(xor)) if sig == xor.signal => {
                if let Some(label) = decrypt(label.deref(), xor.key) {
                    encrypted(client, &label);
                } else {
                    clear(client, label)
                }
            }
            (_, _) => clear(client, label),
        }
    }

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
        questions: question.questions,
        answers: vec![answer(name)],
        authority: vec![],
        additional: vec![],
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
    let red = format!("{} says:", client.ip());
    println!("✉️  {}\n\n\t{}\n\n", red.red(), label);
}

fn encrypted(client: SocketAddr, label: &str) {
    let red = format!("{} says:", client.ip());
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

fn answer(name: Name<'_>) -> ResourceRecord<'_> {
    use dominion::RecordPreamble;
    let preamble = RecordPreamble {
        name,
        rrtype: dominion::Type::A,
        class: dominion::Class::IN,
        ttl: 0,
        rdlen: 4,
    };
    ResourceRecord {
        preamble,
        data: dominion::RecordData::A("127.0.0.1".parse().unwrap()),
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
