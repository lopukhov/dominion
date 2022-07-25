// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use owo_colors::OwoColorize;
use std::net::SocketAddr;

use dominion::{DnsHeader, DnsPacket, Flags, Name, ResourceRecord};

pub fn response<'a>(
    client: SocketAddr,
    question: DnsPacket<'a>,
    filter: &Name<'_>,
) -> DnsPacket<'a> {
    let name = question.questions[0].name.clone();
    if filter.is_subdomain(&name) {
        let label = name.iter_hierarchy().nth(filter.label_count());
        print(
            client,
            label.expect("Because it is a subdomain it should have at least one more label"),
        );
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

fn print(client: SocketAddr, label: &str) {
    let red = format!("{} says:", client.ip());
    println!("✉️  {}\n\n\t{}\n\n", red.red(), label);
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
