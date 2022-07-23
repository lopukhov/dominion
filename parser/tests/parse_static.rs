// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dominion_parser::body::*;
use dominion_parser::header::*;
use dominion_parser::DnsPacket;
use std::net::Ipv4Addr;

const REQ: &'static [u8; 33] = include_bytes!("../assets/dns_request.bin");
const RES: &'static [u8; 49] = include_bytes!("../assets/dns_response.bin");

#[test]
fn test_parse_request() {
    let DnsPacket {
        header,
        questions,
        answers,
        authority,
        additional,
    } = DnsPacket::try_from(&REQ[..]).unwrap();

    assert_eq!(header.flags.qr, QueryResponse::Query);
    assert_eq!(header.flags.opcode, OpCode::Query);
    assert_eq!(header.flags.aa, AuthoritativeAnswer::NonAuthoritative);
    assert_eq!(header.questions, 1);
    assert_eq!(header.answers, 0);
    assert_eq!(header.authority, 0);
    assert_eq!(header.additional, 0);

    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].qtype, QType::A);
    assert_eq!(questions[0].class, Class::IN);
    assert_eq!(
        questions[0].name.to_string(),
        "hello.world.com.".to_string()
    );

    assert!(answers.is_empty());
    assert!(authority.is_empty());
    assert!(additional.is_empty());
}

#[test]
fn test_parse_response() {
    let DnsPacket {
        header,
        questions,
        answers,
        authority,
        additional,
    } = DnsPacket::try_from(&RES[..]).unwrap();

    let real_ip: Ipv4Addr = "204.74.99.100".parse().unwrap();
    let ip = if let RecordData::A(ip) = answers[0].data {
        ip
    } else {
        panic!()
    };

    assert_eq!(header.flags.qr, QueryResponse::Response);
    assert_eq!(header.flags.opcode, OpCode::Query);
    assert_eq!(header.flags.tc, TrunCation::NotTruncated);
    assert_eq!(header.questions, 1);
    assert_eq!(header.answers, 1);
    assert_eq!(header.authority, 0);
    assert_eq!(header.additional, 0);

    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0].qtype, QType::A);
    assert_eq!(questions[0].class, Class::IN);
    assert_eq!(
        questions[0].name.to_string(),
        "hello.world.com.".to_string()
    );

    assert_eq!(answers.len(), 1);
    assert_eq!(ip, real_ip);
    assert_eq!(answers[0].preamble.rdlen, 4);
    assert_eq!(
        answers[0].preamble.name.to_string(),
        "hello.world.com.".to_string()
    );

    assert!(authority.is_empty());
    assert!(additional.is_empty());
}
